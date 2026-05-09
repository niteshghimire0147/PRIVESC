"""
web/app.py — PRIVESC Web Dashboard (FastAPI backend).

Start with:
    pip install -r requirements-web.txt
    uvicorn web.app:app --host 0.0.0.0 --port 8765

Configuration via environment variables (or .env file):
    WEB_HOST       = 0.0.0.0   (bind address)
    WEB_PORT       = 8765      (listen port)
    WEB_DEBUG      = false     (enable uvicorn --reload)
    NVD_API_KEY    =           (optional — 50 req/30s instead of 5 req/30s)

Then open: http://localhost:8765
"""

import sys
import os
import json
import uuid
import datetime
import sqlite3
import subprocess
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

# Add project root to path so we can import scanner modules
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Load .env file if present (simple built-in loader, no extra dependency) ───
_dotenv_path = PROJECT_ROOT / ".env"
if _dotenv_path.exists():
    with open(_dotenv_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# ── Threat Intel State ────────────────────────────────────────────────────────

_intel_state = {
    "status":       "idle",       # idle | updating | done | error
    "last_updated": None,         # ISO timestamp string
    "cve_count":    0,
    "kev_count":    0,
    "cveorg_count": 0,
    "error":        None,
    "auto_interval_hours": 24,    # configurable auto-update interval
    # real-time progress (only meaningful while status == "updating")
    "progress": {
        "step":       0,          # current step number (1-4)
        "total_steps": 4,
        "step_name":  "",         # e.g. "NVD"
        "cves_done":  0,
        "cves_total": 0,
        "started_at": None,       # monotonic time of update start
        "eta_seconds": None,      # estimated seconds remaining
    },
}
_intel_lock = asyncio.Lock()      # created in lifespan, avoids concurrent updates


# ── Server config (override via .env or environment) ─────────────────────────
WEB_HOST  = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT  = int(os.environ.get("WEB_PORT", "8765"))
WEB_DEBUG = os.environ.get("WEB_DEBUG", "false").lower() == "true"

# ── Database ──────────────────────────────────────────────────────────────────

DB_PATH = PROJECT_ROOT / "data" / "privesc.db"

_DB_SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id           TEXT PRIMARY KEY,
        hostname     TEXT,
        platform     TEXT,
        scan_type    TEXT DEFAULT 'local',
        started_at   TEXT,
        completed_at TEXT,
        risk_level   TEXT,
        risk_score   INTEGER DEFAULT 0,
        status       TEXT DEFAULT 'running',
        error_msg    TEXT,
        system_info  TEXT,
        findings     TEXT,
        summary      TEXT,
        attack_paths TEXT
    );

    CREATE TABLE IF NOT EXISTS hosts (
        hostname           TEXT PRIMARY KEY,
        platform           TEXT,
        last_scan_id       TEXT,
        last_scan_time     TEXT,
        current_risk_level TEXT,
        total_scans        INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
    CREATE INDEX IF NOT EXISTS idx_scans_started  ON scans(started_at DESC);
"""


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Initialise (or repair) the SQLite database.
    If the file is corrupt or a stale journal exists, delete and recreate.
    """
    global DB_PATH   # may be reassigned if data/ is not writable

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Detect a corrupt / zero-byte database left by a previous crash
    db_file    = Path(DB_PATH)
    journal    = Path(str(DB_PATH) + "-journal")
    wal        = Path(str(DB_PATH) + "-wal")
    shm        = Path(str(DB_PATH) + "-shm")
    is_corrupt = db_file.exists() and db_file.stat().st_size == 0

    if is_corrupt:
        for stale in (db_file, journal, wal, shm):
            try:
                stale.unlink(missing_ok=True)
            except OSError:
                pass   # read-only FS or sandbox restriction — carry on

    try:
        conn = get_db()
        conn.executescript(_DB_SCHEMA)
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Last resort: fall back to temp directory if project data/ is not writable
        import tempfile
        DB_PATH = Path(tempfile.gettempdir()) / "privesc_dashboard.db"
        conn = sqlite3.connect(str(DB_PATH), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.executescript(_DB_SCHEMA)
        conn.commit()
        conn.close()
        print(f"[WARN] data/ not writable — using fallback DB: {DB_PATH}", file=sys.stderr)


# ── App ───────────────────────────────────────────────────────────────────────

async def _intel_update_worker(verbose: bool = False) -> bool:
    """Run threat intel update and refresh _intel_state. Thread-safe."""
    if _intel_state["status"] == "updating":
        return False
    async with _intel_lock:
        import time as _time
        _intel_state["status"] = "updating"
        _intel_state["error"]  = None
        _intel_state["progress"] = {
            "step": 0, "total_steps": 4, "step_name": "Starting…",
            "cves_done": 0, "cves_total": 0,
            "started_at": _time.monotonic(), "eta_seconds": None,
        }

        def _on_progress(step, total_steps, step_name, cves_done, cves_total):
            """Called from the worker thread — updates shared state."""
            prog = _intel_state["progress"]
            prog["step"]       = step
            prog["total_steps"] = total_steps
            prog["step_name"]  = step_name
            prog["cves_done"]  = cves_done
            prog["cves_total"] = cves_total
            # ETA: extrapolate from elapsed / fraction done
            elapsed = _time.monotonic() - (prog["started_at"] or _time.monotonic())
            # weight: each step counts equally among 4; cves weight the NVD/CVE.org steps
            steps_done_frac = (step - 1) / total_steps
            if cves_total > 0:
                steps_done_frac += (cves_done / cves_total) / total_steps
            if steps_done_frac > 0.02:
                eta = elapsed / steps_done_frac * (1 - steps_done_frac)
                prog["eta_seconds"] = round(eta)
            else:
                prog["eta_seconds"] = None

        try:
            from intelligence.threat_intel import ThreatIntelFeed, _load_cache
            feed = ThreatIntelFeed()
            ok   = await asyncio.get_event_loop().run_in_executor(
                None, lambda: feed.update(verbose=verbose, progress_callback=_on_progress)
            )
            cache = _load_cache()
            cves  = cache.get("cve_details", {})
            kev   = cache.get("kev_cves", [])
            cveorg_count = sum(1 for v in cves.values() if v.get("cwe_ids"))
            _intel_state["last_updated"]   = cache.get("last_updated")
            _intel_state["cve_count"]      = len(cves)
            _intel_state["kev_count"]      = len(kev)
            _intel_state["cveorg_count"]   = cveorg_count
            _intel_state["status"]         = "done" if ok else "error"
            _intel_state["error"]          = None if ok else "APIs unavailable (offline?)"
            # mark progress complete
            _intel_state["progress"]["step"] = 4
            _intel_state["progress"]["step_name"] = "Complete"
            return ok
        except Exception as e:
            _intel_state["status"] = "error"
            _intel_state["error"]  = str(e)
            return False


async def _daily_scheduler():
    """Background task: auto-update intel every N hours."""
    while True:
        interval = _intel_state.get("auto_interval_hours", 24)
        await asyncio.sleep(interval * 3600)
        await _intel_update_worker(verbose=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: init DB, seed intel state, start daily scheduler."""
    init_db()

    # Seed intel state from existing cache (no network call on startup)
    try:
        from intelligence.threat_intel import _load_cache
        cache = _load_cache()
        if cache:
            cves = cache.get("cve_details", {})
            kev  = cache.get("kev_cves", [])
            cveorg_count = sum(1 for v in cves.values() if v.get("cwe_ids"))
            _intel_state["last_updated"]  = cache.get("last_updated")
            _intel_state["cve_count"]     = len(cves)
            _intel_state["kev_count"]     = len(kev)
            _intel_state["cveorg_count"]  = cveorg_count
            _intel_state["status"]        = "done" if cache.get("last_updated") else "idle"
    except Exception:
        pass

    # Start background daily scheduler
    task = asyncio.create_task(_daily_scheduler())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="PRIVESC Dashboard",
    description="Cross-Platform Privilege Escalation Security Scanner",
    version="2.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)


# ── Request Models ────────────────────────────────────────────────────────────

class LocalScanRequest(BaseModel):
    quick:   bool = False
    skip:    Optional[str] = None    # comma-separated module names to skip
    verbose: bool = False

class RemoteSSHRequest(BaseModel):
    host:     str
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    port:     int = 22
    quick:    bool = False

class CompareRequest(BaseModel):
    scan_id_old: str
    scan_id_new: str


# ── Scanning Logic ────────────────────────────────────────────────────────────

def _run_local_scan(scan_id: str, quick: bool, skip: str, verbose: bool):
    """Run a local scan in a background thread and persist results."""
    conn = get_db()
    try:
        cmd = [sys.executable, str(PROJECT_ROOT / "main.py"), "-f", "json"]
        if quick:
            cmd.append("--quick")
        if skip:
            cmd += ["--skip", skip]
        if verbose:
            cmd.append("-v")

        # main.py appends ".json" to the -o base name, so pass base without extension
        output_base = str(PROJECT_ROOT / "data" / f"scan_{scan_id}")
        output_file = output_base + ".json"
        cmd += ["-o", output_base]

        # Force UTF-8 so Windows cp1252 doesn't choke on banner box-drawing chars
        scan_env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            cwd=str(PROJECT_ROOT),
            env=scan_env,
        )

        # Log stderr if scan process failed
        if result.returncode != 0 and result.stderr:
            import logging
            logging.warning("Scanner stderr: %s", result.stderr[:500])

        # Try to load the generated JSON
        scan_data = {}
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                scan_data = json.load(f)

        system_info = scan_data.get("system_info", {})
        findings    = scan_data.get("findings", [])
        summary     = scan_data.get("summary", {})
        hostname    = system_info.get("hostname", "localhost")
        platform    = "windows" if system_info.get("build_number") else "linux"

        # Enrich with attack paths
        try:
            from analysis.attack_path_engine import analyse_attack_paths
            paths = [p.to_dict() for p in analyse_attack_paths(findings)]
        except Exception:
            paths = []

        # Enrich with compliance
        try:
            from analysis.compliance_mapper import enrich_with_compliance
            enrich_with_compliance(findings)
        except Exception:
            pass

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn.execute("""
            UPDATE scans SET
                hostname=?, platform=?, completed_at=?, risk_level=?,
                risk_score=?, status=?, system_info=?, findings=?,
                summary=?, attack_paths=?
            WHERE id=?
        """, (
            hostname, platform, now,
            summary.get("risk_level", "UNKNOWN"),
            summary.get("risk_score", 0),
            "completed",
            json.dumps(system_info),
            json.dumps(findings),
            json.dumps(summary),
            json.dumps(paths),
            scan_id,
        ))

        # Update host inventory
        conn.execute("""
            INSERT INTO hosts (hostname, platform, last_scan_id, last_scan_time, current_risk_level, total_scans)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(hostname) DO UPDATE SET
                platform=excluded.platform,
                last_scan_id=excluded.last_scan_id,
                last_scan_time=excluded.last_scan_time,
                current_risk_level=excluded.current_risk_level,
                total_scans=total_scans+1
        """, (hostname, platform, scan_id, now, summary.get("risk_level", "UNKNOWN")))

        conn.commit()

    except subprocess.TimeoutExpired:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", "Scan timed out (300s)", scan_id))
        conn.commit()
    except Exception as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", str(e)[:500], scan_id))
        conn.commit()
    finally:
        conn.close()


def _run_ssh_scan(scan_id: str, req: RemoteSSHRequest):
    """Run a remote SSH scan in a background thread."""
    conn = get_db()
    try:
        from remote.ssh_scanner import scan_remote_linux, RemoteScanError
        result = scan_remote_linux(
            host=req.host, username=req.username,
            password=req.password, key_path=req.key_path,
            port=req.port, verbose=False,
        )

        system_info = result.get("system_info", {})
        findings    = result.get("findings", [])
        hostname    = system_info.get("hostname", req.host)

        # Run analysis engine on the raw findings
        from analysis.engine import analyse
        from analysis.attack_path_engine import analyse_attack_paths
        from analysis.compliance_mapper import enrich_with_compliance

        analysed = analyse(findings)
        enriched_findings = enrich_with_compliance(analysed.get("findings", findings))
        summary   = analysed.get("summary", {})
        paths     = [p.to_dict() for p in analyse_attack_paths(enriched_findings)]
        now       = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn.execute("""
            UPDATE scans SET
                hostname=?, platform='linux', completed_at=?, risk_level=?,
                risk_score=?, status=?, system_info=?, findings=?,
                summary=?, attack_paths=?
            WHERE id=?
        """, (
            hostname, now,
            summary.get("risk_level", "UNKNOWN"),
            summary.get("risk_score", 0),
            "completed",
            json.dumps(system_info),
            json.dumps(enriched_findings),
            json.dumps(summary),
            json.dumps(paths),
            scan_id,
        ))
        conn.execute("""
            INSERT INTO hosts (hostname, platform, last_scan_id, last_scan_time, current_risk_level, total_scans)
            VALUES (?, 'linux', ?, ?, ?, 1)
            ON CONFLICT(hostname) DO UPDATE SET
                last_scan_id=excluded.last_scan_id,
                last_scan_time=excluded.last_scan_time,
                current_risk_level=excluded.current_risk_level,
                total_scans=total_scans+1
        """, (hostname, scan_id, now, summary.get("risk_level", "UNKNOWN")))
        conn.commit()

    except RemoteScanError as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", f"SSH connection error: {e}"[:500], scan_id))
        conn.commit()
    except Exception as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", str(e)[:500], scan_id))
        conn.commit()
    finally:
        conn.close()


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = STATIC_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>PRIVESC Dashboard</h1><p>Place index.html in web/static/</p>")


@app.get("/api/stats")
async def get_stats():
    """Dashboard KPI statistics."""
    conn = get_db()
    try:
        total_hosts   = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        total_scans   = conn.execute("SELECT COUNT(*) FROM scans WHERE status='completed'").fetchone()[0]
        recent_scans  = conn.execute(
            "SELECT id, hostname, risk_level, risk_score, started_at FROM scans "
            "WHERE status='completed' ORDER BY started_at DESC LIMIT 10"
        ).fetchall()

        # Aggregate findings across all scans for KPI counts
        all_findings_rows = conn.execute(
            "SELECT findings FROM scans WHERE status='completed' AND findings IS NOT NULL"
        ).fetchall()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for row in all_findings_rows:
            try:
                for f in json.loads(row["findings"]):
                    sev = f.get("severity", "LOW")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
            except Exception:
                pass

        # Risk level distribution across hosts
        risk_dist = {}
        for row in conn.execute("SELECT current_risk_level, COUNT(*) as cnt FROM hosts GROUP BY current_risk_level"):
            risk_dist[row["current_risk_level"]] = row["cnt"]

        # Scan trend (last 14 days)
        trend = conn.execute("""
            SELECT DATE(started_at) as day, COUNT(*) as cnt,
                   SUM(risk_score) / COUNT(*) as avg_score
            FROM scans WHERE status='completed'
              AND started_at > DATE('now', '-14 days')
            GROUP BY day ORDER BY day
        """).fetchall()

        return {
            "total_hosts":    total_hosts,
            "total_scans":    total_scans,
            "severity_counts": severity_counts,
            "risk_distribution": risk_dist,
            "scan_trend": [dict(r) for r in trend],
            "recent_scans": [dict(r) for r in recent_scans],
        }
    finally:
        conn.close()


@app.get("/api/scans")
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    hostname: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    conn = get_db()
    try:
        where, params = ["1=1"], []
        if status:     where.append("status=?");       params.append(status)
        if hostname:   where.append("hostname LIKE ?"); params.append(f"%{hostname}%")
        if risk_level: where.append("risk_level=?");   params.append(risk_level)

        total = conn.execute(
            f"SELECT COUNT(*) FROM scans WHERE {' AND '.join(where)}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT id, hostname, platform, scan_type, started_at, completed_at, "
            f"risk_level, risk_score, status, error_msg FROM scans "
            f"WHERE {' AND '.join(where)} ORDER BY started_at DESC "
            f"LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page],
        ).fetchall()

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "scans": [dict(r) for r in rows],
        }
    finally:
        conn.close()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        data = dict(row)
        for key in ("system_info", "findings", "summary", "attack_paths"):
            if data.get(key):
                try:
                    data[key] = json.loads(data[key])
                except Exception:
                    pass
        return data
    finally:
        conn.close()


@app.get("/api/scans/{scan_id}/export/{fmt}")
async def export_scan(scan_id: str, fmt: str):
    """Export a scan as html, pdf, txt, json, or sarif."""
    VALID = {"html", "pdf", "txt", "json", "sarif"}
    if fmt not in VALID:
        raise HTTPException(400, f"Unknown format '{fmt}'. Use: {', '.join(sorted(VALID))}")

    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        data        = dict(row)
        system_info = json.loads(data.get("system_info") or "{}")
        findings    = json.loads(data.get("findings")    or "[]")
        summary     = json.loads(data.get("summary")     or "{}")
        results     = {"findings": findings, "summary": summary}
        host        = data.get("hostname", "scan")
        short_id    = scan_id[:8]
        data_dir    = PROJECT_ROOT / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # ── JSON ──────────────────────────────────────────────
        if fmt == "json":
            return JSONResponse({"system_info": system_info, **results})

        # ── SARIF ─────────────────────────────────────────────
        if fmt == "sarif":
            from reporter.sarif_generator import generate_sarif
            sarif_str = generate_sarif(system_info, results)
            return JSONResponse(json.loads(sarif_str))

        # ── HTML ──────────────────────────────────────────────
        if fmt == "html":
            if "findings_by_category" not in results:
                from analysis.engine import analyse
                full = analyse(findings)
                full["findings"] = findings
                results = full
            out = data_dir / f"export_{short_id}.html"
            from reporter.html_generator import generate_html
            generate_html(system_info, results, output_file=str(out))
            return FileResponse(str(out), media_type="text/html",
                                filename=f"privesc_{host}_{short_id}.html")

        # ── TXT ───────────────────────────────────────────────
        if fmt == "txt":
            from reporter.generator import generate_text
            out = data_dir / f"export_{short_id}.txt"
            generate_text(system_info, results, output_file=str(out), use_color=False)
            return FileResponse(str(out), media_type="text/plain",
                                filename=f"privesc_{host}_{short_id}.txt")

        # ── PDF ───────────────────────────────────────────────
        if fmt == "pdf":
            out = data_dir / f"export_{short_id}.pdf"
            _generate_pdf(system_info, results, str(out))
            return FileResponse(str(out), media_type="application/pdf",
                                filename=f"privesc_{host}_{short_id}.pdf")

    finally:
        conn.close()


def _generate_pdf(system_info: dict, results: dict, out_path: str) -> None:
    """Build a professional PDF report using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#ef4444"),
        "HIGH":     colors.HexColor("#f59e0b"),
        "MEDIUM":   colors.HexColor("#3b82f6"),
        "LOW":      colors.HexColor("#22c55e"),
    }

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
        title="PRIVESC Scan Report",
    )
    styles = getSampleStyleSheet()
    style_title  = ParagraphStyle("title",  fontSize=22, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#1e293b"), spaceAfter=6)
    style_sub    = ParagraphStyle("sub",    fontSize=11, fontName="Helvetica",
                                  textColor=colors.HexColor("#64748b"), spaceAfter=4)
    style_h2     = ParagraphStyle("h2",     fontSize=13, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#1e293b"), spaceBefore=14, spaceAfter=6)
    style_body   = ParagraphStyle("body",   fontSize=9,  fontName="Helvetica",
                                  textColor=colors.HexColor("#334155"), leading=14, spaceAfter=4)
    style_mono   = ParagraphStyle("mono",   fontSize=8,  fontName="Courier",
                                  textColor=colors.HexColor("#475569"), leading=12,
                                  backColor=colors.HexColor("#f8fafc"), spaceAfter=4,
                                  borderPadding=4)
    style_label  = ParagraphStyle("label",  fontSize=8,  fontName="Helvetica-Bold",
                                  textColor=colors.white)
    style_center = ParagraphStyle("center", fontSize=9,  fontName="Helvetica",
                                  alignment=TA_CENTER, textColor=colors.HexColor("#64748b"))

    hostname  = system_info.get("hostname", "Unknown")
    platform  = system_info.get("platform", "")
    os_name   = system_info.get("os", system_info.get("distribution", ""))
    findings  = results.get("findings", [])
    summary   = results.get("summary", {})
    risk_lv   = summary.get("risk_level", "UNKNOWN")
    risk_sc   = summary.get("risk_score", 0)
    sev_counts = summary.get("severity_counts", {})
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story = []

    # ── Cover / header ──────────────────────────────────────
    story.append(Paragraph("PRIVESC Security Report", style_title))
    story.append(Paragraph(f"Host: <b>{hostname}</b>  ·  {os_name}  ·  {platform}", style_sub))
    story.append(Paragraph(f"Generated: {generated}", style_sub))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#3b82f6"),
                            spaceAfter=12))

    # ── Summary KPI table ───────────────────────────────────
    story.append(Paragraph("Executive Summary", style_h2))
    risk_color = SEV_COLORS.get(risk_lv, colors.grey)
    kpi_data = [
        ["Risk Level", "Risk Score", "Total Findings",
         "Critical", "High", "Medium", "Low"],
        [
            Paragraph(f'<font color="white"><b>{risk_lv}</b></font>', style_label),
            str(risk_sc),
            str(len(findings)),
            str(sev_counts.get("CRITICAL", 0)),
            str(sev_counts.get("HIGH", 0)),
            str(sev_counts.get("MEDIUM", 0)),
            str(sev_counts.get("LOW", 0)),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[3*cm, 2.5*cm, 3*cm, 2*cm, 2*cm, 2*cm, 2*cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#1e293b")),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0),  8),
        ("BACKGROUND",  (0, 1), (0, 1),   risk_color),
        ("BACKGROUND",  (1, 1), (-1, 1),  colors.HexColor("#f8fafc")),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE",    (0, 1), (-1, 1),  10),
        ("FONTNAME",    (1, 1), (-1, 1),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.HexColor("#f8fafc")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    # ── System info table ───────────────────────────────────
    story.append(Paragraph("System Information", style_h2))
    si_rows = [["Property", "Value"]]
    for key in ("hostname", "os", "distribution", "kernel", "architecture",
                "platform", "is_root", "username"):
        val = system_info.get(key)
        if val is not None:
            si_rows.append([key.replace("_", " ").title(), str(val)])
    if len(si_rows) > 1:
        si_table = Table(si_rows, colWidths=[5*cm, 12*cm])
        si_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(si_table)
        story.append(Spacer(1, 16))

    # ── Findings ─────────────────────────────────────────────
    story.append(Paragraph(f"Findings ({len(findings)} total)", style_h2))
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sorted_findings = sorted(findings,
        key=lambda f: sev_order.index(f.get("severity", "LOW")) if f.get("severity") in sev_order else 99)

    for i, f in enumerate(sorted_findings, 1):
        sev  = f.get("severity", "LOW")
        ftype = f.get("type", "Unknown")
        cat  = f.get("category", "")
        desc = f.get("description", "")
        mit  = f.get("mitigation", "")
        sev_c = SEV_COLORS.get(sev, colors.grey)

        block = []
        # Finding header row
        hdr_data = [[
            Paragraph(f'<font color="white"><b>{sev}</b></font>', style_label),
            Paragraph(f'<b>{i}. {ftype}</b>', ParagraphStyle("fh", fontSize=9,
                      fontName="Helvetica-Bold", textColor=colors.HexColor("#1e293b"))),
            Paragraph(cat, ParagraphStyle("fc", fontSize=8, fontName="Helvetica",
                      textColor=colors.HexColor("#64748b"), alignment=2)),
        ]]
        hdr_table = Table(hdr_data, colWidths=[2.2*cm, 11*cm, 3.8*cm])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0),   sev_c),
            ("BACKGROUND",    (1, 0), (-1, 0),  colors.HexColor("#f1f5f9")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (0, 0), (0, -1),  "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (0, -1),  4),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        block.append(hdr_table)
        if desc:
            block.append(Paragraph(desc, style_body))
        if mit:
            block.append(Paragraph(f"<b>Mitigation:</b> {mit}", style_mono))
        story.append(KeepTogether(block))
        story.append(Spacer(1, 6))

    # ── Footer ───────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"),
                            spaceBefore=12, spaceAfter=6))
    story.append(Paragraph(
        f"PRIVESC Security Dashboard  ·  Report generated {generated}  ·  "
        "For authorised security testing only.",
        style_center,
    ))

    doc.build(story)



# ── Scan endpoints ────────────────────────────────────────────────────────────

class LocalScanRequest(BaseModel):
    quick: bool = False
    skip: str = ""

class RemoteSSHRequest(BaseModel):
    host: str
    username: str
    password: str = ""
    port: int = 22
    key_path: Optional[str] = None
    quick: bool = False


def _upsert_host(conn, hostname: str, platform: str, scan_id: str,
                 scan_time: str, risk_level: str) -> None:
    conn.execute("""
        INSERT INTO hosts (hostname, platform, last_scan_id, last_scan_time,
                           current_risk_level, total_scans)
        VALUES (?,?,?,?,?,1)
        ON CONFLICT(hostname) DO UPDATE SET
            platform           = excluded.platform,
            last_scan_id       = excluded.last_scan_id,
            last_scan_time     = excluded.last_scan_time,
            current_risk_level = excluded.current_risk_level,
            total_scans        = total_scans + 1
    """, (hostname, platform, scan_id, scan_time, risk_level))


async def _run_local_scan(scan_id: str) -> None:
    """Background task: run a local privilege-escalation scan and store results."""
    conn = get_db()
    try:
        from main import run_scan
        results     = run_scan(quick=False)
        system_info = results.get("system_info", {})
        findings    = results.get("findings", [])
        summary     = results.get("summary", {})
        attack_paths = results.get("attack_paths", [])

        hostname   = system_info.get("hostname", "unknown")
        platform   = system_info.get("platform", "unknown")
        risk_level = summary.get("risk_level", "LOW")
        risk_score = summary.get("risk_score", 0)
        now        = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn.execute("""
            UPDATE scans SET status=?, completed_at=?, hostname=?, platform=?,
                risk_level=?, risk_score=?, system_info=?, findings=?, summary=?,
                attack_paths=?
            WHERE id=?
        """, ("completed", now, hostname, platform, risk_level, risk_score,
              json.dumps(system_info), json.dumps(findings),
              json.dumps(summary), json.dumps(attack_paths), scan_id))
        _upsert_host(conn, hostname, platform, scan_id, now, risk_level)
        conn.commit()
    except Exception as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", str(e)[:500], scan_id))
        conn.commit()
    finally:
        conn.close()


async def _run_ssh_scan(scan_id: str, req: RemoteSSHRequest) -> None:
    """Background task: run a remote SSH scan and store results."""
    conn = get_db()
    try:
        from remote.ssh_scanner import RemoteScanError, scan_remote_host
        results     = scan_remote_host(
            host=req.host, username=req.username,
            password=req.password, port=req.port,
            key_path=req.key_path,
        )
        system_info  = results.get("system_info", {})
        findings     = results.get("findings", [])
        summary      = results.get("summary", {})
        attack_paths = results.get("attack_paths", [])

        hostname   = system_info.get("hostname", req.host)
        platform   = system_info.get("platform", "linux")
        risk_level = summary.get("risk_level", "LOW")
        risk_score = summary.get("risk_score", 0)
        now        = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn.execute("""
            UPDATE scans SET status=?, completed_at=?, hostname=?, platform=?,
                risk_level=?, risk_score=?, system_info=?, findings=?, summary=?,
                attack_paths=?
            WHERE id=?
        """, ("completed", now, hostname, platform, risk_level, risk_score,
              json.dumps(system_info), json.dumps(findings),
              json.dumps(summary), json.dumps(attack_paths), scan_id))
        _upsert_host(conn, hostname, platform, scan_id, now, risk_level)
        conn.commit()
    except RemoteScanError as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", f"SSH connection error: {e}"[:500], scan_id))
        conn.commit()
    except Exception as e:
        conn.execute("UPDATE scans SET status=?, error_msg=? WHERE id=?",
                     ("failed", str(e)[:500], scan_id))
        conn.commit()
    finally:
        conn.close()


@app.post("/api/scans/local", status_code=202)
async def start_local_scan(req: LocalScanRequest, background_tasks: BackgroundTasks):
    """Start an asynchronous local scan."""
    scan_id = str(uuid.uuid4())
    conn = get_db()
    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO scans (id, scan_type, started_at, status)
            VALUES (?,?,?,?)
        """, (scan_id, "local", now, "running"))
        conn.commit()
    finally:
        conn.close()
    background_tasks.add_task(_run_local_scan, scan_id)
    return {"scan_id": scan_id, "status": "started"}


@app.post("/api/scans/remote/ssh", status_code=202)
async def start_ssh_scan(req: RemoteSSHRequest, background_tasks: BackgroundTasks):
    """Start an asynchronous remote SSH scan."""
    scan_id = str(uuid.uuid4())
    conn = get_db()
    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO scans (id, hostname, scan_type, started_at, status)
            VALUES (?,?,?,?,?)
        """, (scan_id, req.host, "ssh", now, "running"))
        conn.commit()
    finally:
        conn.close()
    background_tasks.add_task(_run_ssh_scan, scan_id, req)
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/hosts")
async def list_hosts():
    """Return all known hosts."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM hosts ORDER BY last_scan_time DESC"
        ).fetchall()
        return {"hosts": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/findings")
async def list_findings(
    page: int = Query(1, ge=1),
    per_page: int = Query(30, ge=1, le=200),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    hostname: Optional[str] = None,
):
    """Aggregate findings from all completed scans with filters."""
    conn = get_db()
    try:
        where, params = ["status='completed'", "findings IS NOT NULL"], []
        if hostname:
            where.append("hostname=?"); params.append(hostname)
        clause = "WHERE " + " AND ".join(where)
        rows = conn.execute(
            f"SELECT hostname, findings FROM scans {clause}", params
        ).fetchall()

        all_findings = []
        for row in rows:
            try:
                for f in json.loads(row["findings"]):
                    f["_hostname"] = row["hostname"]
                    all_findings.append(f)
            except Exception:
                pass

        if severity:
            all_findings = [f for f in all_findings if f.get("severity") == severity]
        if category:
            all_findings = [f for f in all_findings if f.get("category") == category]
        if search:
            sl = search.lower()
            all_findings = [f for f in all_findings
                            if sl in str(f.get("type","")).lower()
                            or sl in str(f.get("description","")).lower()]

        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity","LOW"), 9))
        total  = len(all_findings)
        offset = (page - 1) * per_page
        return {
            "total":    total,
            "page":     page,
            "pages":    max(1, (total + per_page - 1) // per_page),
            "findings": all_findings[offset:offset + per_page],
        }
    finally:
        conn.close()


@app.post("/api/compare")
async def compare_scans(
    scan_a: str = Query(...),
    scan_b: str = Query(...),
):
    """Diff two scans and return new/resolved/changed findings."""
    conn = get_db()
    try:
        def build_report(row):
            data = dict(row)
            findings = json.loads(data.get("findings") or "[]")
            return {"findings": findings, "summary": json.loads(data.get("summary") or "{}")}

        row_a = conn.execute("SELECT * FROM scans WHERE id=?", (scan_a,)).fetchone()
        row_b = conn.execute("SELECT * FROM scans WHERE id=?", (scan_b,)).fetchone()
        if not row_a or not row_b:
            raise HTTPException(404, "One or both scans not found")

        from analysis.diff_engine import diff_scans
        result = diff_scans(build_report(row_a), build_report(row_b))
        return result
    finally:
        conn.close()


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan record."""
    conn = get_db()
    try:
        row = conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()
        return {"deleted": scan_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        conn.close()


@app.delete("/api/hosts/{hostname}")
async def delete_host(hostname: str):
    """Delete a host and all its associated scans."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT hostname FROM hosts WHERE hostname=?", (hostname,)
        ).fetchone()
        if not row:
            raise HTTPException(404, f"Host '{hostname}' not found")
        count = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE hostname=?", (hostname,)
        ).fetchone()[0]
        conn.execute("DELETE FROM scans WHERE hostname=?", (hostname,))
        conn.execute("DELETE FROM hosts  WHERE hostname=?", (hostname,))
        conn.commit()
        return {"deleted": hostname, "scans_removed": count}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        conn.close()


# ── Threat Intel API ──────────────────────────────────────────────────────────

@app.get("/api/intel/status")
async def get_intel_status():
    """Return current threat intel cache status including real-time progress."""
    from intelligence.threat_intel import CACHE_TTL_HOURS
    state = dict(_intel_state)
    prog  = dict(_intel_state["progress"])
    prog.pop("started_at", None)
    state["progress"] = prog
    state["is_stale"]    = False
    state["next_update"] = None
    if state["last_updated"]:
        try:
            ts  = datetime.datetime.fromisoformat(state["last_updated"])
            age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                   - ts.replace(tzinfo=None)).total_seconds() / 3600
            state["age_hours"]   = round(age, 1)
            state["is_stale"]    = age > CACHE_TTL_HOURS
            remaining = max(0, CACHE_TTL_HOURS - age)
            state["next_update"] = f"in {round(remaining,1)}h" if remaining > 0 else "overdue"
        except Exception:
            state["age_hours"] = None
    else:
        state["age_hours"] = None
    return state


@app.get("/api/intel/cves")
async def get_intel_cves():
    """Return full CVE details from the cached threat intel feed."""
    try:
        from intelligence.threat_intel import _load_cache
        cache = _load_cache()
        cves  = cache.get("cve_details", {})
        kev   = set(cache.get("kev_cves", []))
        rows  = []
        for cve_id, detail in sorted(cves.items()):
            rows.append({
                "id":          cve_id,
                "description": (detail.get("description") or "")[:200],
                "cvss":        detail.get("cvss_score"),
                "severity":    detail.get("severity", ""),
                "epss":        detail.get("epss_score"),
                "in_kev":      cve_id in kev,
                "cwe_ids":     detail.get("cwe_ids", []),
                "vendors":     detail.get("affected_vendors", [])[:3],
            })
        return JSONResponse({"total": len(rows), "cves": rows})
    except Exception as e:
        return JSONResponse({"total": 0, "cves": [], "error": str(e)})


@app.post("/api/intel/update", status_code=202)
async def trigger_intel_update(background_tasks: BackgroundTasks):
    """Manually trigger a threat intel update."""
    async with _intel_lock:
        if _intel_state["status"] == "updating":
            raise HTTPException(status_code=409, detail="Update already in progress")
        _intel_state["status"] = "updating"
        _intel_state["error"]  = None
    background_tasks.add_task(_intel_update_worker)
    return {"message": "Threat intel update started"}


@app.post("/api/intel/interval")
async def set_intel_interval(hours: int = Query(default=24, ge=1, le=168)):
    """Set the auto-update interval (1–168 hours)."""
    _intel_state["auto_interval_hours"] = hours
    return {"message": f"Auto-update interval set to {hours} hours"}
