"""
html_generator.py — Professional HTML report generator.

Produces a self-contained, single-file HTML report with:
  - Inline CSS (no external dependencies, works offline)
  - Executive summary cards with severity counts
  - Category breakdown table
  - Full findings list with color-coded severity badges
  - Expandable detail sections per finding
  - Print-friendly layout
"""

import datetime
import html as _html


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _esc(text):
    """HTML-escape a value for safe embedding."""
    if text is None:
        return "N/A"
    return _html.escape(str(text))


def _severity_class(severity):
    return {
        "CRITICAL": "sev-critical",
        "HIGH":     "sev-high",
        "MEDIUM":   "sev-medium",
        "LOW":      "sev-low",
    }.get(severity, "sev-low")


def _severity_icon(severity):
    return {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }.get(severity, "⚪")


def _path_from_finding(f):
    return (
        f.get("path") or
        f.get("binary_path") or
        f.get("script_path") or
        f.get("setting") or
        "N/A"
    )


# ─── CSS ──────────────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    line-height: 1.6;
}

/* ── Layout ── */
.container { max-width: 1200px; margin: 0 auto; padding: 24px 20px; }

/* ── Banner ── */
.banner {
    background: linear-gradient(135deg, #161b22 0%, #1a1f2e 100%);
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 28px 32px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
}

.banner h1 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #58a6ff;
    margin-bottom: 6px;
}
.banner .subtitle { font-size: 0.85rem; color: #8b949e; }
.banner .meta { text-align: right; font-size: 0.83rem; color: #8b949e; line-height: 1.9; }
.banner .meta span { color: #c9d1d9; font-weight: 600; }

/* ── Risk Level Badge ── */
.risk-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.5px;
    margin-top: 8px;
}
.risk-CRITICAL { background: #3d0f0f; color: #ff6b6b; border: 1px solid #ff4444; }
.risk-HIGH     { background: #2d1f00; color: #ffb347; border: 1px solid #ff8c00; }
.risk-MEDIUM   { background: #1a1f3d; color: #79b8ff; border: 1px solid #388bfd; }
.risk-LOW      { background: #0f2d1a; color: #56d364; border: 1px solid #3fb950; }

/* ── Summary Cards ── */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 24px;
}
@media (max-width: 700px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }

.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}
.card .count {
    font-size: 2.8rem;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 6px;
}
.card .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; }
.card.critical .count { color: #ff6b6b; }
.card.critical { border-color: #3d1515; }
.card.high .count    { color: #ffb347; }
.card.high    { border-color: #3d2800; }
.card.medium .count  { color: #79b8ff; }
.card.medium  { border-color: #1a2a4d; }
.card.low .count     { color: #56d364; }
.card.low     { border-color: #1a3a25; }

/* ── Section Headings ── */
.section-title {
    font-size: 1rem;
    font-weight: 700;
    color: #58a6ff;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 28px 0 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Category Table ── */
.cat-table {
    width: 100%;
    border-collapse: collapse;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 24px;
    font-size: 0.9rem;
}
.cat-table th {
    background: #21262d;
    color: #8b949e;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.5px;
    padding: 12px 16px;
    text-align: left;
}
.cat-table th.num, .cat-table td.num { text-align: center; }
.cat-table td {
    padding: 11px 16px;
    border-top: 1px solid #21262d;
    color: #c9d1d9;
}
.cat-table tr:hover td { background: #1c2128; }
.cat-table .n-critical { color: #ff6b6b; font-weight: 700; }
.cat-table .n-high     { color: #ffb347; font-weight: 700; }
.cat-table .n-medium   { color: #79b8ff; }
.cat-table .n-low      { color: #56d364; }
.cat-table .n-zero     { color: #484f58; }

/* ── Severity Badges ── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.sev-critical { background: #3d0f0f; color: #ff6b6b; border: 1px solid #7d1f1f; }
.sev-high     { background: #2d1f00; color: #ffb347; border: 1px solid #7d4800; }
.sev-medium   { background: #1a1f3d; color: #79b8ff; border: 1px solid #2a4fa8; }
.sev-low      { background: #0f2d1a; color: #56d364; border: 1px solid #1f6b3a; }

/* ── Finding Cards ── */
.finding {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 10px;
    overflow: hidden;
}
.finding-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 16px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
}
.finding-header:hover { background: #1c2128; }
.finding-num { color: #484f58; font-size: 0.8rem; min-width: 38px; }
.finding-title { font-weight: 600; color: #c9d1d9; flex: 1; font-size: 0.92rem; }
.finding-path {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.78rem;
    color: #8b949e;
    max-width: 380px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.toggle-icon { color: #484f58; font-size: 0.8rem; margin-left: 8px; transition: transform 0.2s; }
.finding.open .toggle-icon { transform: rotate(180deg); }

.finding-body {
    display: none;
    padding: 0 16px 16px;
    border-top: 1px solid #21262d;
}
.finding.open .finding-body { display: block; }

.field-grid {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 4px 12px;
    margin: 12px 0;
    font-size: 0.875rem;
}
.field-label { color: #8b949e; font-weight: 600; padding-top: 1px; }
.field-value {
    color: #c9d1d9;
    font-family: 'Consolas', 'Courier New', monospace;
    word-break: break-all;
}
.field-value.plain { font-family: inherit; }

.subsection {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 12px 14px;
    margin-top: 10px;
    font-size: 0.875rem;
}
.subsection-title {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 8px;
}
.subsection-title.desc   { color: #8b949e; }
.subsection-title.exploit { color: #ff6b6b; }
.subsection-title.fix    { color: #56d364; }

pre {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.83rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: #c9d1d9;
    margin: 0;
}

.tag {
    display: inline-block;
    background: #21262d;
    color: #8b949e;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 0.72rem;
    margin-right: 4px;
}
.tag.yes { background: #2d1f00; color: #ffb347; }

/* ── System Info Table ── */
.sys-table {
    width: 100%;
    border-collapse: collapse;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 24px;
    font-size: 0.875rem;
}
.sys-table td { padding: 9px 16px; border-top: 1px solid #21262d; }
.sys-table tr:first-child td { border-top: none; }
.sys-table .key { color: #8b949e; font-weight: 600; width: 200px; }
.sys-table .val {
    font-family: 'Consolas', 'Courier New', monospace;
    color: #c9d1d9;
}

/* ── Shell Users Table ── */
.user-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 24px;
}
.user-table th {
    background: #21262d;
    color: #8b949e;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 10px 14px;
    text-align: left;
}
.user-table td { padding: 9px 14px; border-top: 1px solid #21262d; font-family: monospace; }
.user-table tr:hover td { background: #1c2128; }

/* ── Footer ── */
.footer {
    margin-top: 40px;
    padding: 16px;
    border-top: 1px solid #21262d;
    text-align: center;
    font-size: 0.78rem;
    color: #484f58;
}

/* ── Print styles ── */
@media print {
    body { background: white; color: black; }
    .container { max-width: 100%; }
    .finding-body { display: block !important; }
    .toggle-icon { display: none; }
    .banner, .card, .finding, .cat-table, .sys-table, .user-table {
        border: 1px solid #ccc !important;
        background: white !important;
        color: black !important;
        break-inside: avoid;
    }
    .section-title { color: #1a1a2e !important; border-bottom: 2px solid #ccc !important; }
    .badge { border: 1px solid #aaa !important; color: black !important; background: #f0f0f0 !important; }
    .count { color: black !important; }
    pre { background: #f5f5f5; padding: 8px; }
}
"""


# ─── JavaScript ───────────────────────────────────────────────────────────────

JS = """
function toggleFinding(el) {
    el.closest('.finding').classList.toggle('open');
}
function expandAll() {
    document.querySelectorAll('.finding').forEach(f => f.classList.add('open'));
}
function collapseAll() {
    document.querySelectorAll('.finding').forEach(f => f.classList.remove('open'));
    window.scrollTo(0, 0);
}
// Auto-expand CRITICAL findings
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.finding[data-sev="CRITICAL"]').forEach(f => f.classList.add('open'));
});
"""


# ─── HTML Sections ────────────────────────────────────────────────────────────

def _banner_html(system_info, summary):
    risk = summary["risk_level"]
    # Normalise cross-platform keys
    current_user  = system_info.get("current_user") or system_info.get("username", "")
    is_root       = system_info.get("is_root") or system_info.get("is_elevated", False)
    kernel_str    = system_info.get("kernel_release") or system_info.get("build_number", "")
    os_str        = system_info.get("os_name") or system_info.get("os_version", "")
    platform_name = "Windows" if system_info.get("build_number") else "Linux"
    priv_warn     = '&nbsp;<span style="color:#ff6b6b">ADMIN ⚠</span>' if is_root else ""
    return f"""
<div class="banner">
  <div>
    <h1>🛡 PRIVESC — {_esc(platform_name)} Privilege Escalation Scanner</h1>
    <div class="subtitle">Detection-only | Authorised security testing &amp; education</div>
    <div class="risk-badge risk-{_esc(risk)}">{_esc(risk)} RISK</div>
  </div>
  <div class="meta">
    <div>Generated &nbsp;<span>{_esc(_now())}</span></div>
    <div>Host &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>{_esc(system_info.get('hostname'))}</span></div>
    <div>User &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>{_esc(current_user)}</span>{priv_warn}</div>
    <div>Kernel &nbsp;&nbsp;&nbsp;&nbsp;<span>{_esc(kernel_str)}</span></div>
    <div>OS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>{_esc(os_str)}</span></div>
    <div>Risk Score <span>{summary['risk_score']}</span></div>
  </div>
</div>"""


def _summary_cards_html(summary):
    return f"""
<div class="summary-grid">
  <div class="card critical">
    <div class="count">{summary['critical']}</div>
    <div class="label">🔴 Critical</div>
  </div>
  <div class="card high">
    <div class="count">{summary['high']}</div>
    <div class="label">🟠 High</div>
  </div>
  <div class="card medium">
    <div class="count">{summary['medium']}</div>
    <div class="label">🟡 Medium</div>
  </div>
  <div class="card low">
    <div class="count">{summary['low']}</div>
    <div class="label">🟢 Low</div>
  </div>
</div>"""


def _category_table_html(findings_by_category, category_counts):
    from analysis.engine import CATEGORY_ORDER
    ordered = [c for c in CATEGORY_ORDER if c in findings_by_category]
    other = [c for c in findings_by_category if c not in CATEGORY_ORDER]

    def num_cell(n, cls):
        css = cls if n > 0 else "n-zero"
        return f'<td class="num {css}">{n if n > 0 else "—"}</td>'

    rows = ""
    for cat in ordered + other:
        cc = category_counts.get(cat, {})
        total = sum(cc.values())
        rows += f"""
    <tr>
      <td>{_esc(cat)}</td>
      {num_cell(cc.get('CRITICAL', 0), 'n-critical')}
      {num_cell(cc.get('HIGH', 0),     'n-high')}
      {num_cell(cc.get('MEDIUM', 0),   'n-medium')}
      {num_cell(cc.get('LOW', 0),      'n-low')}
      <td class="num" style="font-weight:600">{total}</td>
    </tr>"""

    return f"""
<div class="section-title">📊 Findings by Category</div>
<table class="cat-table">
  <thead>
    <tr>
      <th>Category</th>
      <th class="num">Critical</th>
      <th class="num">High</th>
      <th class="num">Medium</th>
      <th class="num">Low</th>
      <th class="num">Total</th>
    </tr>
  </thead>
  <tbody>{rows}
  </tbody>
</table>"""


def _system_info_table_html(system_info):
    rows = ""
    # Normalise cross-platform keys
    current_user = system_info.get("current_user") or system_info.get("username")
    kernel_str   = system_info.get("kernel_release") or system_info.get("build_number")
    os_str       = system_info.get("os_name") or system_info.get("os_version")
    fields = [
        ("Hostname",        system_info.get("hostname")),
        ("Current User",    current_user),
        ("User ID (id)",    system_info.get("user_id")),
        ("Kernel Release",  kernel_str),
        ("Kernel Full",     system_info.get("kernel_version")),
        ("OS",              os_str),
        ("OS Version",      system_info.get("os_version")),
        ("Build Number",    system_info.get("build_number")),
        ("Architecture",    system_info.get("architecture")),
        ("Home Directory",  system_info.get("home_dir")),
        ("PATH",            system_info.get("env_path")),
        ("Sudo Version",    system_info.get("sudo_version")),
    ]
    for key, val in fields:
        if val:
            rows += f'<tr><td class="key">{_esc(key)}</td><td class="val">{_esc(val)}</td></tr>\n'

    return f"""
<div class="section-title">💻 System Information</div>
<table class="sys-table">{rows}</table>"""


def _shell_users_html(shell_users):
    if not shell_users:
        return ""
    rows = "".join(
        f'<tr><td>{_esc(u["uid"])}</td><td>{_esc(u["user"])}</td><td>{_esc(u["shell"])}</td></tr>'
        for u in shell_users
    )
    return f"""
<div class="section-title">👤 Users with Shell Access</div>
<table class="user-table">
  <thead><tr><th>UID</th><th>Username</th><th>Shell</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _finding_card_html(index, f):
    severity = f.get("severity", "LOW")
    category = _esc(f.get("category", "Unknown"))
    ftype = _esc(f.get("type", "Unknown"))
    path = _esc(_path_from_finding(f))
    sev_class = _severity_class(severity)
    icon = _severity_icon(severity)

    # ── Header ──
    header = f"""
<div class="finding-header" onclick="toggleFinding(this)">
  <span class="finding-num">#{index:03d}</span>
  <span class="badge {sev_class}">{icon} {_esc(severity)}</span>
  <span class="finding-title">{category} &rsaquo; {ftype}</span>
  <span class="finding-path">{path}</span>
  <span class="toggle-icon">▼</span>
</div>"""

    # ── Field grid ──
    grid_rows = ""

    def add_field(label, value, plain=False):
        nonlocal grid_rows
        if value:
            cls = "field-value plain" if plain else "field-value"
            grid_rows += f'<div class="field-label">{_esc(label)}</div><div class="{cls}">{_esc(value)}</div>\n'

    add_field("Path / Target", _path_from_finding(f))

    if f.get("bit_type"):
        add_field("Bit Type", f.get("bit_type"))
        gtfo = "Yes ⚠" if f.get("in_gtfobins") else "No"
        gtfo_class = "field-value plain"
        grid_rows += (
            f'<div class="field-label">In GTFOBins</div>'
            f'<div class="{gtfo_class}">'
            f'<span class="tag {"yes" if f.get("in_gtfobins") else ""}">{_esc(gtfo)}</span>'
            f'</div>\n'
        )

    if f.get("schedule"):
        add_field("Cron Schedule", f.get("schedule"))
        add_field("Runs As", f.get("user"))

    if f.get("service"):
        add_field("Service", f.get("service"))
        add_field("Service File", f.get("service_file"))
        add_field("Runs As", f.get("runs_as"))

    if f.get("cve_id") and f.get("cve_id") != "N/A":
        cve_display = f.get("cve_id", "")
        if f.get("cve_name"):
            cve_display += f"  ({f.get('cve_name')})"
        add_field("CVE", cve_display)

    if f.get("capabilities"):
        add_field("Capabilities", f.get("capabilities"))

    if f.get("permissions"):
        add_field("Permissions", f.get("permissions"))

    if f.get("dangerous_caps"):
        add_field("Dangerous Caps", ", ".join(f.get("dangerous_caps", [])))

    # ── Body sections ──
    body_parts = ""

    if grid_rows:
        body_parts += f'<div class="field-grid">{grid_rows}</div>'

    notes = f.get("notes", "").strip()
    if notes:
        body_parts += f"""
<div class="subsection">
  <div class="subsection-title desc">📋 Description</div>
  <pre>{_esc(notes)}</pre>
</div>"""

    exploit = f.get("exploit_example", "").strip()
    if exploit:
        body_parts += f"""
<div class="subsection">
  <div class="subsection-title exploit">⚡ Exploit Example (authorised testing only)</div>
  <pre>{_esc(exploit)}</pre>
</div>"""

    ref = f.get("reference", "").strip()
    if ref and ref != "N/A":
        body_parts += f"""
<div class="subsection">
  <div class="subsection-title desc">🔗 Reference</div>
  <pre>{_esc(ref)}</pre>
</div>"""

    mitigation = f.get("mitigation", "").strip()
    if mitigation:
        body_parts += f"""
<div class="subsection">
  <div class="subsection-title fix">🛠 Mitigation</div>
  <pre>{_esc(mitigation)}</pre>
</div>"""

    return f"""
<div class="finding" data-sev="{_esc(severity)}">
  {header}
  <div class="finding-body">
    {body_parts}
  </div>
</div>"""


def _findings_section_html(findings):
    if not findings:
        return """
<div class="section-title">🔍 Detailed Findings</div>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
     padding:32px;text-align:center;color:#56d364;">
  ✅ No findings detected — the system appears well-hardened.
</div>"""

    controls = """
<div style="margin-bottom:10px;text-align:right;">
  <button onclick="expandAll()"
    style="background:#21262d;color:#8b949e;border:1px solid #30363d;
    border-radius:6px;padding:5px 14px;cursor:pointer;font-size:0.82rem;margin-right:6px;">
    Expand All
  </button>
  <button onclick="collapseAll()"
    style="background:#21262d;color:#8b949e;border:1px solid #30363d;
    border-radius:6px;padding:5px 14px;cursor:pointer;font-size:0.82rem;">
    Collapse All
  </button>
</div>"""

    cards = "".join(_finding_card_html(i, f) for i, f in enumerate(findings, 1))

    return f"""
<div class="section-title">🔍 Detailed Findings ({len(findings)} total)</div>
{controls}
{cards}"""


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_html(system_info, results, output_file=None):
    """
    Generate a self-contained HTML security report.

    Args:
        system_info (dict): From modules/system_info.collect().
        results (dict): From analysis/engine.analyse().
        output_file (str|None): If given, write to this path.

    Returns:
        str: Full HTML document as a string.
    """
    summary = results["summary"]
    findings = results["findings"]
    findings_by_category = results["findings_by_category"]
    category_counts = results["category_counts"]
    shell_users = system_info.get("shell_users", [])

    body = (
        _banner_html(system_info, summary) +
        _summary_cards_html(summary) +
        _system_info_table_html(system_info) +
        (_shell_users_html(shell_users) if shell_users else "") +
        _category_table_html(findings_by_category, category_counts) +
        _findings_section_html(findings)
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PRIVESC Report â {_esc(system_info.get('hostname', 'host'))} â {_esc(_now())}</title>
  <style>{CSS}</style>
</head>
<body>
<div class="container">
{body}
<div class="footer">
  PRIVESC Cross-Platform Privilege Escalation Toolkit &nbsp;|&nbsp;
  For authorised security testing and educational purposes only &nbsp;|&nbsp;
  Generated {_esc(_now())}
</div>
</div>
<script>{JS}</script>
</body>
</html>"""

    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(doc)

    return doc
