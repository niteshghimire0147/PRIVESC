"""
threat_intel.py — Live threat intelligence feed.

Fetches and caches:
  - NVD (National Vulnerability Database) API v2 — CVE details, CVSS scores
  - CISA KEV (Known Exploited Vulnerabilities) catalog
  - EPSS (Exploit Prediction Scoring System) scores
  - CVE.org / MITRE CVE API — CWE classification, affected products, references

Performance design:
  - Per-CVE TTL: individual CVEs are only re-fetched when stale (not every run)
  - Parallel fetching: NVD and CVE.org requests run concurrently via ThreadPoolExecutor
  - HTTP 429 retry: NVD rate-limit responses are retried with exponential back-off
  - Bulk EPSS: all CVEs fetched in a single request
  - Reduced timeout: 8s per call (was 15s) for faster failure detection

Usage:
    from intelligence.threat_intel import ThreatIntelFeed
    feed = ThreatIntelFeed()
    feed.update(verbose=True)
    info = feed.get_cve_info("CVE-2022-0847")
"""

import json
import os
import time
import datetime
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed


DATA_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
CACHE_FILE = os.path.join(DATA_DIR, "threat_intel_cache.json")

# NVD API key — optional but strongly recommended (50 req/30s vs 5 req/30s)
# Set NVD_API_KEY in your .env file or environment to enable the higher rate limit.
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

# Public API endpoints (no API key required for basic use)
NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL   = "https://api.first.org/data/v1/epss"
CVEORG_API_URL = "https://cveawg.mitre.org/api/cve"   # CVE.org MITRE API (CVE JSON 5.0)

# CVEs tracked by PRIVESC across both platforms
TRACKED_CVES = [
    "CVE-2022-0847",   # Dirty Pipe
    "CVE-2021-4034",   # PwnKit
    "CVE-2021-3156",   # Baron Samedit
    "CVE-2016-5195",   # Dirty COW
    "CVE-2021-3493",   # Ubuntu OverlayFS
    "CVE-2022-2588",   # Route of Death
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2021-36934",  # HiveNightmare
    "CVE-2020-0796",   # SMBGhost
    "CVE-2019-1388",   # UAC certificate dialog
    "CVE-2022-21882",  # Win32k LPE
    "CVE-2023-21674",  # ALPC LPE
]

CACHE_TTL_HOURS     = 24    # full cache TTL
CVE_TTL_HOURS       = 72    # per-CVE TTL: skip re-fetch if fresher than this
FETCH_TIMEOUT       = 8     # seconds per HTTP call

# NVD rate limits:
#   Without API key: 5 req / 30s  →  1 worker,  6.5s delay
#   With API key:   50 req / 30s  →  8 workers, 0.5s delay
if NVD_API_KEY:
    NVD_RATE_DELAY  = 0.5   # 50 req/30s authenticated
    NVD_MAX_WORKERS = 8     # parallel workers — safe at 50 req/30s
else:
    NVD_RATE_DELAY  = 6.5   # 5 req/30s unauthenticated (stay under limit)
    NVD_MAX_WORKERS = 1     # single worker to avoid 429s

CVEORG_RATE_DELAY   = 0.15  # CVE.org has no hard limit — be a good citizen
CVEORG_MAX_WORKERS  = 6     # parallel CVE.org fetch workers
NVD_MAX_RETRIES     = 3     # retries on HTTP 429


# ── Thread-safe NVD rate limiter ──────────────────────────────────────────────
_nvd_lock      = threading.Lock()
_nvd_last_call = 0.0


def _nvd_throttle():
    """Ensure at least NVD_RATE_DELAY seconds between NVD calls (thread-safe)."""
    global _nvd_last_call
    with _nvd_lock:
        now  = time.monotonic()
        wait = NVD_RATE_DELAY - (now - _nvd_last_call)
        if wait > 0:
            time.sleep(wait)
        _nvd_last_call = time.monotonic()


def _fetch_url(url: str, timeout: int = FETCH_TIMEOUT) -> dict | list | None:
    """Fetch a JSON URL and return parsed content, or None on error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PRIVESC-SecurityScanner/2.2.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, Exception):
        return None


def _fetch_nvd(url: str, retries: int = NVD_MAX_RETRIES) -> dict | list | None:
    """Fetch from NVD with rate-limiting and HTTP 429 retry."""
    nvd_headers = {"User-Agent": "PRIVESC-SecurityScanner/2.2.0"}
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY
    for attempt in range(retries):
        _nvd_throttle()
        try:
            req = urllib.request.Request(
                url,
                headers=nvd_headers,
            )
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Rate limited — back off exponentially
                backoff = 6 * (2 ** attempt)
                time.sleep(backoff)
                continue
            return None
        except (urllib.error.URLError, json.JSONDecodeError, Exception):
            return None
    return None


def _cve_is_fresh(cve_entry: dict) -> bool:
    """Return True if this CVE entry was fetched within CVE_TTL_HOURS."""
    fetched_at = cve_entry.get("fetched_at", "")
    if not fetched_at:
        return False
    try:
        ts  = datetime.datetime.fromisoformat(fetched_at)
        age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - ts.replace(tzinfo=None)).total_seconds() / 3600
        return age < CVE_TTL_HOURS
    except Exception:
        return False


def _load_cache() -> dict:
    """Load the threat intel cache from disk."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    """Save the threat intel cache to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


# ── NVD per-CVE fetch ─────────────────────────────────────────────────────────

def _fetch_nvd_cve(cve_id: str, kev_catalog: set) -> tuple[str, dict | None]:
    """Fetch a single CVE from NVD. Returns (cve_id, entry_dict | None)."""
    url  = f"{NVD_API_URL}?cveId={cve_id}"
    data = _fetch_nvd(url)
    if not data:
        return cve_id, None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return cve_id, None

    cve_item = vulns[0].get("cve", {})
    metrics  = cve_item.get("metrics", {})

    cvss_score, cvss_vector, severity = None, "", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m           = metrics[key][0]
            cvss_data   = m.get("cvssData", {})
            cvss_score  = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString", "")
            # NVD v3 supplies baseSeverity directly; v2 uses baseSeverity too
            severity    = (m.get("baseSeverity") or cvss_data.get("baseSeverity", "")).upper()
            break

    # Derive severity from score if NVD didn't supply it explicitly
    if not severity and cvss_score is not None:
        if cvss_score >= 9.0:   severity = "CRITICAL"
        elif cvss_score >= 7.0: severity = "HIGH"
        elif cvss_score >= 4.0: severity = "MEDIUM"
        else:                   severity = "LOW"

    descriptions = cve_item.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    return cve_id, {
        "cve_id":            cve_id,
        "description":       desc_en[:500],
        "cvss_score":        cvss_score,
        "cvss_vector":       cvss_vector,
        "severity":          severity,
        "published":         cve_item.get("published", ""),
        "last_modified":     cve_item.get("lastModified", ""),
        "exploited_in_wild": cve_id in kev_catalog,
        "fetched_at":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ── CVE.org per-CVE fetch ─────────────────────────────────────────────────────

def _fetch_cveorg_cve(cve_id: str, kev_catalog: set) -> tuple[str, dict | None]:
    """Fetch a single CVE from CVE.org. Returns (cve_id, enrichment_dict | None)."""
    time.sleep(CVEORG_RATE_DELAY)
    url  = f"{CVEORG_API_URL}/{cve_id}"
    data = _fetch_url(url)
    if not data:
        return cve_id, None

    meta = data.get("cveMetadata", {})
    cna  = data.get("containers", {}).get("cna", {})

    cwe_ids: list[str] = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe = desc.get("cweId", "") or desc.get("description", "")
            if cwe and cwe not in cwe_ids:
                cwe_ids.append(cwe)

    affected: list[str] = []
    for a in cna.get("affected", []):
        vendor  = a.get("vendor", "")
        product = a.get("product", "")
        entry   = f"{vendor} {product}".strip()
        if entry and entry not in affected:
            affected.append(entry)

    refs: list[str] = [
        r["url"] for r in cna.get("references", []) if r.get("url")
    ][:5]

    cveorg_desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").lower().startswith("en"):
            cveorg_desc = d.get("value", "")[:500]
            break

    return cve_id, {
        "cwe_ids":           cwe_ids,
        "affected_products": affected[:10],
        "references":        refs,
        "cve_state":         meta.get("state", ""),
        "cveorg_published":  meta.get("datePublished", ""),
        "cveorg_desc":       cveorg_desc,
        "exploited_in_wild": cve_id in kev_catalog,
    }


# ── Main feed class ───────────────────────────────────────────────────────────

class ThreatIntelFeed:
    """
    Manages threat intelligence data for PRIVESC.

    Data is cached locally in data/threat_intel_cache.json and
    refreshed from public APIs when update() is called or the cache
    is stale (older than CACHE_TTL_HOURS).

    Per-CVE TTL (CVE_TTL_HOURS) means individual CVE records are only
    re-fetched when they are genuinely stale — skipping unchanged entries
    dramatically reduces update time on repeat runs.
    """

    def __init__(self):
        self._cache = _load_cache()
        self._kev_catalog: set[str] = set(self._cache.get("kev_cves", []))

    def _is_stale(self) -> bool:
        last_update = self._cache.get("last_updated", "")
        if not last_update:
            return True
        try:
            ts  = datetime.datetime.fromisoformat(last_update)
            age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - ts.replace(tzinfo=None)).total_seconds() / 3600
            return age > CACHE_TTL_HOURS
        except Exception:
            return True

    def update(self, verbose: bool = False, progress_callback=None) -> bool:
        """
        Refresh threat intelligence from NVD, CISA KEV, EPSS, and CVE.org.

        Speed optimisations vs. previous version:
          - Per-CVE TTL:   CVEs fresh within CVE_TTL_HOURS are skipped entirely
          - Parallel NVD:  up to NVD_MAX_WORKERS concurrent NVD requests
          - Parallel CVEORG: up to CVEORG_MAX_WORKERS concurrent CVE.org requests
          - HTTP 429 retry: exponential back-off on NVD rate-limit responses
          - Bulk EPSS:     all CVEs in one request (unchanged)
          - Timeout 8s:    faster failure detection (was 15s)

        Returns True if update succeeded, False if offline or all APIs unavailable.
        """
        if verbose:
            print("[*] Updating threat intelligence feeds...")

        updated      = False
        cve_details: dict = self._cache.get("cve_details", {})
        def _progress(step, step_name, cves_done=0, cves_total=0):
            if progress_callback:
                progress_callback(
                    step=step, total_steps=4, step_name=step_name,
                    cves_done=cves_done, cves_total=cves_total,
                )



        # ── STEP 1: CISA KEV (single bulk request) ────────────────────────────
        _progress(1, "CISA KEV", 0, 1)
        if verbose:
            print("    [1/4] Fetching CISA KEV catalog...")
        kev_data = _fetch_url(CISA_KEV_URL)
        if kev_data and "vulnerabilities" in kev_data:
            kev_cves = {v["cveID"] for v in kev_data["vulnerabilities"] if "cveID" in v}
            self._kev_catalog = kev_cves
            self._cache["kev_cves"] = list(kev_cves)
            if verbose:
                print(f"    ✔ CISA KEV: {len(kev_cves)} known-exploited CVEs loaded.")
            updated = True
        else:
            if verbose:
                print("    ✘ CISA KEV: unavailable (using cached list).")

        # ── STEP 2: NVD — parallel fetch, skip fresh CVEs ────────────────────
        stale_cves = [
            cve for cve in TRACKED_CVES
            if not _cve_is_fresh(cve_details.get(cve, {}))
        ]
        fresh_count = len(TRACKED_CVES) - len(stale_cves)

        if verbose:
            print(f"    [2/4] NVD: {len(stale_cves)} CVEs to fetch, "
                  f"{fresh_count} cached (skip)...")

        nvd_ok = 0
        _progress(2, "NVD", 0, len(stale_cves))
        if stale_cves:
            with ThreadPoolExecutor(max_workers=NVD_MAX_WORKERS) as pool:
                futures = {
                    pool.submit(_fetch_nvd_cve, cve, self._kev_catalog): cve
                    for cve in stale_cves
                }
                for future in as_completed(futures):
                    cve_id, entry = future.result()
                    if entry:
                        cve_details[cve_id] = entry
                        nvd_ok += 1
                        _progress(2, "NVD", nvd_ok, len(stale_cves))
                        if verbose:
                            score = entry.get("cvss_score", "N/A")
                            print(f"      ✔ {cve_id}  CVSS={score}")
                    else:
                        nvd_ok_shown = nvd_ok
                        _progress(2, "NVD", nvd_ok_shown, len(stale_cves))
                        if verbose:
                            print(f"      ✘ {cve_id}  (fetch failed / rate-limited)")

        if nvd_ok:
            updated = True
        if verbose:
            print(f"    NVD done: {nvd_ok}/{len(stale_cves)} fetched"
                  + (f", {fresh_count} served from cache." if fresh_count else "."))

        # ── STEP 3: EPSS — single bulk request for all CVEs ──────────────────
        _progress(3, "EPSS", 0, 1)
        if verbose:
            print("    [3/4] Fetching EPSS scores (bulk)...")
        cve_list_param = ",".join(TRACKED_CVES)
        epss_data = _fetch_url(f"{EPSS_API_URL}?cve={cve_list_param}")
        epss_ok   = 0
        if epss_data and "data" in epss_data:
            for entry in epss_data["data"]:
                cve_id = entry.get("cve")
                if cve_id in cve_details:
                    cve_details[cve_id]["epss_score"]      = float(entry.get("epss", 0))
                    cve_details[cve_id]["epss_percentile"] = float(entry.get("percentile", 0))
                    epss_ok += 1
            updated = True
            if verbose:
                print(f"    ✔ EPSS: {epss_ok} scores loaded.")
        else:
            if verbose:
                print("    ✘ EPSS: unavailable (using cached scores).")

        # ── STEP 4: CVE.org — parallel fetch, skip fresh CVEs ────────────────
        cveorg_stale = [
            cve for cve in TRACKED_CVES
            if not cve_details.get(cve, {}).get("cwe_ids")
            or not _cve_is_fresh(cve_details.get(cve, {}))
        ]
        cveorg_fresh = len(TRACKED_CVES) - len(cveorg_stale)

        if verbose:
            print(f"    [4/4] CVE.org: {len(cveorg_stale)} CVEs to fetch, "
                  f"{cveorg_fresh} cached (skip)...")

        cveorg_ok = 0
        _progress(4, "CVE.org", 0, len(cveorg_stale))
        if cveorg_stale:
            with ThreadPoolExecutor(max_workers=CVEORG_MAX_WORKERS) as pool:
                futures = {
                    pool.submit(_fetch_cveorg_cve, cve, self._kev_catalog): cve
                    for cve in cveorg_stale
                }
                for future in as_completed(futures):
                    cve_id, enrichment = future.result()
                    if enrichment:
                        entry = cve_details.setdefault(cve_id, {"cve_id": cve_id})
                        entry["cwe_ids"]           = enrichment["cwe_ids"]
                        entry["affected_products"] = enrichment["affected_products"]
                        entry["references"]        = enrichment["references"]
                        entry["cve_state"]         = enrichment["cve_state"]
                        entry["cveorg_published"]  = enrichment["cveorg_published"]
                        entry["exploited_in_wild"] = enrichment["exploited_in_wild"]
                        if not entry.get("description") and enrichment["cveorg_desc"]:
                            entry["description"]   = enrichment["cveorg_desc"]
                        cveorg_ok += 1
                        _progress(4, "CVE.org", cveorg_ok, len(cveorg_stale))
                        if verbose:
                            cwes = ", ".join(enrichment["cwe_ids"]) or "N/A"
                            print(f"      ✔ {cve_id}  CWE={cwes}")
                    else:
                        _progress(4, "CVE.org", cveorg_ok, len(cveorg_stale))
                        if verbose:
                            print(f"      ✘ {cve_id}  (CVE.org unavailable)")

        if cveorg_ok:
            updated = True
        if verbose:
            print(f"    CVE.org done: {cveorg_ok}/{len(cveorg_stale)} fetched"
                  + (f", {cveorg_fresh} served from cache." if cveorg_fresh else "."))

        # ── Save ──────────────────────────────────────────────────────────────
        self._cache["cve_details"]  = cve_details
        self._cache["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _save_cache(self._cache)

        if verbose:
            print(f"\n    Threat intel update {'succeeded' if updated else 'failed (all APIs offline?)'}. "
                  f"Cache: {len(cve_details)} CVEs stored.")

        return updated

    def get_cve_info(self, cve_id: str) -> dict:
        """Return cached threat intelligence for a given CVE ID."""
        details = self._cache.get("cve_details", {})
        return details.get(cve_id, {
            "cve_id":            cve_id,
            "exploited_in_wild": cve_id in self._kev_catalog,
        })

    def is_exploited_in_wild(self, cve_id: str) -> bool:
        """Return True if the CVE is in the CISA KEV catalog."""
        return cve_id in self._kev_catalog

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        """
        Add threat intelligence data to findings that reference CVEs.
        Adds a 'threat_intel' sub-dict to each relevant finding in-place.
        """
        import re
        for finding in findings:
            cve_id = finding.get("details", {}).get("cve") or ""
            if not cve_id.startswith("CVE-"):
                match = re.search(
                    r"CVE-\d{4}-\d+",
                    finding.get("type", "") + finding.get("description", "")
                )
                if match:
                    cve_id = match.group(0)

            if cve_id:
                info = self.get_cve_info(cve_id)
                if info:
                    finding["threat_intel"] = {
                        "cvss_score":        info.get("cvss_score"),
                        "cvss_vector":       info.get("cvss_vector", ""),
                        "epss_score":        info.get("epss_score", 0.0),
                        "epss_percentile":   info.get("epss_percentile", 0.0),
                        "exploited_in_wild": info.get("exploited_in_wild", False),
                        "nvd_description":   info.get("description", ""),
                        "cwe_ids":           info.get("cwe_ids", []),
                        "affected_products": info.get("affected_products", []),
                        "references":        info.get("references", []),
                        "cve_status":        info.get("cve_status", ""),
                    }
        return findings
