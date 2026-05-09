#!/usr/bin/env python3
"""
main.py — Cross-Platform Privilege Escalation Automation Toolkit

Entry point and orchestrator. Auto-detects the host OS (Linux or Windows),
runs the appropriate scanner modules in sequence, passes findings through the
full analysis pipeline, and generates the final report.

Usage:
    python3 main.py [options]

Options:
    -o, --output <file>             Write report to file (base name)
    -f, --format [text|json|html|sarif|all]  Output format (default: html)
    -v, --verbose                   Print progress messages while scanning
    --no-color                      Disable ANSI colour codes in terminal output
    --quick                         Quick mode: skip slow filesystem scans
    --skip <modules>                Comma-separated list of modules to skip
                                    Linux:   suid, perms, services, cron, kernel,
                                             caps, creds, path
                                    Windows: services, registry, privs, creds,
                                             path, tasks, uac, kernel
    --compare <old.json> <new.json> Diff two JSON scan reports and show changes
    --update-intel                  Refresh threat intelligence feeds (NVD/CISA KEV/EPSS)
                                    then exit (or continue scan if combined with other flags)
    --no-intel                      Skip threat intelligence enrichment entirely
    --no-compliance                 Skip MITRE/CIS/NIST compliance mapping
    --no-attack-paths               Skip attack path chaining analysis
    --web                           Launch the web dashboard
    --host <addr>                   Dashboard bind address (default: 127.0.0.1)
    --port <port>                   Dashboard bind port (default: 5000)
    -h, --help                      Show this help message

Examples:
    python3 main.py
    python3 main.py -o report -f all -v
    python3 main.py -f sarif -o findings.sarif
    python3 main.py --compare old.json new.json
    python3 main.py --update-intel
    python3 main.py --skip kernel,uac -v
    python3 main.py --quick -f html -o report.html
    python3 main.py --web
    python3 main.py --web --host 0.0.0.0 --port 8080
"""

import sys
import os
import argparse
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ── Path setup: allow imports from project root ──────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DATA_DIR   = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")


def ensure_output_dir():
    """Create the output/ directory if it does not exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_platform() -> str:
    """Return 'linux', 'windows', or 'unknown'."""
    import platform
    s = platform.system().lower()
    if s == "linux":
        return "linux"
    if s == "windows":
        return "windows"
    return "unknown"


def check_platform():
    """Warn if running on an unsupported platform."""
    p = get_platform()
    if p == "unknown":
        import platform
        print(
            "\n[WARNING] Unsupported platform detected.\n"
            f"  Detected: {platform.system()}\n"
            "  This toolkit supports Linux and Windows.\n"
        )


def print_banner(use_color=True):
    """Print the startup banner."""
    RED   = "\033[91m" if use_color else ""
    CYAN  = "\033[96m" if use_color else ""
    RESET = "\033[0m"  if use_color else ""
    BOLD  = "\033[1m"  if use_color else ""

    banner = f"""
{RED}{'═'*70}{RESET}
{BOLD}{CYAN}  ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
  ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
  ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
  ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝{RESET}

  {BOLD}Privilege Escalation Automation Toolkit  v2.2.0{RESET}
  {CYAN}Linux + Windows | Detection-only | Authorised testing only{RESET}
{RED}{'═'*70}{RESET}
"""
    print(banner)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cross-Platform Privilege Escalation Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
    python3 main.py
    python3 main.py -o report -f all -v
    python3 main.py -f sarif -o findings.sarif
    python3 main.py --compare old.json new.json
    python3 main.py --update-intel
    python3 main.py --skip kernel,caps -v
    python3 main.py --quick -f html -o report.html
    python3 main.py --web
    python3 main.py --web --host 0.0.0.0 --port 8080""",
    )
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write report to FILE (base name; extensions added per format)")
    parser.add_argument("-f", "--format",
                        choices=["text", "json", "html", "sarif", "all"],
                        default="html",
                        help="Output format (default: html)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress while scanning")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour codes")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: skip slow filesystem scans")
    parser.add_argument("--skip", metavar="MODULES",
                        help="Comma-separated modules to skip")

    # ── Phase 5: new CLI options ─────────────────────────────────────────────
    parser.add_argument("--compare", nargs=2, metavar=("OLD_JSON", "NEW_JSON"),
                        help="Diff two JSON scan reports and show what changed")
    parser.add_argument("--update-intel", action="store_true",
                        help="Refresh NVD / CISA KEV / EPSS threat intel feeds")
    parser.add_argument("--no-intel", action="store_true",
                        help="Skip threat intelligence enrichment")
    parser.add_argument("--no-compliance", action="store_true",
                        help="Skip MITRE/CIS/NIST compliance mapping")
    parser.add_argument("--no-attack-paths", action="store_true",
                        help="Skip attack path chaining analysis")

    # ── Web dashboard ────────────────────────────────────────────────────────
    parser.add_argument("--web", action="store_true",
                        help="Launch the web dashboard (requires fastapi + uvicorn)")
    parser.add_argument("--host", default="127.0.0.1", metavar="HOST",
                        help="Dashboard bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, metavar="PORT",
                        help="Dashboard bind port (default: 5000)")

    return parser.parse_args()


def run_scanner(name, func, verbose):
    """
    Run a scanner module function, catch errors, and return findings.

    Args:
        name (str): Display name for progress output.
        func (callable): Scanner function to call.
        verbose (bool): Whether to print progress.

    Returns:
        list[dict]: Findings, or empty list on error.
    """
    if verbose:
        print(f"\n[*] Running: {name}...")

    start = time.time()
    try:
        findings = func()
        elapsed = time.time() - start
        if verbose:
            print(f"    Done in {elapsed:.1f}s — {len(findings)} findings.")
        return findings
    except OSError as e:
        if verbose:
            print(f"    [!] Permission denied: {e}")
        return []
    except Exception as e:
        print(f"    [ERROR] {name} failed: {e}", file=sys.stderr)
        return []


def run_linux_scanners(args, skip, quick, info, all_findings):
    """Run all Linux-specific scanner modules."""

    # ── Step 2a: SUID/SGID Scan ─────────────────────────────────────────────
    if "suid" not in skip:
        label = "[STEP 2a/8] Scanning SUID/SGID binaries"
        label += " (quick: known paths only)..." if quick else "..."
        print(f"\n{label}")
        from modules import suid_scanner
        findings = run_scanner(
            "SUID/SGID Scanner",
            lambda: suid_scanner.scan(data_dir=DATA_DIR, verbose=args.verbose, quick=quick),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        gtfo_hits = sum(1 for f in findings if f.get("in_gtfobins"))
        print(f"  Found {len(findings)} SUID/SGID binaries | {gtfo_hits} with GTFOBins exploit paths")

    # ── Step 2b: Permission Scan ─────────────────────────────────────────────
    if "perms" not in skip:
        label = "[STEP 2b/8] Scanning file and directory permissions"
        label += " (quick: critical files only)..." if quick else "..."
        print(f"\n{label}")
        from modules import permission_scanner
        findings = run_scanner(
            "Permission Scanner",
            lambda: permission_scanner.scan(verbose=args.verbose, quick=quick),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} permission issues")

    # ── Step 2c: Service Scan ────────────────────────────────────────────────
    if "services" not in skip:
        print("\n[STEP 2c/8] Scanning services and sudo rules...")
        from modules import service_scanner
        findings = run_scanner(
            "Service Scanner",
            lambda: service_scanner.scan(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} service/sudo issues")

    # ── Step 2d: Cron Scan ───────────────────────────────────────────────────
    if "cron" not in skip:
        print("\n[STEP 2d/8] Scanning cron jobs...")
        from modules import cron_scanner
        findings = run_scanner(
            "Cron Scanner",
            lambda: cron_scanner.scan(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} cron vulnerabilities")

    # ── Step 2e: Kernel Scan ─────────────────────────────────────────────────
    if "kernel" not in skip:
        print("\n[STEP 2e/8] Checking kernel version and CVEs...")
        from modules import kernel_scanner
        findings = run_scanner(
            "Kernel Scanner",
            lambda: kernel_scanner.scan(data_dir=DATA_DIR, verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        cves = sum(1 for f in findings if f.get("type") == "Known Kernel CVE")
        print(f"  Found {cves} CVE matches, {len(findings) - cves} hardening issues")

    # ── Step 2f: Capabilities Scan ───────────────────────────────────────────
    if "caps" not in skip:
        print("\n[STEP 2f/8] Scanning Linux capabilities (getcap)...")
        from modules import capabilities_scanner
        findings = run_scanner(
            "Capabilities Scanner",
            lambda: capabilities_scanner.scan(data_dir=DATA_DIR, verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} capability issues")

    # ── Step 2g: Credential Scan ─────────────────────────────────────────────
    if "creds" not in skip:
        print("\n[STEP 2g/8] Scanning for exposed credentials and secrets...")
        from modules import credential_scanner
        findings = run_scanner(
            "Credential Scanner",
            lambda: credential_scanner.scan(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} credential exposure issues")

    # ── Step 2h: PATH Hijacking Scan ─────────────────────────────────────────
    if "path" not in skip:
        print("\n[STEP 2h/8] Scanning for PATH hijacking vulnerabilities...")
        from modules import path_scanner
        findings = run_scanner(
            "PATH Hijacking Scanner",
            lambda: path_scanner.scan(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} PATH hijacking risks")


def run_windows_scanners(args, skip, quick, info, all_findings):
    """Run all Windows-specific scanner modules."""

    # ── Step 2a: Service Scan ────────────────────────────────────────────────
    if "services" not in skip:
        print("\n[STEP 2a/8] Scanning Windows services (unquoted paths, weak perms)...")
        from modules.windows import windows_service_scanner
        findings = run_scanner(
            "Windows Service Scanner",
            lambda: windows_service_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} service issue(s)")

    # ── Step 2b: Registry Scan ───────────────────────────────────────────────
    if "registry" not in skip:
        print("\n[STEP 2b/8] Scanning registry (AlwaysInstallElevated, AutoRun, autologon)...")
        from modules.windows import windows_registry_scanner
        findings = run_scanner(
            "Windows Registry Scanner",
            lambda: windows_registry_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} registry issue(s)")

    # ── Step 2c: Token Privileges Scan ───────────────────────────────────────
    if "privs" not in skip:
        print("\n[STEP 2c/8] Scanning token privileges (whoami /priv)...")
        from modules.windows import windows_privilege_scanner
        findings = run_scanner(
            "Windows Privilege Scanner",
            lambda: windows_privilege_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} dangerous privilege(s)")

    # ── Step 2d: Credential Scan ─────────────────────────────────────────────
    if "creds" not in skip:
        print("\n[STEP 2d/8] Scanning for exposed credentials (cmdkey, unattend, SAM)...")
        from modules.windows import windows_credential_scanner
        findings = run_scanner(
            "Windows Credential Scanner",
            lambda: windows_credential_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} credential issue(s)")

    # ── Step 2e: PATH / DLL Hijacking Scan ───────────────────────────────────
    if "path" not in skip:
        print("\n[STEP 2e/8] Scanning for PATH and DLL hijacking vectors...")
        from modules.windows import windows_path_scanner
        findings = run_scanner(
            "Windows PATH Scanner",
            lambda: windows_path_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} PATH/DLL hijacking risk(s)")

    # ── Step 2f: Scheduled Tasks Scan ────────────────────────────────────────
    if "tasks" not in skip:
        print("\n[STEP 2f/8] Scanning scheduled tasks for writable binaries...")
        from modules.windows import windows_task_scanner
        findings = run_scanner(
            "Windows Task Scanner",
            lambda: windows_task_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} scheduled task issue(s)")

    # ── Step 2g: UAC Scan ────────────────────────────────────────────────────
    if "uac" not in skip:
        print("\n[STEP 2g/8] Scanning UAC configuration...")
        from modules.windows import windows_uac_scanner
        findings = run_scanner(
            "Windows UAC Scanner",
            lambda: windows_uac_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        print(f"  Found {len(findings)} UAC issue(s)")

    # ── Step 2h: Kernel CVE Scan ─────────────────────────────────────────────
    if "kernel" not in skip:
        print("\n[STEP 2h/8] Checking Windows version against known CVEs...")
        from modules.windows import windows_kernel_scanner
        findings = run_scanner(
            "Windows Kernel Scanner",
            lambda: windows_kernel_scanner.run(verbose=args.verbose),
            verbose=args.verbose,
        )
        all_findings.extend(findings)
        cves = sum(1 for f in findings if "CVE" in f.get("type", ""))
        print(f"  Found {cves} CVE match(es), {len(findings) - cves} hardening issue(s)")


# ── Mode: --compare ──────────────────────────────────────────────────────────

def run_compare_mode(old_path: str, new_path: str, use_color: bool):
    """
    Load two PRIVESC JSON reports, diff them, and print the result.
    Exits after printing.
    """
    from analysis.diff_engine import compare, render_diff_text

    if not os.path.isfile(old_path):
        print(f"[ERROR] Old report not found: {old_path}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(new_path):
        print(f"[ERROR] New report not found: {new_path}", file=sys.stderr)
        sys.exit(2)

    print("\n[*] Comparing reports:")
    print(f"    Old : {old_path}")
    print(f"    New : {new_path}\n")

    diff = compare(old_path, new_path)
    print(render_diff_text(diff, use_color=use_color))
    sys.exit(0)


# ── Mode: --update-intel ─────────────────────────────────────────────────────

def run_update_intel(verbose: bool) -> bool:
    """
    Refresh the threat intelligence cache (NVD / CISA KEV / EPSS).
    Returns True on success.
    """
    try:
        from intelligence.threat_intel import ThreatIntelFeed
        feed = ThreatIntelFeed()
        ok = feed.update(verbose=True)
        if ok:
            print("\n[+] Threat intelligence updated successfully.")
        else:
            print("\n[!] Threat intelligence update failed (offline or API unavailable).")
        return ok
    except Exception as e:
        print(f"\n[ERROR] Failed to update threat intelligence: {e}", file=sys.stderr)
        return False


# ── Enrichment pipeline ──────────────────────────────────────────────────────

def enrich_findings(findings: list, args) -> list:
    """
    Run the full enrichment pipeline on raw findings:
      1. Threat intelligence (CVSS, EPSS, CISA KEV)
      2. Compliance mapping (MITRE ATT&CK, CIS, NIST SP 800-53, ISO 27001)
      3. Priority scoring (composite 0-100 score)
    Returns the enriched findings list (modified in-place and returned).
    """

    # ── 1. Threat Intelligence ───────────────────────────────────────────────
    if not args.no_intel:
        try:
            from intelligence.threat_intel import ThreatIntelFeed
            feed = ThreatIntelFeed()
            feed.auto_update_if_stale(verbose=args.verbose)
            findings = feed.enrich_findings(findings)
            intel_count = sum(1 for f in findings if "threat_intel" in f)
            if args.verbose and intel_count:
                print(f"    Threat intel enriched {intel_count} finding(s).")
        except Exception as e:
            if args.verbose:
                print(f"    [!] Threat intel enrichment skipped: {e}")

    # ── 2. Compliance Mapping ────────────────────────────────────────────────
    if not args.no_compliance:
        try:
            from analysis.compliance_mapper import enrich_with_compliance
            findings = enrich_with_compliance(findings)
            comp_count = sum(1 for f in findings if f.get("compliance"))
            if args.verbose and comp_count:
                print(f"    Compliance mapped {comp_count} finding(s).")
        except Exception as e:
            if args.verbose:
                print(f"    [!] Compliance mapping skipped: {e}")

    # ── 3. Priority Scoring ──────────────────────────────────────────────────
    try:
        from analysis.priority_engine import enrich_with_priority
        findings = enrich_with_priority(findings)
        if args.verbose:
            high_pri = sum(1 for f in findings if f.get("priority_score", 0) >= 80)
            print(f"    Priority scoring complete — {high_pri} finding(s) in immediate-action tier.")
    except Exception as e:
        if args.verbose:
            print(f"    [!] Priority scoring skipped: {e}")

    return findings


def analyse_attack_paths(findings: list, args) -> list:
    """Run the attack path chaining engine. Returns list of AttackPath dicts."""
    if args.no_attack_paths:
        return []
    try:
        from analysis.attack_path_engine import analyse_attack_paths as _analyse
        paths = _analyse(findings)
        if args.verbose and paths:
            print(f"    Attack path engine identified {len(paths)} exploit chain(s).")
        return [p.to_dict() for p in paths]
    except Exception as e:
        if args.verbose:
            print(f"    [!] Attack path analysis skipped: {e}")
        return []


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    use_color = not args.no_color and sys.stdout.isatty()

    print_banner(use_color=use_color)
    ensure_output_dir()

    # ── Mode: --web (launch dashboard, exits) ────────────────────────────────
    if args.web:
        try:
            import uvicorn
        except ImportError:
            print(
                "[ERROR] Web dashboard requires extra dependencies.\n"
                "  Run:  pip install fastapi uvicorn[standard] pydantic python-multipart\n"
                "  Or:   pip install -r requirements-web.txt",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"[*] Starting web dashboard on http://{args.host}:{args.port}")
        print("[*] Press Ctrl+C to stop.\n")

        # Ensure data/ dir exists for SQLite DB
        os.makedirs(os.path.join(PROJECT_ROOT, "data"), exist_ok=True)

        uvicorn.run(
            "web.app:app",
            host=args.host,
            port=args.port,
            reload=False,
            log_level="info",
        )
        sys.exit(0)

    # ── Mode: --compare (runs standalone, exits) ─────────────────────────────
    if args.compare:
        run_compare_mode(args.compare[0], args.compare[1], use_color=use_color)
        # run_compare_mode calls sys.exit — execution stops here.

    # ── Mode: --update-intel ─────────────────────────────────────────────────
    if args.update_intel:
        run_update_intel(verbose=args.verbose)
        # If no scan was also requested, exit now.
        # (If user combined --update-intel with a scan, continue below.)
        if not args.output and args.format == "html":
            # Default invocation — treat as "update only" and exit.
            sys.exit(0)

    check_platform()
    current_platform = get_platform()

    # Parse skipped modules
    skip = set()
    if args.skip:
        skip = {s.strip().lower() for s in args.skip.split(",")}

    quick = args.quick
    if quick:
        print("[i] Quick mode enabled — skipping slow filesystem sweeps.\n")

    all_findings = []

    if current_platform == "windows":
        # ── Step 1: Windows System Information ──────────────────────────────
        print("[STEP 1/8] Collecting Windows system information...")
        from modules.windows import windows_system_info
        info = windows_system_info.collect(verbose=args.verbose)
        print(f"  Host   : {info.get('hostname')}")
        print(f"  User   : {info.get('username')}  ({'Admin ⚠' if info.get('is_elevated') else 'Non-Admin'})")
        print(f"  OS     : {info.get('os_version')}")
        print(f"  Build  : {info.get('build_number')}")
        if info.get("is_elevated"):
            print("\n  ⚠  Running as Administrator — all checks have full access.\n")

        # ── Step 2: Windows Scanners ─────────────────────────────────────────
        run_windows_scanners(args, skip, quick, info, all_findings)

    else:
        # ── Step 1: Linux System Information ────────────────────────────────
        print("[STEP 1/8] Collecting system information...")
        from modules import system_info
        info = system_info.collect()
        print(f"  Host   : {info.get('hostname')}")
        print(f"  User   : {info.get('current_user')}  ({'ROOT ⚠' if info.get('is_root') else 'non-root'})")
        print(f"  Kernel : {info.get('kernel_release')}")
        print(f"  OS     : {info.get('os_name')}")
        if info.get("is_root"):
            print("\n  ⚠  Running as ROOT — all filesystem checks will have full access.\n")

        # ── Step 2: Linux Scanners ────────────────────────────────────────────
        run_linux_scanners(args, skip, quick, info, all_findings)

    # ── Step 3: Analysis engine ───────────────────────────────────────────────
    print("\n[STEP 3/8] Running analysis engine...")
    from analysis import engine
    results = engine.analyse(all_findings)
    summary = results["summary"]

    risk_color = SEVERITY_COLORS_TERMINAL.get(summary["risk_level"], "") if use_color else ""
    reset = "\033[0m" if use_color else ""

    print(f"  Overall Risk: {risk_color}{summary['risk_level']}{reset}  (score: {summary['risk_score']})")
    print(f"  Critical: {summary['critical']}  High: {summary['high']}  "
          f"Medium: {summary['medium']}  Low: {summary['low']}  Total: {summary['total']}")

    # ── Step 3b: Enrichment pipeline ─────────────────────────────────────────
    print("\n[STEP 3b/8] Running enrichment pipeline...")
    enriched_findings = enrich_findings(results.get("findings", all_findings), args)
    results["findings"] = enriched_findings

    # ── Step 3c: Attack path chaining ────────────────────────────────────────
    if not args.no_attack_paths:
        print("\n[STEP 3c/8] Analysing attack paths...")
        attack_paths = analyse_attack_paths(enriched_findings, args)
        results["attack_paths"] = attack_paths
        if attack_paths:
            critical_chains = sum(1 for p in attack_paths if p.get("severity") in ("CRITICAL", "HIGH"))
            print(f"  {len(attack_paths)} attack path(s) identified — {critical_chains} critical/high severity chain(s)")
        else:
            print("  No chained attack paths identified.")
    else:
        results["attack_paths"] = []

    # ── Step 4: Compliance summary ────────────────────────────────────────────
    if not args.no_compliance:
        try:
            from analysis.compliance_mapper import get_compliance_summary
            results["compliance_summary"] = get_compliance_summary(enriched_findings)
        except Exception:
            results["compliance_summary"] = {}

    # ── Step 5: Priority summary ──────────────────────────────────────────────
    try:
        from analysis.priority_engine import compute_enhanced_risk_summary
        results["priority_summary"] = compute_enhanced_risk_summary(enriched_findings)
    except Exception:
        results["priority_summary"] = {}

    # ── Step 6: Report Generation ─────────────────────────────────────────────
    print("\n[STEP 6/8] Generating report...")
    from reporter import generator
    import datetime as _dt

    fmt = args.format

    # Build timestamped base name inside output/ when -o is not specified
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = info.get("hostname", "host").replace(" ", "_")
    default_base = os.path.join(OUTPUT_DIR, f"privesc_{hostname}_{ts}")

    # Resolve the output base path
    if args.output:
        if os.path.dirname(args.output):
            output_base = args.output
        else:
            output_base = os.path.join(OUTPUT_DIR, args.output)
    else:
        output_base = default_base

    # ── Text report ──────────────────────────────────────────────────────────
    if fmt in ("text", "all"):
        text_file = output_base + ".txt"

        text_report = generator.generate_text(
            info, results,
            output_file=None,
            use_color=use_color,
        )

        # Always print coloured version to stdout
        print("\n")
        print(text_report)

        plain_report = generator.generate_text(info, results, use_color=False)
        with open(text_file, "w", encoding="utf-8") as f:
            f.write(plain_report)
        print(f"\n[+] Text report    : {text_file}")

    # ── JSON report ──────────────────────────────────────────────────────────
    if fmt in ("json", "all"):
        json_file = output_base + ".json"
        generator.generate_json(info, results, output_file=json_file)
        print(f"[+] JSON report    : {json_file}")

    # ── HTML report ──────────────────────────────────────────────────────────
    if fmt in ("html", "all"):
        from reporter import html_generator
        html_file = output_base + ".html"
        html_generator.generate_html(info, results, output_file=html_file)
        print(f"[+] HTML report    : {html_file}")

    # ── SARIF report ─────────────────────────────────────────────────────────
    if fmt in ("sarif", "all"):
        sarif_file = output_base + ".sarif"
        try:
            from reporter.sarif_generator import generate_sarif
            generate_sarif(info, results, output_file=sarif_file)
            print(f"[+] SARIF report   : {sarif_file}")
        except Exception as e:
            print(f"[!] SARIF generation failed: {e}", file=sys.stderr)

    # ── Post-scan: attack path summary ───────────────────────────────────────
    attack_paths = results.get("attack_paths", [])
    if attack_paths:
        print(f"\n[!] {len(attack_paths)} exploit chain(s) detected:")
        for path in attack_paths[:5]:   # show at most 5 in terminal
            sev   = path.get("severity", "?")
            name  = path.get("name", "Unknown chain")
            conf  = int(path.get("confidence", 0) * 100)
            ttp   = path.get("mitre_attack", "")
            ttp_s = f"  [{ttp}]" if ttp else ""
            sev_color = SEVERITY_COLORS_TERMINAL.get(sev, "") if use_color else ""
            print(f"    {sev_color}{sev}{reset}  {name}{ttp_s}  (confidence: {conf}%)")
        if len(attack_paths) > 5:
            print(f"    ... and {len(attack_paths) - 5} more (see full report)")

    # ── Post-scan: priority remediation tiers ────────────────────────────────
    priority_summary = results.get("priority_summary", {})
    phases = priority_summary.get("remediation_phases", {})
    p1_count = phases.get("phase1_immediate", 0)   # engine returns int counts
    top_priorities = priority_summary.get("top_priorities", [])
    if p1_count:
        print(f"\n[!] {p1_count} finding(s) require IMMEDIATE remediation (priority ≥ 80):")
        for f in top_priorities[:3]:
            print(f"    • {f.get('type', 'Unknown')}  (score: {f.get('priority_score', 0):.0f})")
        if p1_count > 3:
            print(f"    ... and {p1_count - 3} more")

    print("\n[+] Scan complete.")
    return 0 if summary["risk_level"] in ("LOW",) else 1


# Terminal colours used in main()
SEVERITY_COLORS_TERMINAL = {
    "CRITICAL": "\033[91m",
    "HIGH":     "[93m",
    "MEDIUM":   "[94m",
    "LOW":      "[92m",
}


if __name__ == "__main__":
    sys.exit(main())
