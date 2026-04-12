#!/usr/bin/env python3
"""
main.py — Linux Privilege Escalation Automation Toolkit

Entry point and orchestrator. Runs all scanner modules in sequence,
passes findings to the analysis engine, and generates the final report.

Usage:
    python3 main.py [options]

Options:
    -o, --output <file>         Write report to file (default: stdout only)
    -f, --format [text|json|html|all]  Output format (default: html)
    -v, --verbose               Print progress messages while scanning
    --no-color                  Disable ANSI colour codes in terminal output
    --quick                     Quick mode: skip slow filesystem scans
                                (skips full suid/permission sweeps)
    --skip <modules>            Comma-separated list of modules to skip
                                Choices: suid, perms, services, cron, kernel,
                                         caps, creds, path
    -h, --help                  Show this help message

Examples:
    python3 main.py
    python3 main.py -o report.txt -f all -v
    python3 main.py -f json -o findings.json
    python3 main.py --skip kernel,caps -v
    python3 main.py --quick -f html -o report.html
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


def check_platform():
    """Warn if running on a non-Linux platform."""
    import platform
    if platform.system() != "Linux":
        print(
            "\n[WARNING] This toolkit is designed for Linux systems.\n"
            f"  Detected platform: {platform.system()}\n"
            "  Many checks rely on Linux-specific paths and commands.\n"
            "  Run this script on a Linux system for accurate results.\n"
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

  {BOLD}Linux Privilege Escalation Automation Toolkit{RESET}
  {CYAN}Detection-only | For authorised security testing & education{RESET}
{RED}{'═'*70}{RESET}
"""
    print(banner)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Linux Privilege Escalation Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
    python3 main.py
    python3 main.py -o report.txt -f all -v
    python3 main.py -f json -o findings.json
    python3 main.py --skip kernel,caps -v
    python3 main.py --quick -f html -o report.html""",
    )
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write report to FILE (base name; extensions added per format)")
    parser.add_argument("-f", "--format", choices=["text", "json", "html", "all"],
                        default="html", help="Output format (default: html)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress while scanning")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour codes")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: skip slow filesystem scans (suid full sweep, world-writable search)")
    parser.add_argument("--skip", metavar="MODULES",
                        help="Comma-separated modules to skip: suid,perms,services,cron,kernel,caps,creds,path")
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


def main():
    args = parse_args()
    use_color = not args.no_color and sys.stdout.isatty()

    print_banner(use_color=use_color)
    check_platform()
    ensure_output_dir()

    # Parse skipped modules
    skip = set()
    if args.skip:
        skip = {s.strip().lower() for s in args.skip.split(",")}

    quick = args.quick
    if quick:
        print("[i] Quick mode enabled — skipping slow filesystem sweeps.\n")

    # ── Step 1: System Information ───────────────────────────────────────────
    print("[STEP 1/8] Collecting system information...")
    from modules import system_info
    info = system_info.collect()
    print(f"  Host   : {info.get('hostname')}")
    print(f"  User   : {info.get('current_user')}  ({'ROOT ⚠' if info.get('is_root') else 'non-root'})")
    print(f"  Kernel : {info.get('kernel_release')}")
    print(f"  OS     : {info.get('os_name')}")
    if info.get("is_root"):
        print(f"\n  ⚠  Running as ROOT — all filesystem checks will have full access.\n")

    all_findings = []

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

    # ── Step 3: Analysis ─────────────────────────────────────────────────────
    print("\n[STEP 3/8] Running analysis engine...")
    from analysis import engine
    results = engine.analyse(all_findings)
    summary = results["summary"]

    risk_color = SEVERITY_COLORS_TERMINAL.get(summary["risk_level"], "") if use_color else ""
    reset = "\033[0m" if use_color else ""

    print(f"  Overall Risk: {risk_color}{summary['risk_level']}{reset}  (score: {summary['risk_score']})")
    print(f"  Critical: {summary['critical']}  High: {summary['high']}  "
          f"Medium: {summary['medium']}  Low: {summary['low']}  Total: {summary['total']}")

    # ── Step 4: Report Generation ─────────────────────────────────────────────
    print("\n[STEP 4/8] Generating report...")
    from reporter import generator
    import datetime as _dt

    fmt = args.format

    # Build timestamped base name inside output/ when -o is not specified
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = info.get("hostname", "host").replace(" ", "_")
    default_base = os.path.join(OUTPUT_DIR, f"privesc_{hostname}_{ts}")

    # Resolve the output base path
    if args.output:
        # If user gave a bare filename with no directory, put it in output/
        if os.path.dirname(args.output):
            output_base = args.output          # user supplied full path
        else:
            output_base = os.path.join(OUTPUT_DIR, args.output)
    else:
        output_base = default_base

    # ── Text report ──
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
        print(f"\n[+] Text report  : {text_file}")

    # ── JSON report ──
    if fmt in ("json", "all"):
        json_file = output_base + ".json"
        generator.generate_json(info, results, output_file=json_file)
        print(f"[+] JSON report  : {json_file}")

    # ── HTML report ──
    if fmt in ("html", "all"):
        from reporter import html_generator
        html_file = output_base + ".html"
        html_generator.generate_html(info, results, output_file=html_file)
        print(f"[+] HTML report  : {html_file}")

    print("\n[+] Scan complete.")
    return 0 if summary["risk_level"] in ("LOW",) else 1


# Terminal colours used in main() — imported from engine if available
SEVERITY_COLORS_TERMINAL = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
}


if __name__ == "__main__":
    sys.exit(main())
