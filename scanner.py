#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════════
 Vuln Scanner  ·  Main CLI  ·  scanner.py
 ─────────────────────────────────────────────────────────────────
 Usage examples:
   python scanner.py --target 192.168.1.1
   python scanner.py --target https://example.com --full
   python scanner.py --target scanme.nmap.org --ports 1-1024 --threads 100
   python scanner.py --target http://testphp.vulnweb.com --web-only
══════════════════════════════════════════════════════════════════
"""

import argparse
import os
import sys
import time
import webbrowser
from urllib.parse import urlparse

# ── Ensure modules are importable ────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.port_scanner import run_port_scan
from modules.web_auditor  import run_web_audit
from modules.reporter     import generate_report

# ── Paths ─────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(BASE_DIR, "wordlists", "common_dirs.txt")
REPORT_PATH   = os.path.join(BASE_DIR, "security_audit_report.html")

# ── Banner ─────────────────────────────────────────────────────────────
BANNER = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗                  ║
  ║    ██║   ██║██║   ██║██║     ████╗  ██║                  ║
  ║    ██║   ██║██║   ██║██║     ██╔██╗ ██║                  ║
  ║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║                  ║
  ║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║                  ║
  ║      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝  SCANNER v1.0   ║
  ║                                                           ║
  ║    Network & Web Vulnerability Auditor                    ║
  ║    For authorised security testing only.                  ║
  ╚═══════════════════════════════════════════════════════════╝
"""


def print_banner():
    try:
        print("\033[36m" + BANNER + "\033[0m")
    except Exception:
        print(BANNER)


# ── Argument Parser ───────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Network & Web Vulnerability Auditor — generates a cyberpunk HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --target 192.168.1.1
  python scanner.py --target https://example.com --full
  python scanner.py --target scanme.nmap.org --ports 1-1024 --threads 100
  python scanner.py --target http://testphp.vulnweb.com --web-only
  python scanner.py --target 10.0.0.1 --ports common --no-report
        """,
    )

    p.add_argument(
        "--target", "-t",
        required=True,
        metavar="HOST/URL",
        help="Target hostname, IP address, or URL.",
    )
    p.add_argument(
        "--ports", "-p",
        default="common",
        metavar="SPEC",
        help="Port spec: 'common' (default), '1-1024', '22,80,443', etc.",
    )
    p.add_argument(
        "--threads",
        type=int,
        default=80,
        metavar="N",
        help="Thread pool size for port scanning (default: 80).",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        metavar="SECS",
        help="Per-port TCP timeout in seconds (default: 0.8).",
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Run both port scan AND full web audit.",
    )
    p.add_argument(
        "--web-only",
        action="store_true",
        dest="web_only",
        help="Skip port scan — run web audit only.",
    )
    p.add_argument(
        "--wordlist", "-w",
        default=WORDLIST_PATH,
        metavar="PATH",
        help=f"Path to directory fuzzing wordlist (default: {WORDLIST_PATH}).",
    )
    p.add_argument(
        "--output", "-o",
        default=REPORT_PATH,
        metavar="FILE",
        help=f"Output HTML report path (default: {REPORT_PATH}).",
    )
    p.add_argument(
        "--no-report",
        action="store_true",
        dest="no_report",
        help="Don't write an HTML report — print summary only.",
    )
    p.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the report in the browser when done.",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress verbose output.",
    )

    return p


# ── Target Analysis ───────────────────────────────────────────────────

def extract_host(target: str) -> str:
    """Pull the bare hostname/IP from a URL or return as-is."""
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or target
    return target


def looks_like_url(target: str) -> bool:
    """True only for explicit http/https URLs, not bare IPs/hostnames."""
    return target.startswith(("http://", "https://"))


# ── Main ──────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser  = build_parser()
    args    = parser.parse_args()
    verbose = not args.quiet
    target  = args.target.strip()

    # Determine scan mode
    # --full           → port scan + web audit
    # --web-only       → web audit only (no ports)
    # bare IP/hostname → port scan only
    # http/https URL   → web audit only (same as --web-only)
    run_ports = not args.web_only
    run_web   = args.full or args.web_only or looks_like_url(target)

    mode_label = "FULL" if args.full else ("WEB ONLY" if args.web_only else "PORT SCAN")
    print(f"  Target   : {target}")
    print(f"  Mode     : {mode_label}")
    print(f"  Ports    : {args.ports}")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s per port")
    print()

    port_result = None
    web_result  = None
    t_start     = time.time()

    # ── Port Scan ─────────────────────────────────────────────────────
    if run_ports:
        host = extract_host(target)
        print(f"  [*] Starting port scan on {host} …")
        port_result = run_port_scan(
            host      = host,
            port_spec = args.ports,
            threads   = args.threads,
            timeout   = args.timeout,
            verbose   = verbose,
        )
        if port_result.error:
            print(f"\n  [ERROR] Port scan failed: {port_result.error}")
            print(f"  [HINT]  Check that the host is reachable: ping {host}")

    # ── Web Audit ─────────────────────────────────────────────────────
    if run_web:
        # Always ensure a proper scheme
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        print(f"\n  [*] Starting web audit on {url} …")
        print(f"  [*] Checking connectivity …")

        # Quick connectivity probe before running the full audit
        import socket as _sock
        from urllib.parse import urlparse as _up
        _parsed = _up(url)
        _host   = _parsed.hostname or target
        _port   = _parsed.port or (443 if url.startswith("https") else 80)
        try:
            with _sock.create_connection((_host, _port), timeout=5):
                pass
            print(f"  [✓] Connected to {_host}:{_port}")
        except Exception as _e:
            print(f"\n  [✗] Cannot reach {_host}:{_port} — {_e}")
            print(f"  [!] Web audit skipped. Is the target online?")
            run_web = False

    if run_web:
        web_result = run_web_audit(
            target_url    = url,
            wordlist_path = args.wordlist,
            verbose       = verbose,
        )
        if web_result.error:
            print(f"\n  [ERROR] Web audit: {web_result.error}")

    elapsed = time.time() - t_start

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n  {'─'*54}")
    print(f"  SCAN COMPLETE  ({elapsed:.1f}s)")
    print(f"  {'─'*54}")
    if port_result and not port_result.error:
        print(f"  Open Ports     : {len(port_result.open_ports)}")
        print(f"  OS Estimate    : {port_result.os_guess}  (TTL {port_result.ttl})")
    if web_result:
        print(f"  Missing Headers: {len(web_result.missing_headers)}")
        print(f"  Fuzz Hits      : {len(web_result.fuzz_hits)}")
        print(f"  SQLi Points    : {len(web_result.sqli_results)}")
    print(f"  {'─'*54}\n")

    # ── Report ────────────────────────────────────────────────────────
    if not args.no_report and (port_result or web_result):
        report_path = generate_report(port_result, web_result, output_path=args.output)
        if args.open:
            webbrowser.open(f"file:///{report_path.replace(os.sep, '/')}")
    elif not port_result and not web_result:
        print("  [!] Nothing to report — no scan results collected.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [STOPPED] Scan interrupted by user. Partial results discarded.\n")
        sys.exit(0)
