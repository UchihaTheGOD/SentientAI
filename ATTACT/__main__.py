"""ATTACT CLI — python -m ATTACT --help"""
from __future__ import annotations
import argparse, json, sys, pathlib
from .runner import CHECKS, run_assessment
from .report import render_terminal, write_json
from .scope import ScopeError

def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="python -m ATTACT", description="ATTACT — authorized web security assessment toolkit (read-only, low-rate, loopback by default).")
    p.add_argument("--target", default="", help="Target base URL, e.g. http://127.0.0.1:8000")
    p.add_argument("--confirm-authorized", action="store_true", help="Confirm you have authorization to test the target")
    p.add_argument("--allowlist", default="", help="Comma-separated hosts/IPs explicitly allowed beyond loopback (e.g. 127.0.0.1,localhost,10.0.0.5)")
    p.add_argument("--checks", default=",".join(CHECKS), help=f"Comma-separated checks to run. Available: {','.join(CHECKS)}")
    p.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout seconds (default 6)")
    p.add_argument("--max-requests", type=int, default=120, help="Global request limit (default 120)")
    p.add_argument("--json-out", default="", help="Path to write JSON report")
    p.add_argument("--list-checks", action="store_true", help="List available checks and exit")
    p.add_argument("--auth-user", default="", help="Test account username for auth checks (optional)")
    p.add_argument("--auth-pass", default="", help="Test account password for auth checks (optional)")
    p.add_argument("--access-user-a", default="", help="Access-control account A username")
    p.add_argument("--access-pass-a", default="", help="Access-control account A password")
    p.add_argument("--access-user-b", default="", help="Access-control account B username")
    p.add_argument("--access-pass-b", default="", help="Access-control account B password")
    p.add_argument("--rate-limit-path", default="/login", help="Endpoint for rate-limit probe (default /login)")
    p.add_argument("--rate-limit-count", type=int, default=6, help="Number of rate-limit probes (max 10, default 6)")
    return p

def main(argv=None) -> int:
    parser=build_parser()
    args=parser.parse_args(argv)
    if args.list_checks:
        for c in CHECKS: print(c)
        return 0
    # if no target, print help and exit 2
    if not args.target:
        parser.print_help()
        print("\nHint: start SentientAI locally (run.bat start) then run:\n  python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized\n", file=sys.stderr)
        return 2
    allow=[h.strip() for h in args.allowlist.split(",") if h.strip()] if args.allowlist else []
    checks=[c.strip() for c in args.checks.split(",") if c.strip()]
    try:
        report=run_assessment(target_url=args.target, allowlist=allow, confirm_authorized=args.confirm_authorized,
                              checks=checks, timeout=args.timeout, max_requests=args.max_requests,
                              auth_user=args.auth_user, auth_pass=args.auth_pass,
                              access_user_a=args.access_user_a, access_pass_a=args.access_pass_a,
                              access_user_b=args.access_user_b, access_pass_b=args.access_pass_b,
                              rate_limit_path=args.rate_limit_path, rate_limit_count=args.rate_limit_count)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr); return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr); return 1
    print(render_terminal(report))
    if args.json_out:
        p=write_json(report, args.json_out)
        print(f"\nJSON report written to {p}", file=sys.stderr)
    return 0

if __name__=="__main__": raise SystemExit(main())
