#!/usr/bin/env python3
"""
SimpleAuth OIDF Conformance Suite Automation
=============================================
Automates running failing/non-passing tests in the OIDF Conformance Suite.

Usage:
  python3 run_conformance.py [--plan PLAN_ID] [--token TOKEN] [--mode MODE]

Modes:
  status   - Show current status of all tests (default)
  rerun    - Re-run all non-passing tests (creates new instances)
  watch    - Watch a test instance for completion
  open     - Open test URLs in browser for interaction

Examples:
  python3 run_conformance.py --mode status
  python3 run_conformance.py --mode rerun --dry-run
  python3 run_conformance.py --mode rerun
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import webbrowser
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

CONFORMANCE_BASE = "https://www.certification.openid.net"
DEFAULT_TOKEN = os.environ.get("OIDF_TOKEN", "")

PLANS = {
    "basic":    "NQvjPGZPSMZBv",
    "formpost": "GPcTWMXiiUb6K",
    "config":   "fdx6Lji5floOI",
}

# Tests that need manual browser interaction (not auto-advanceable)
REQUIRES_INTERACTION = {
    "oidcc-prompt-none-not-logged-in",  # needs manual logout first
    "oidcc-prompt-login",               # needs login interaction
    "oidcc-max-age-1",                  # needs fresh login
}

# Tests that must NOT overlap with others (sleep window)
SEQUENTIAL_ONLY = {
    "oidcc-codereuse-30seconds",        # pauses 30s — alias conflict if concurrent
}

# Terminal statuses (no need to re-poll)
TERMINAL = {"FINISHED", "INTERRUPTED"}

# Passing result codes (SKIPPED = server doesn't support the feature, which is correct)
PASSING = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}

# Result color codes for terminal output
COLORS = {
    "PASSED":      "\033[92m",  # green
    "WARNING":     "\033[93m",  # yellow
    "REVIEW":      "\033[96m",  # cyan
    "FAILED":      "\033[91m",  # red
    "INTERRUPTED":  "\033[91m", # red
    "SKIPPED":     "\033[90m",  # grey
    "WAITING":     "\033[94m",  # blue
    "RUNNING":     "\033[94m",  # blue
    "CREATED":     "\033[94m",  # blue
    None:          "\033[90m",  # grey (no instance)
}
RESET = "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def api(token: str, method: str, path: str, params: dict = None) -> dict:
    """Make an OIDF API call."""
    url = f"{CONFORMANCE_BASE}{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)

    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            return {"error": body, "status": e.code}


def get_plan(token: str, plan_id: str) -> dict:
    return api(token, "GET", f"/api/plan/{plan_id}")


def get_instance_info(token: str, instance_id: str) -> dict:
    return api(token, "GET", f"/api/info/{instance_id}")


def create_test_instance(token: str, plan_id: str, test_name: str) -> dict:
    """Create a new test instance under a plan."""
    return api(token, "POST", "/api/runner", params={"test": test_name, "plan": plan_id})


# ─────────────────────────────────────────────────────────────────────────────
# Plan analysis
# ─────────────────────────────────────────────────────────────────────────────

def get_latest_instance_id(module: dict) -> Optional[str]:
    """Return the most recent instance ID for a module (last in list = newest)."""
    instances = module.get("instances", [])
    if not instances:
        return None
    return instances[-1]  # API returns oldest-first


def instance_result(info: Optional[dict]) -> Optional[str]:
    """Get the overall result of a test instance info dict."""
    if info is None:
        return None
    return info.get("result")  # PASSED, WARNING, REVIEW, FAILED, etc.


def instance_status(info: Optional[dict]) -> Optional[str]:
    """Get the run status (FINISHED, RUNNING, WAITING, etc.)."""
    if info is None:
        return None
    return info.get("status")


def needs_rerun(info: Optional[dict]) -> bool:
    """Return True if this instance should be re-run."""
    if info is None:
        return True
    result = instance_result(info)
    status = instance_status(info)
    # Re-run if: not passing and test is done (terminal state)
    # Also rerun INTERRUPTED tests regardless of result
    if status == "INTERRUPTED":
        return True
    return result not in PASSING and status in TERMINAL


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def color(text: str, key: str) -> str:
    c = COLORS.get(key, COLORS[None])
    return f"{c}{text}{RESET}"


def print_status_table(token: str, modules: list):
    """Print a formatted status table for all modules in a plan."""
    print(f"\n{'TEST MODULE':<55} {'STATUS':<12} {'RESULT':<12} {'INSTANCE'}")
    print("─" * 110)

    counts = {}
    for module in modules:
        name = module.get("testModule", "?")
        inst_id = get_latest_instance_id(module)
        if inst_id:
            info = get_instance_info(token, inst_id)
            result = instance_result(info) or "—"
            status = instance_status(info) or "—"
        else:
            info = None
            result = "—"
            status = "—"
            inst_id = "—"

        result_color = COLORS.get(result, COLORS[None])
        print(f"{name:<55} {status:<12} {result_color}{result:<12}{RESET} {inst_id}")

        counts[result] = counts.get(result, 0) + 1

    print("─" * 110)
    summary = "  ".join(f"{color(str(v), k)} {k}" for k, v in sorted(counts.items()))
    print(f"\nSummary: {summary}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Rerun logic
# ─────────────────────────────────────────────────────────────────────────────

def rerun_plan(token: str, plan_id: str, dry_run: bool = False, sequential_only: bool = False):
    """Re-run all non-passing tests in a plan."""
    plan = get_plan(token, plan_id)
    modules = plan.get("modules", [])

    to_rerun = []
    skipped_needs_interaction = []
    already_passing = []

    for module in modules:
        name = module.get("testModule", "?")
        inst_id = get_latest_instance_id(module)
        info = get_instance_info(token, inst_id) if inst_id else None

        if name in REQUIRES_INTERACTION:
            skipped_needs_interaction.append(name)
            continue

        if not needs_rerun(info):
            already_passing.append(name)
            continue

        to_rerun.append((name, module))

    print(f"\n{'DRY RUN — ' if dry_run else ''}Plan: {plan_id}")
    print(f"  Already passing:         {len(already_passing)}")
    print(f"  Need re-run:             {len(to_rerun)}")
    print(f"  Skipped (need browser):  {len(skipped_needs_interaction)}")

    if skipped_needs_interaction:
        print(f"\n⚠️  Tests needing manual browser interaction (run separately):")
        for n in skipped_needs_interaction:
            print(f"   {n}")

    if not to_rerun:
        print("\n✅ All tests are passing — nothing to re-run!")
        return

    print(f"\n{'Would re-run' if dry_run else 'Re-running'} {len(to_rerun)} tests:")
    new_instances = []

    # Sequential-only tests go last
    regular = [(n, m) for n, m in to_rerun if n not in SEQUENTIAL_ONLY]
    sequential = [(n, m) for n, m in to_rerun if n in SEQUENTIAL_ONLY]

    for name, module in regular + sequential:
        is_sequential = name in SEQUENTIAL_ONLY
        marker = " [sequential]" if is_sequential else ""
        print(f"  → {name}{marker}", end="", flush=True)

        if dry_run:
            print("  (dry run)")
            continue

        result = create_test_instance(token, plan_id, name)

        if "error" in result:
            print(f"  ❌ ERROR: {result['error']}")
        else:
            inst_id = result.get("id", "?")
            url = result.get("url", "?")
            print(f"  ✓ {inst_id}")
            new_instances.append({
                "name": name,
                "id": inst_id,
                "url": url,
                "sequential": is_sequential,
            })

        if is_sequential:
            # Give the sequential test a moment before we start the next
            time.sleep(1)

    if new_instances:
        print(f"\n{'='*70}")
        print(f"Created {len(new_instances)} new test instances.")
        print(f"\nOpen each URL in your browser to complete the test flow:")
        print(f"  (Tests that 'pause for 30 seconds' must NOT be interrupted)")
        print()
        for inst in new_instances:
            marker = " ⏱  [wait 30s — do not run other tests concurrently]" if inst["sequential"] else ""
            print(f"  {inst['name']}")
            print(f"    {CONFORMANCE_BASE}/test-plan/{plan_id}/module/{inst['name']}")
            print(f"    Instance: {inst['id']}{marker}")
        print()

    return new_instances


# ─────────────────────────────────────────────────────────────────────────────
# Watch mode
# ─────────────────────────────────────────────────────────────────────────────

def watch_instance(token: str, instance_id: str, timeout: int = 120):
    """Poll a test instance until it finishes or times out."""
    print(f"Watching instance {instance_id}...")
    start = time.time()
    last_status = None

    while time.time() - start < timeout:
        info = get_instance_info(token, instance_id)
        status = info.get("status", "?")
        result = info.get("result", "")

        if status != last_status:
            ts = datetime.now().strftime("%H:%M:%S")
            result_str = f" → {color(result, result)}" if result else ""
            print(f"  [{ts}] {status}{result_str}")
            last_status = status

        if status in TERMINAL:
            print(f"\n✅ Done: {color(result or status, result or status)}")
            return info

        time.sleep(3)

    print(f"\n⏰ Timeout after {timeout}s. Last status: {last_status}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SimpleAuth OIDF Conformance Automation")
    parser.add_argument("--plan", default="basic",
                        help="Plan alias (basic/formpost/config) or full plan ID")
    parser.add_argument("--token", default=DEFAULT_TOKEN,
                        help="OIDF API bearer token (or set OIDF_TOKEN env var)")
    parser.add_argument("--mode", default="status",
                        choices=["status", "rerun", "watch"],
                        help="Operation mode")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without creating instances")
    parser.add_argument("--instance", help="Instance ID for watch mode")
    args = parser.parse_args()

    token = args.token
    if not token:
        print("❌ No API token. Set OIDF_TOKEN env var or use --token.")
        sys.exit(1)

    plan_id = PLANS.get(args.plan, args.plan)

    if args.mode == "status":
        print(f"Fetching plan {plan_id}...")
        plan = get_plan(token, plan_id)
        modules = plan.get("modules", [])
        if not modules:
            print(json.dumps(plan, indent=2))
            sys.exit(1)
        print(f"\nPlan: {plan.get('planName', plan_id)}  ({len(modules)} tests)")
        print_status_table(token, modules)

    elif args.mode == "rerun":
        rerun_plan(token, plan_id, dry_run=args.dry_run)

    elif args.mode == "watch":
        if not args.instance:
            print("❌ --instance INSTANCE_ID required for watch mode")
            sys.exit(1)
        watch_instance(token, args.instance)


if __name__ == "__main__":
    main()
