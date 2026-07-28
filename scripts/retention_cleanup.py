#!/usr/bin/env python3
"""Run retention policies from CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from helpers.retention import run_retention  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Log Enrichment retention cleanup")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--audit-days", type=int, default=None)
    p.add_argument("--audit-lines", type=int, default=None)
    p.add_argument("--sessions-days", type=int, default=None)
    p.add_argument("--cache-days", type=int, default=None)
    args = p.parse_args()
    summary = run_retention(
        audit_max_age_days=args.audit_days,
        audit_max_lines=args.audit_lines,
        sessions_max_age_days=args.sessions_days,
        cache_max_age_days=args.cache_days,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
