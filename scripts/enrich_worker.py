#!/usr/bin/env python3
"""
Headless enrichment worker (no Streamlit UI).

  python scripts/enrich_worker.py --input logs.txt --output output/csv/out.csv
  python scripts/enrich_worker.py --input logs.txt --air-gapped

For multi-user high volume, run several workers behind a queue (RQ/Celery);
Streamlit remains the UI only.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    p = argparse.ArgumentParser(description="Headless IP enrichment worker")
    p.add_argument("--input", required=True, help="Input log file path")
    p.add_argument("--output", default=str(ROOT / "output" / "csv" / "worker_out.csv"))
    p.add_argument("--alvo", default="worker")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--period", type=int, default=0)
    p.add_argument("--cache", default="ip_cache.json")
    p.add_argument("--api-key", default=os.getenv("IPAPI_KEY") or None)
    p.add_argument("--air-gapped", action="store_true", help="Cache-only, no external HTTP")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--no-incremental", action="store_true")
    args = p.parse_args()

    if args.air_gapped:
        os.environ["AIR_GAPPED"] = "1"

    from file_handler import processar_log_acesso_async
    from helpers.shared import run_async

    cache_file = None if args.no_cache else args.cache
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    def _log(msg: str) -> None:
        print(msg, flush=True)

    result = run_async(
        processar_log_acesso_async(
            str(input_path),
            str(out),
            is_file=True,
            batch_size=args.batch_size,
            period=args.period,
            cache_file=cache_file,
            incremental=not args.no_incremental,
            update_callback=_log,
            progress_callback=lambda cur, tot, *a: _log(f"progress {cur}/{tot}"),
            alvo=args.alvo,
            api_key=None if args.air_gapped else args.api_key,
        )
    )
    n = 0 if result is None else len(result)
    print(f"Done: {n} records -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
