"""CLI entry-point for the DreadGOAD benchmark runner.

Subcommands:
  ``run``    — execute a grid against a fresh provisioned lab.
  ``report`` — re-emit the human-readable summaries from an existing
               results directory (offline; no AWS calls).

Exit codes:
  0   — every scenario completed (status == "completed")
  1   — at least one scenario failed or timed out
  2   — runner-level error (lab provision failed, langgraph
        unreachable, ...)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from benchmark.dreadgoad.config import load_config
from benchmark.dreadgoad.reporter import write_report
from benchmark.dreadgoad.runner import run_grid


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="benchmark.dreadgoad",
        description="DreadGOAD AD lab benchmark runner for LangGraph agents",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Execute a grid")
    run.add_argument("--config", required=True, help="Path to grid YAML")
    run.add_argument(
        "--results-dir",
        default="benchmark/dreadgoad/results/",
        help="Output directory (default: benchmark/dreadgoad/results/)",
    )
    run.add_argument(
        "--agents",
        nargs="+",
        help="Override config.agents (subset of LangGraph assistant ids)",
    )
    run.add_argument("--rounds", type=int, help="Override config.rounds")

    report = sub.add_parser(
        "report",
        help="Re-emit the human-readable summaries from an existing results directory",
    )
    report.add_argument("--results-dir", required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args(argv)

    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "report":
        return _cmd_report(args)
    return 2


def _cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.agents:
        cfg = _override(cfg, agents=tuple(args.agents))
    if args.rounds:
        cfg = _override(cfg, rounds=args.rounds)

    results_dir = Path(args.results_dir)
    try:
        results = asyncio.run(run_grid(cfg, results_dir=results_dir))
    except Exception as exc:  # noqa: BLE001
        logging.error("runner error: %s", exc)
        return 2

    if not results:
        logging.error("no scenarios were executed")
        return 2

    write_report(results_dir=results_dir, results=results)
    all_completed = all(r.status == "completed" for r in results)
    return 0 if all_completed else 1


def _cmd_report(args: argparse.Namespace) -> int:
    # Re-emits the per-agent grid summaries from existing run dirs without
    # touching AWS. Useful after pulling a results tree off a cloud
    # runner. The per-run scorecards + metadata are already on disk; this
    # only refreshes the aggregate ``grid-summary.md`` files.
    from benchmark.dreadgoad.reporter import refresh_grid_summaries

    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        logging.error("results dir not found: %s", results_dir)
        return 2
    refresh_grid_summaries(results_dir)
    return 0


def _override(cfg, **overrides):
    """Return a copy of ``cfg`` (frozen dataclass) with selected fields replaced."""
    from dataclasses import replace

    return replace(cfg, **overrides)


if __name__ == "__main__":
    sys.exit(main())
