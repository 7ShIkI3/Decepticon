"""Benchmark output layout.

Output layout::

  <results_dir>/<agent_id>/<UTC-ts>/
    metadata.json         run-level evidence: LangSmith trace_id / thread_id,
                          timing, cost breakdown, lab provisioning info
    scorecard.md          human-readable single-run summary
    measurement.json      raw measurement-callback record copied from sandbox
    opplan.json           agent's final OPPLAN (from workspace/plan/)
    timeline.jsonl        engagement event log (from workspace/timeline.jsonl)
    findings/             FIND-*.md per-finding evidence (from workspace/findings/)
    workspace.tar.gz      full /workspace/<engagement>/ archive

  <results_dir>/<agent_id>/grid-summary.md   accumulated across all
                                             timestamped runs of this agent

Design rationale:

- ``agent_id`` (== LangGraph ``assistant_id``) is the top-level grouping
  so a re-run of the same agent does not overwrite past evidence;
  timestamp is the second level for chronological ordering.
- LangSmith ``trace_id`` is the primary evidence — the full trace lives
  in LangSmith UI, only the navigable ID is persisted to metadata.json.
- The workspace tarball preserves the agent's filesystem-of-record so
  any later post-mortem about a specific finding / artifact remains
  reproducible after the sandbox container is gone.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from benchmark.dreadgoad.harness import (
    _LITELLM_URL,
    _SANDBOX_CONTAINER,
    pull_measurement_bytes,
)
from benchmark.dreadgoad.schemas import RunResult

log = logging.getLogger(__name__)

# DreadGOAD ``goad-full-5host`` lab inventory — what the agent actually
# sees inside ``10.8.1.0/24``. Captured here (rather than read from the
# running cloud resource group at report time) so the persisted
# metadata.json is self-contained and a later reader does not need
# cloud credentials to identify a host. Add a sibling entry under this
# dict for any new lab profile a config references — and that
# ``lab_profile`` flows through ``BenchmarkConfig`` unchanged.
_LAB_INVENTORY = {
    "GOAD": {
        "subnet": "10.8.1.0/24",
        "domains": [
            "sevenkingdoms.local",
            "north.sevenkingdoms.local",
            "essos.local",
        ],
        "dcs": [
            {"name": "DC01 (KINGSLANDING)", "ip": "10.8.1.7", "domain": "sevenkingdoms.local"},
            {"name": "DC02 (WINTERFELL)", "ip": "10.8.1.6", "domain": "north.sevenkingdoms.local"},
            {"name": "DC03 (MEEREEN)", "ip": "10.8.1.5", "domain": "essos.local"},
        ],
        "members": [
            {"name": "SRV02 (CASTELBLACK)", "ip": "10.8.1.8", "role": "IIS web server"},
            {"name": "SRV03 (BRAAVOS)", "ip": "10.8.1.4", "role": "MSSQL server"},
        ],
    },
}


def write_report(
    *,
    results_dir: Path,
    results: list[RunResult],
) -> Path:
    """Emit one timestamped run dir per scenario + per-agent grid summary.

    Returns the ``results_dir`` (the per-agent subdirs are addressable
    from there).
    """
    results_dir = Path(results_dir)

    for run in results:
        run_dir = results_dir / run.scenario.agent_id / _ts_slug(run.started_at)
        run_dir.mkdir(parents=True, exist_ok=True)
        _emit_run_dir(run_dir, run)

    # Per-agent grid summary aggregates every timestamped run dir under
    # ``results/<agent_id>/``. Re-rendered every time so re-runs of the
    # same agent pick up the previous evidence too.
    for agent_id in sorted({r.scenario.agent_id for r in results}):
        agent_dir = results_dir / agent_id
        _emit_grid_summary(agent_dir, agent_id)

    return results_dir


def refresh_grid_summaries(results_dir: Path) -> None:
    """Re-emit ``grid-summary.md`` for every per-agent subdir.

    Used by the ``benchmark report`` subcommand to refresh aggregates
    from an existing results tree without re-running anything.
    """
    results_dir = Path(results_dir)
    for agent_dir in sorted(results_dir.iterdir()):
        if not agent_dir.is_dir():
            continue
        _emit_grid_summary(agent_dir, agent_dir.name)


def _ts_slug(iso_ts: str) -> str:
    """Convert ``2026-05-31T10:34:37.000+00:00`` → ``2026-05-31T10-34Z``."""
    if not iso_ts:
        from datetime import datetime, timezone

        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%MZ")
    base = iso_ts.split(".", 1)[0]
    return base.replace(":", "-")[:16] + "Z"


def _emit_run_dir(run_dir: Path, run: RunResult) -> None:
    """Populate one run's evidence directory."""
    metadata = _build_metadata(run)
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True, default=str)
    )
    (run_dir / "scorecard.md").write_text(_format_run_scorecard(run, metadata))

    # Measurement + workspace artifacts require a real ``run_id`` —
    # ``pull_measurement_bytes`` would no-op anyway, and an empty
    # ``run_id`` would collapse the sandbox-side tar paths.
    if not run.run_id:
        return

    raw_measurement = pull_measurement_bytes(run.scenario.name, run.run_id)
    if raw_measurement:
        (run_dir / "measurement.json").write_bytes(raw_measurement)
    else:
        log.debug("no measurement record for %s/%s", run.scenario.agent_id, run.run_id)

    _copy_workspace_artifacts(run_dir, run.scenario.name)


def _build_metadata(run: RunResult) -> dict:
    return {
        "agent_id": run.scenario.agent_id,
        "scenario_name": run.scenario.name,
        "engagement_id": run.scenario.name,
        "round_index": run.scenario.round_index,
        "rounds_in_grid": run.scenario.rounds_in_grid,
        "langsmith": {
            "project": run.langsmith_project,
            "trace_id": run.run_id,
            "thread_id": run.thread_id,
            "assistant_id": run.assistant_id,
            "url": run.trace_url,
        },
        "timing": {
            "started_at": run.started_at,
            "ended_at": run.ended_at,
            "duration_sec": run.duration_sec,
        },
        "lab": {
            "provider": "dreadgoad",
            "lab_profile": run.scenario.lab_profile,
            "variant_id": run.provision.variant_id,
            "dc_url": run.provision.dc_url,
            "domain": run.provision.domain,
            "provisioned_at": run.provision.provisioned_at,
            "inventory": _LAB_INVENTORY.get(run.scenario.lab_profile, {}),
        },
        "outcome": {
            "status": run.status,
            "tool_calls_count": len(run.tool_calls),
            "hosts_compromised_count": len(run.hosts_compromised),
            "error_message": run.error_message,
        },
        "cost": {
            "method": run.cost_method,
            "total_usd": run.cost_total_usd,
            "by_model": run.cost_by_model,
        },
        "litellm_proxy": _LITELLM_URL,
    }


def _copy_workspace_artifacts(run_dir: Path, scenario_name: str) -> None:
    """Pull opplan.json + timeline.jsonl + findings/ + full tarball from sandbox."""
    _docker_cp(
        f"/workspace/{scenario_name}/plan/opplan.json",
        run_dir / "opplan.json",
    )
    _docker_cp(
        f"/workspace/{scenario_name}/timeline.jsonl",
        run_dir / "timeline.jsonl",
    )
    findings_dst = run_dir / "findings"
    findings_dst.mkdir(exist_ok=True)
    _docker_cp_dir(
        f"/workspace/{scenario_name}/findings/.",
        findings_dst,
    )
    _make_workspace_tarball(scenario_name, run_dir / "workspace.tar.gz")


def _docker_cp(remote_path: str, local_path: Path) -> bool:
    """``docker cp`` a single file from the sandbox container. Best-effort."""
    try:
        result = subprocess.run(
            ["docker", "cp", f"{_SANDBOX_CONTAINER}:{remote_path}", str(local_path)],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("_docker_cp(%s): %s", remote_path, exc)
        return False
    if result.returncode != 0:
        log.debug("_docker_cp(%s) rc=%d: %s", remote_path, result.returncode, result.stderr[:200])
        return False
    return True


def _docker_cp_dir(remote_path: str, local_dir: Path) -> bool:
    """Copy directory contents using ``docker cp`` (recursive by default)."""
    try:
        result = subprocess.run(
            ["docker", "cp", f"{_SANDBOX_CONTAINER}:{remote_path}", str(local_dir)],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("_docker_cp_dir(%s): %s", remote_path, exc)
        return False
    if result.returncode != 0:
        log.debug(
            "_docker_cp_dir(%s) rc=%d: %s", remote_path, result.returncode, result.stderr[:200]
        )
        return False
    return True


def _make_workspace_tarball(scenario_name: str, dst: Path) -> bool:
    """``tar -czf`` the sandbox-side engagement workspace, then docker cp to dst."""
    sandbox_tar = f"/tmp/{scenario_name}.tar.gz"  # noqa: S108 — sandbox tmp, removed at end
    try:
        mk = subprocess.run(
            [
                "docker",
                "exec",
                _SANDBOX_CONTAINER,
                "bash",
                "-c",
                f"cd /workspace && tar czf {sandbox_tar} {scenario_name}/",
            ],
            capture_output=True,
            timeout=120,
            check=False,
        )
        if mk.returncode != 0:
            log.warning("workspace tarball create rc=%d: %s", mk.returncode, mk.stderr[:200])
            return False
        cp = subprocess.run(
            ["docker", "cp", f"{_SANDBOX_CONTAINER}:{sandbox_tar}", str(dst)],
            capture_output=True,
            timeout=120,
            check=False,
        )
        if cp.returncode != 0:
            log.warning("workspace tarball copy rc=%d: %s", cp.returncode, cp.stderr[:200])
            return False
        subprocess.run(
            ["docker", "exec", _SANDBOX_CONTAINER, "rm", "-f", sandbox_tar],
            capture_output=True,
            timeout=30,
            check=False,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("_make_workspace_tarball(%s): %s", scenario_name, exc)
        return False


def _format_run_scorecard(run: RunResult, metadata: dict) -> str:
    """Per-run human-readable summary written to scorecard.md."""
    ls = metadata["langsmith"]
    out = metadata["outcome"]
    cost = metadata["cost"]
    lines = [
        f"# {run.scenario.agent_id} — {run.scenario.name}",
        "",
        f"**Status**: {run.status}  ",
        f"**Duration**: {run.duration_sec:.0f} sec  ",
        f"**Started**: {run.started_at}  ",
        f"**Ended**: {run.ended_at}",
        "",
        "## LangSmith trace",
        "",
        f"- Project: `{ls['project']}`",
        f"- Trace ID: `{ls['trace_id']}`",
        f"- Thread ID: `{ls['thread_id']}`",
        f"- Assistant: `{ls['assistant_id']}`",
        f"- URL: {ls['url']}" if ls["url"] else "- URL: (unavailable)",
        "",
        "## Activity",
        "",
        f"- Tool calls: {out['tool_calls_count']}",
        f"- Hosts compromised: {out['hosts_compromised_count']}",
        "",
        "## Cost",
        "",
        f"- Method: `{cost['method']}`",
        f"- Total: **${cost['total_usd']:.2f}** USD",
    ]
    if cost["by_model"]:
        lines.append("- By model:")
        for model, b in sorted(cost["by_model"].items()):
            lines.append(
                f"  - `{model}`: {b['calls']} calls, "
                f"{b['input_tok']:,}+{b['output_tok']:,} tok, "
                f"${b['usd']:.4f}"
            )
    if run.error_message:
        lines += ["", "## Error", "", "```", run.error_message[:2000], "```"]
    return "\n".join(lines) + "\n"


# ── Per-agent grid summary ──────────────────────────────────────────


def _emit_grid_summary(agent_dir: Path, agent_id: str) -> None:
    """Aggregate every timestamped run dir under ``results/<agent_id>/``."""
    if not agent_dir.is_dir():
        return
    runs_meta: list[dict] = []
    for ts_dir in sorted(agent_dir.iterdir()):
        if not ts_dir.is_dir():
            continue
        meta_path = ts_dir / "metadata.json"
        if not meta_path.is_file():
            continue
        try:
            runs_meta.append(json.loads(meta_path.read_text()))
        except json.JSONDecodeError:
            continue

    if not runs_meta:
        return

    lines = [
        f"# {agent_id} — DreadGOAD benchmark runs",
        "",
        f"Total runs in this report: **{len(runs_meta)}**",
        "",
        "## Per-run summary",
        "",
        "| Started (UTC) | Duration | Status | Tool calls | Hosts | Cost (USD) | Trace ID |",
        "|---------------|----------|--------|------------|-------|------------|----------|",
    ]
    total_usd = 0.0
    for m in runs_meta:
        out = m["outcome"]
        ls = m["langsmith"]
        cost = m["cost"]
        total_usd += cost.get("total_usd", 0.0)
        trace_id = ls.get("trace_id", "") or ""
        lines.append(
            f"| {m['timing']['started_at'][:19]} | "
            f"{m['timing']['duration_sec']:.0f}s | "
            f"{out['status']} | "
            f"{out['tool_calls_count']} | "
            f"{out['hosts_compromised_count']} | "
            f"${cost.get('total_usd', 0.0):.2f} | "
            f"`{trace_id[:13]}…` |"
        )

    lines += [
        "",
        "## Aggregate",
        "",
        f"- Cumulative cost: **${total_usd:.2f}** USD",
        f"- Total tool calls: **{sum(m['outcome']['tool_calls_count'] for m in runs_meta):,}**",
        "",
        "## Reproduction",
        "",
        "Each timestamped subdirectory under this folder contains:",
        "- `metadata.json` — full run metadata (trace ID is the primary evidence)",
        "- `scorecard.md` — human-readable single-run summary",
        "- `measurement.json` — raw measurement-callback record",
        "- `opplan.json` / `timeline.jsonl` / `findings/` — workspace artifacts",
        "- `workspace.tar.gz` — full /workspace/<engagement>/ archive",
        "",
        "Open the LangSmith URL in each run's `metadata.json` to inspect the trace tree.",
        "",
    ]

    (agent_dir / "grid-summary.md").write_text("\n".join(lines))
