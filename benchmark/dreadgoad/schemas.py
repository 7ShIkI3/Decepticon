"""Typed contracts shared across the DreadGOAD benchmark runner.

All inputs (``BenchmarkConfig``, ``Scenario``) are frozen dataclasses so
the runner can hold them in lists / dicts safely. ``RunResult`` is
mutable so the runner can populate fields incrementally as a run
progresses (e.g., extending ``tool_calls`` during streaming).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BenchmarkConfig:
    """Parsed YAML grid config — immutable runtime constant."""

    name: str
    provider: str
    lab_profile: str
    rounds: int
    parallel: int
    timeout_per_run_seconds: int
    langgraph_url: str
    # LangGraph ``assistant_id`` values the harness will invoke. Each
    # entry is run ``rounds`` times. The operator is responsible for
    # registering matching graphs on the LangGraph server before
    # launching a grid.
    agents: tuple[str, ...]
    operator_message_template: str
    # Free-form list of OPPLAN concessions to inject when the agent
    # exposes an OPPLAN approval gate (e.g. ``["destructive_ok"]``).
    # Optional; the OSS default agent stack ignores it when unset.
    extra_opplan_concessions: tuple[str, ...] = ()

    # Lab lifecycle:
    #   "isolated" (default) — one lab variant per scenario;
    #     provision/teardown fires per ``run_one``. Strongest isolation;
    #     cost scales linearly with ``rounds × len(agents)``.
    #   "shared" — one lab variant per grid; provider provisions it
    #     once, every scenario reuses that ``ProvisionResult``, and the
    #     lab is torn down once at the end. Workspace isolation is
    #     preserved via ``/workspace/<scenario.name>``; AD state is
    #     *not* isolated. Pick this when the cost of N labs is
    #     prohibitive and AD state leakage across agents is acceptable.
    lab_mode: str = "isolated"


@dataclass(frozen=True)
class Scenario:
    """One unit of work — one agent invocation, one round."""

    name: str
    # LangGraph ``assistant_id`` resolved from ``BenchmarkConfig.agents``.
    agent_id: str
    lab_profile: str
    operator_message: str
    rounds_in_grid: int
    round_index: int


@dataclass
class ProvisionResult:
    """Output of ``provider.provision`` — lab metadata."""

    variant_id: str
    dc_url: str
    domain: str
    seed_credentials: dict[str, str]
    inventory: dict
    provisioned_at: str


@dataclass
class RunResult:
    """Complete record of a single run.

    Populated incrementally during execution and finalised in
    ``harness.run_one``. JSON-serialised to
    ``results/<agent_id>/<UTC-ts>/metadata.json``.
    """

    scenario: Scenario
    provision: ProvisionResult
    run_id: str
    started_at: str
    ended_at: str
    status: str  # "completed" | "timeout" | "failed"

    # LangSmith tracing identifiers — useful for any operator who needs
    # to navigate to the trace in the LangSmith UI. ``run_id`` above is
    # the LangSmith ``trace_id``; the extras make the trace reachable
    # without grepping the export.
    langsmith_project: str = ""
    thread_id: str = ""
    assistant_id: str = ""
    trace_url: str = ""
    duration_sec: float = 0.0

    # Per-run cost (model-provider public pricing, computed offline).
    # ``cost_method`` is ``"time_window"`` by default — the runner
    # filters LiteLLM ``spend_logs`` to the run's wall-clock window.
    cost_method: str = ""
    cost_total_usd: float = 0.0
    cost_by_model: dict = field(default_factory=dict)

    # Per-host outcome captured opportunistically from the agent's
    # workspace artifacts (``<ip>_state.txt`` files, OPPLAN status,
    # etc.). Free-form ``dict``s so different agent stacks can record
    # whatever shape they want.
    hosts_compromised: list[dict] = field(default_factory=list)

    # Streaming tool-call log; useful for operator-side post-hoc
    # analysis without touching LangSmith.
    tool_calls: list[dict] = field(default_factory=list)

    # Paths
    workspace_archive_path: str = ""
    error_message: str | None = None
