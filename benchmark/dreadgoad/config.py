"""YAML loader for benchmark scenario configs.

Validates that:
  - ``agents`` is a non-empty list of LangGraph ``assistant_id`` slugs
  - ``rounds`` >= 1
  - ``parallel`` >= 1
  - ``timeout_per_run_seconds`` > 0
  - ``lab_mode`` is one of {"isolated", "shared"}

The operator is responsible for ensuring every ``agent_id`` in ``agents``
is registered on the LangGraph server before launching a grid; the
loader does no graph-registration introspection. Unknown keys are
tolerated (forward-compat with future config additions).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from benchmark.dreadgoad.schemas import BenchmarkConfig

_VALID_LAB_MODES: frozenset[str] = frozenset({"isolated", "shared"})


def load_config(path: str | Path) -> BenchmarkConfig:
    """Parse a YAML benchmark config file into a typed ``BenchmarkConfig``."""
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"expected a YAML mapping in {path}, got {type(raw).__name__}")

    _required = ("name", "provider", "lab_profile", "langgraph_url", "operator_message_template")
    missing = [k for k in _required if k not in raw]
    if missing:
        raise ValueError(f"missing required config key(s): {missing}")

    agents_list = list(raw.get("agents", []))
    if not agents_list:
        raise ValueError(f"agents list must not be empty in {path}")

    rounds = int(raw.get("rounds", 1))
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds}")

    parallel = int(raw.get("parallel", 1))
    if parallel < 1:
        raise ValueError(f"parallel must be >= 1, got {parallel}")

    timeout = int(raw.get("timeout_per_run_seconds", 3600))
    if timeout <= 0:
        raise ValueError(f"timeout_per_run_seconds must be > 0, got {timeout}")

    lab_mode = str(raw.get("lab_mode", "isolated"))
    if lab_mode not in _VALID_LAB_MODES:
        raise ValueError(f"lab_mode must be one of {sorted(_VALID_LAB_MODES)}, got {lab_mode!r}")

    return BenchmarkConfig(
        name=raw["name"],
        provider=raw["provider"],
        lab_profile=raw["lab_profile"],
        rounds=rounds,
        parallel=parallel,
        timeout_per_run_seconds=timeout,
        langgraph_url=raw["langgraph_url"],
        agents=tuple(agents_list),
        operator_message_template=raw["operator_message_template"],
        extra_opplan_concessions=tuple(raw.get("extra_opplan_concessions", ())),
        lab_mode=lab_mode,
    )
