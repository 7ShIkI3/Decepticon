"""Regression guard: reporting tools must reach the agents that need them.

Historical context: ``REPORTING_TOOLS`` shipped and were unit-tested but
reached no agent (no agent listed them and ``build_tools`` never
received them), while ``contract_auditor.md`` instructed the model to
call ``report_hackerone`` — a tool the agent did not actually have, so
the model would emit a tool call that always fails. These tests pin the
wiring AND the prompt<->tool contract so the regression cannot return.

Current state (post-KG-narrow, refactor/kg-narrow-and-research-prep):
``contract_auditor`` no longer wires ``report_hackerone`` (the tool
routes through the broken ``graph_transaction`` shim and the narrow
prunes it pending the KG middleware redesign). ``contract_auditor.md``
step 6 now emits a HackerOne-style ``findings/FIND-NNN.md`` directly
instead. ``analyst`` remains the sole carrier of the full
``REPORTING_TOOLS`` suite and is the only agent the prompt<->tool
contract check still applies to.
"""

from __future__ import annotations

from typing import Any

import pytest

from decepticon.agents.prompts import load_prompt
from decepticon.agents.standard import analyst
from decepticon.tools.reporting.tools import REPORTING_TOOLS

_REPORTING_NAMES = frozenset(t.name for t in REPORTING_TOOLS)


def test_reporting_suite_is_nonempty() -> None:
    # Guards against the bundle being emptied out from under the wiring tests.
    assert {"report_hackerone", "report_sarif", "report_executive"} <= _REPORTING_NAMES


def test_analyst_exposes_full_reporting_suite() -> None:
    """The Analyst is the engagement reporting specialist — it gets every report_* tool."""
    missing = _REPORTING_NAMES - frozenset(analyst._STANDARD_TOOLS)
    assert not missing, f"analyst is missing reporting tools: {sorted(missing)}"


@pytest.mark.parametrize(
    ("module", "role"),
    [
        (analyst, "analyst"),
    ],
)
def test_prompt_referenced_reporting_tools_are_wired(module: Any, role: str) -> None:
    """Any report_* tool a prompt tells the model to call MUST be in its toolset.

    A prompt that references a tool the agent cannot see makes the model
    emit a tool call that can never resolve — the exact bug this fixes.

    Only the analyst is checked: it is the sole agent that carries the
    full REPORTING_TOOLS bundle post-narrow. Other roles that previously
    referenced specific report_* tools (e.g. contract_auditor invoking
    report_hackerone in its prompt) have had those references rewritten
    to file-based equivalents.
    """
    prompt = load_prompt(role, shared=["bash"])
    toolset = frozenset(module._STANDARD_TOOLS)
    referenced = frozenset(name for name in _REPORTING_NAMES if name in prompt)
    missing = referenced - toolset
    assert not missing, f"{role}.md references unreachable reporting tools: {sorted(missing)}"
