"""DreadGOAD benchmark provider.

Expands a ``BenchmarkConfig`` into ``len(config.agents) × config.rounds``
scenarios, wraps the upstream ``./cli/dreadgoad`` Go binary for lab
lifecycle, and maps the parsed inventory JSON into a typed
``ProvisionResult``.

Agent registration is fully delegated to the operator — every
``agent_id`` listed in the config YAML must already be registered on
the LangGraph server before a grid runs. No hardcoded registry; the
provider trusts ``BenchmarkConfig.agents`` verbatim.
"""

from __future__ import annotations

import datetime as _dt

from benchmark.dreadgoad.lab import dreadgoad_cli
from benchmark.dreadgoad.providers.base import BaseBenchmarkProvider
from benchmark.dreadgoad.schemas import (
    BenchmarkConfig,
    ProvisionResult,
    Scenario,
)


def _iso_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


class DreadGOADProvider(BaseBenchmarkProvider):
    """Provisions DreadGOAD AD labs via the upstream Go CLI."""

    @property
    def name(self) -> str:
        return "dreadgoad"

    def load_scenarios(self, config: BenchmarkConfig) -> list[Scenario]:
        # Grid-level timestamp so every scenario in the same grid run
        # shares the same suffix — easier to correlate
        # ``<agent>-<ts>`` directories on the sandbox with the grid
        # invocation that produced them. ISO 8601 minute precision with
        # ``:`` swapped for ``-`` so the slug stays filesystem-safe.
        grid_ts = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out: list[Scenario] = []
        for agent_id in config.agents:
            for i in range(1, config.rounds + 1):
                suffix = grid_ts if config.rounds == 1 else f"{grid_ts}-{i}"
                out.append(
                    Scenario(
                        name=f"{agent_id}-{suffix}",
                        agent_id=agent_id,
                        lab_profile=config.lab_profile,
                        operator_message="",  # populated by harness after provision
                        rounds_in_grid=config.rounds,
                        round_index=i,
                    )
                )
        return out

    def provision(self, scenario: Scenario) -> ProvisionResult:
        return self._provision_lab(scenario.lab_profile)

    def teardown(self, provision: ProvisionResult) -> None:
        dreadgoad_cli.destroy(provision.variant_id)

    # --- Shared-lab lifecycle ----------------------------------------------

    def provision_grid(self, lab_profile: str) -> ProvisionResult:
        """One lab per grid (shared mode). Internally identical to
        ``provision`` — what differs is *who* owns the lifecycle: the
        runner calls this once for the whole grid, never per scenario.
        """
        return self._provision_lab(lab_profile)

    def teardown_grid(self, provision: ProvisionResult) -> None:
        dreadgoad_cli.destroy(provision.variant_id)

    # --- Internals ---------------------------------------------------------

    def _provision_lab(self, lab_profile: str) -> ProvisionResult:
        inv = dreadgoad_cli.provision(lab_profile)
        dreadgoad_cli.wait_healthy(inv["variant_id"])
        return ProvisionResult(
            variant_id=inv["variant_id"],
            dc_url=inv["primary_dc"]["url"],
            domain=inv["domain"],
            seed_credentials=dict(inv.get("seed_credentials", {})),
            inventory=inv,
            provisioned_at=_iso_now(),
        )
