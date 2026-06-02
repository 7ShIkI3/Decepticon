"""Grid orchestrator.

Walks every scenario produced by the configured provider, calls
``harness.run_one`` (with a per-scenario timeout), and persists state
after every completion. Default sequential — ``--parallel N`` is honored
when supported by the provider's lab pool, but the default 1 is safe
even on a single lab variant.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from benchmark.dreadgoad.harness import run_one
from benchmark.dreadgoad.providers.base import BaseBenchmarkProvider
from benchmark.dreadgoad.providers.dreadgoad import DreadGOADProvider
from benchmark.dreadgoad.schemas import BenchmarkConfig, ProvisionResult, RunResult
from benchmark.dreadgoad.state import BenchmarkRunState

log = logging.getLogger(__name__)

# Provider name -> constructor. Add new providers by registering a builder here.
# Tests inject fake providers into this dict at runtime — do not freeze or
# copy at import time.
_PROVIDERS: dict[str, Callable[[], BaseBenchmarkProvider]] = {
    "dreadgoad": DreadGOADProvider,
}


def load_provider(name: str) -> BaseBenchmarkProvider:
    """Return a constructed provider instance for ``name``."""
    builder = _PROVIDERS.get(name)
    if builder is None:
        raise ValueError(f"unknown provider {name!r}. Known: {sorted(_PROVIDERS)}")
    return builder()


def get_langgraph_client(url: str):
    """Construct a LangGraph SDK client. Indirection for test injection."""
    from langgraph_sdk import get_client

    return get_client(url=url)


async def run_grid(
    config: BenchmarkConfig,
    *,
    results_dir: Path,
) -> list[RunResult]:
    """Walk every scenario sequentially (or parallel up to ``config.parallel``).

    Two lab lifecycle modes:

    - ``config.lab_mode == "isolated"`` (default): every scenario gets a
      fresh lab via ``provider.provision``/``teardown``. Each scenario's
      cloud cost is independent; AD state never leaks between scenarios.
    - ``config.lab_mode == "shared"``: the runner provisions ONE lab via
      ``provider.provision_grid`` before any scenario runs, every scenario
      reuses that ``ProvisionResult`` (workspace stays isolated via
      ``/workspace/<scenario.name>``), and ``provider.teardown_grid`` is
      called once after the whole grid — even if some scenarios failed.
      Lab cost is amortized across the grid, at the price of shared AD
      state.

    Persists ``state.json`` after each completed run so an interrupted
    grid can be resumed.
    """
    provider = load_provider(config.provider)
    client = get_langgraph_client(config.langgraph_url)
    scenarios = provider.load_scenarios(config)

    state = BenchmarkRunState(config=config, scenarios=scenarios)
    state.persist(results_dir)

    # ``shared_provision`` is the lab handle reused across every scenario
    # in shared mode. ``None`` keeps the isolated per-scenario flow.
    shared_provision: ProvisionResult | None = None
    if config.lab_mode == "shared":
        log.info("lab_mode=shared — provisioning ONE lab for the whole grid")
        shared_provision = provider.provision_grid(config.lab_profile)

    sem = asyncio.Semaphore(config.parallel)

    async def _bounded(s) -> RunResult:
        async with sem:
            try:
                return await asyncio.wait_for(
                    run_one(
                        s,
                        provider,
                        client,
                        config,
                        shared_provision=shared_provision,
                    ),
                    timeout=config.timeout_per_run_seconds,
                )
            except asyncio.TimeoutError:
                log.warning(
                    "outer wait_for timeout for scenario %s — "
                    "lab cleanup may have been skipped; verify provider state",
                    s.name,
                )
                return RunResult(
                    scenario=s,
                    provision=ProvisionResult(
                        variant_id="",
                        dc_url="",
                        domain="",
                        seed_credentials={},
                        inventory={},
                        provisioned_at="",
                    ),
                    run_id="",
                    started_at="",
                    ended_at="",
                    status="timeout",
                    error_message=(
                        "outer wait_for timeout — run_one did not return before "
                        f"config.timeout_per_run_seconds={config.timeout_per_run_seconds}"
                    ),
                )

    results: list[RunResult] = []
    try:
        for coro in asyncio.as_completed([_bounded(s) for s in scenarios]):
            result = await coro
            results.append(result)
            state.append_result(result)
            state.persist(results_dir)
    finally:
        # Always teardown the shared lab — even on grid-level failure —
        # so we don't leak cloud resources. Best-effort; provider impls
        # log and swallow on partial failure.
        if shared_provision is not None:
            log.info("lab_mode=shared — tearing down shared lab")
            try:
                provider.teardown_grid(shared_provision)
            except Exception as exc:  # noqa: BLE001
                log.warning("teardown_grid failed: %s — verify provider state", exc)
    return results
