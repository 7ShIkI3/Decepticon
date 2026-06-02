"""Abstract base for benchmark providers.

A provider owns:

  1. **Scenario enumeration** — expanding a ``BenchmarkConfig`` into
     concrete ``Scenario`` instances (e.g., 5 APTs × 3 rounds → 15
     scenarios).
  2. **Lab lifecycle** — ``provision`` brings a lab up and waits for
     health-check pass; ``teardown`` destroys it. Both are best-effort
     with respect to AWS billing — teardown failures log a warning but
     do not raise.

Concrete providers live alongside this file
(``benchmark/providers/dreadgoad.py`` etc).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from benchmark.dreadgoad.schemas import (
    BenchmarkConfig,
    ProvisionResult,
    Scenario,
)


class BaseBenchmarkProvider(ABC):
    """Abstract benchmark provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider display name (e.g. ``"dreadgoad"``)."""

    @abstractmethod
    def load_scenarios(self, config: BenchmarkConfig) -> list[Scenario]:
        """Expand a benchmark config into a typed scenario list."""

    @abstractmethod
    def provision(self, scenario: Scenario) -> ProvisionResult:
        """Stand up the lab and block until health-check passes.

        Used by the **isolated** lab mode (one lab per scenario).
        """

    @abstractmethod
    def teardown(self, provision: ProvisionResult) -> None:
        """Destroy the lab. Best-effort — log + continue on partial failure.

        Used by the **isolated** lab mode (paired with ``provision``).
        """

    # --- Shared-lab lifecycle (optional) ------------------------------------
    # Default raises NotImplementedError so existing providers don't have to
    # change to keep working in isolated mode. Providers that opt in
    # (DreadGOAD does) override both as a pair.

    def provision_grid(self, lab_profile: str) -> ProvisionResult:
        """Stand up ONE lab shared by every scenario in the grid (shared mode).

        Called by the runner exactly once at grid start. The returned
        ``ProvisionResult`` is reused for every scenario; ``teardown_grid``
        destroys it exactly once at grid end.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support shared lab_mode")

    def teardown_grid(self, provision: ProvisionResult) -> None:
        """Destroy the shared lab. Best-effort — paired with ``provision_grid``."""
        raise NotImplementedError(f"{type(self).__name__} does not support shared lab_mode")
