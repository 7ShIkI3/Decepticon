"""Persistent benchmark-grid state for crash resilience.

A grid run can be interrupted (Ctrl+C, network glitch, AWS quota
exhaustion). To avoid losing accumulated results, the runner flushes
the state after every completed scenario. ``state.json`` is written
to the same grid output directory as the per-run dumps + scorecard.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from benchmark.dreadgoad.schemas import BenchmarkConfig, RunResult, Scenario


@dataclass
class BenchmarkRunState:
    """In-memory + on-disk state of one grid execution."""

    config: BenchmarkConfig
    scenarios: list[Scenario]
    results: list[RunResult] = field(default_factory=list)

    def append_result(self, result: RunResult) -> None:
        self.results.append(result)

    def completed_scenario_names(self) -> set[str]:
        return {r.scenario.name for r in self.results}

    def remaining_scenarios(self) -> list[Scenario]:
        done = self.completed_scenario_names()
        return [s for s in self.scenarios if s.name not in done]

    def persist(self, out_dir: Path) -> None:
        """Atomically write ``<out_dir>/state.json``.

        Uses tempfile + ``os.replace`` so an interrupted write cannot leave
        a truncated file. Reconstruction (resume from a prior state.json)
        is the runner's responsibility — see ``benchmark/runner.py``.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / "state.json"
        data = json.dumps(
            {
                "config": asdict(self.config),
                "scenarios": [asdict(s) for s in self.scenarios],
                "results": [asdict(r) for r in self.results],
            },
            sort_keys=True,
            default=str,
        )
        fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
        try:
            os.write(fd, data.encode())
            os.close(fd)
            os.replace(tmp, target)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
