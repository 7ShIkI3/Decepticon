"""Subprocess wrapper around the upstream DreadGOAD Go CLI.

Configures DREADGOAD_CLI_PATH (env, default ``./cli/dreadgoad``). The
operator is responsible for cloning DreadGOAD + building the binary
before running any benchmark grid that uses DreadGOADProvider.

Functions:
  - provision(variant) → inventory dict (parsed JSON)
  - wait_healthy(variant_id, timeout) → None | raises RuntimeError
  - destroy(variant_id) → None (best-effort, logs warning on failure)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path

log = logging.getLogger(__name__)

DREADGOAD_CLI = Path(os.environ.get("DREADGOAD_CLI_PATH", "./cli/dreadgoad"))

# DREADGOAD_BENCH_REUSE=1 reuses a pre-provisioned lab instead of calling the
# upstream CLI. The operator brings the lab up out-of-band (e.g. `dreadgoad up`
# on Azure), and the env vars below describe it. Skips both `provision` (the
# upstream CLI's `--variant/--output-json` flags don't exist on every release)
# and `destroy` (operator owns lifecycle / billing).
_REUSE = os.environ.get("DREADGOAD_BENCH_REUSE", "").lower() in ("1", "true", "yes")


def _reuse_inventory() -> dict:
    """Build the same dict shape that the upstream JSON would have, sourced
    from DREADGOAD_BENCH_* env vars. Keeps ProvisionResult mapping in
    ``providers/dreadgoad.py`` unchanged."""
    variant_id = os.environ.get("DREADGOAD_BENCH_VARIANT_ID", "reuse-external")
    domain = os.environ.get("DREADGOAD_BENCH_DOMAIN", "sevenkingdoms.local")
    dc_url = os.environ.get("DREADGOAD_BENCH_DC_URL", "")
    if not dc_url:
        raise RuntimeError(
            "DREADGOAD_BENCH_REUSE=1 but DREADGOAD_BENCH_DC_URL is unset "
            "(expected e.g. http://10.8.1.7:5985 or smb://10.8.1.7)."
        )
    seed_user = os.environ.get("DREADGOAD_BENCH_SEED_USER", "")
    seed_pass = os.environ.get("DREADGOAD_BENCH_SEED_PASS", "")
    seed = {"username": seed_user, "password": seed_pass} if seed_user else {}
    return {
        "variant_id": variant_id,
        "primary_dc": {"url": dc_url},
        "domain": domain,
        "seed_credentials": seed,
        "reuse": True,
    }


def provision(variant: str = "goad-full-5host", *, timeout: int = 1800) -> dict:
    """Run ``./cli/dreadgoad provision --variant <variant>`` and parse JSON output.

    Raises RuntimeError on:
      - non-zero exit
      - invalid JSON in stdout
      - subprocess timeout (re-raised by subprocess.run)
    """
    if _REUSE:
        log.info("DREADGOAD_BENCH_REUSE=1 — reusing pre-provisioned lab.")
        return _reuse_inventory()
    result = subprocess.run(
        [str(DREADGOAD_CLI), "provision", "--variant", variant, "--output-json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"dreadgoad provision failed (exit {result.returncode}): {result.stderr[:500]}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"dreadgoad provision stdout not JSON: {result.stdout[:500]}") from exc


def wait_healthy(variant_id: str, *, timeout: int = 600, poll_seconds: int = 15) -> None:
    """Poll ``./cli/dreadgoad health-check`` until exit 0 or timeout.

    Each poll is a fresh subprocess call. Raises RuntimeError on timeout.
    """
    if _REUSE:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            [str(DREADGOAD_CLI), "health-check", "--variant-id", variant_id],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(poll_seconds)
    raise RuntimeError(f"dreadgoad lab {variant_id} unhealthy after {timeout}s")


def destroy(variant_id: str, *, timeout: int = 900) -> None:
    """Best-effort lab destruction.

    Logs a warning on failure but does not raise — letting an unrelated
    subprocess error block subsequent grid runs would multiply AWS cost.
    Operator must verify AWS billing manually if this path is exercised.
    """
    if _REUSE:
        log.info("DREADGOAD_BENCH_REUSE=1 — skipping destroy for %s.", variant_id)
        return
    try:
        subprocess.run(
            [str(DREADGOAD_CLI), "destroy", "--variant-id", variant_id],
            capture_output=True,
            timeout=timeout,
            check=True,
        )
    except subprocess.SubprocessError as exc:
        log.warning(
            "dreadgoad destroy failed for variant_id=%s: %s — verify AWS billing.",
            variant_id,
            exc,
        )
