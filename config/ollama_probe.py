"""Container-side Ollama reachability + tool-capability probe.

Two checks: ``GET /api/tags`` for reachability (with diagnostics for
the localhost trap and the 127.0.0.1-binding case), and
``POST /api/show`` to require the model's ``capabilities`` includes
``tools`` — Decepticon agents always emit tool calls. Best-effort:
never blocks proxy boot, just logs ``[decepticon ollama]`` lines.

Lives next to ``litellm_startup.py`` rather than inside it so the
unit tests can load it via ``importlib`` without dragging in the
startup script's heavy import-time side effects.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Ollama's tools capability is reported under ``capabilities`` in
# /api/show responses on Ollama 0.3+ (released 2024-08). Models like
# qwen3-coder, llama3.3, mistral-small3 advertise it; smaller or
# legacy models often don't.
_TOOLS_CAPABILITY = "tools"

# Local Ollama (host or WSL) vs Ollama Cloud (https://ollama.com). They
# probe different endpoints with different auth, so the startup script
# separates requested models by provider prefix before probing.
LOCAL_OLLAMA_PREFIXES = ("ollama_chat", "ollama")
CLOUD_OLLAMA_PREFIXES = ("ollama_cloud",)
_OLLAMA_PROVIDER_PREFIXES = LOCAL_OLLAMA_PREFIXES + CLOUD_OLLAMA_PREFIXES

# Ollama Cloud's default base is the OpenAI-compatible ``/v1`` path, but
# the native ``/api/tags`` and ``/api/show`` capability endpoints live at
# the root. ``_native_api_base`` strips a trailing ``/v1`` so the probe
# targets the native API.
_CLOUD_DEFAULT_BASE = "https://ollama.com"

_HttpOpener = Callable[[Any, float], Any]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one probe step. ``message=None`` means silent pass."""

    ok: bool
    message: str | None = None


def has_ollama_route(
    model_ids: Iterable[str],
    prefixes: Iterable[str] = _OLLAMA_PROVIDER_PREFIXES,
) -> bool:
    """True when at least one requested model uses an Ollama provider.

    ``prefixes`` narrows the match — pass ``LOCAL_OLLAMA_PREFIXES`` or
    ``CLOUD_OLLAMA_PREFIXES`` to test one family. Defaults to all.
    """
    wanted = {p.lower() for p in prefixes}
    for model_id in model_ids:
        prefix = model_id.split("/", 1)[0].lower()
        if prefix in wanted:
            return True
    return False


def extract_ollama_models(
    model_ids: Iterable[str],
    prefixes: Iterable[str] = _OLLAMA_PROVIDER_PREFIXES,
) -> list[str]:
    """Strip the Ollama provider prefix; skip non-Ollama and bare-prefix entries.

    ``prefixes`` narrows which providers are extracted — pass
    ``LOCAL_OLLAMA_PREFIXES`` or ``CLOUD_OLLAMA_PREFIXES`` to pull just
    one family (local vs cloud probe different endpoints). Defaults to all.
    """
    wanted = {p.lower() for p in prefixes}
    out: list[str] = []
    for model_id in model_ids:
        prefix, _, tag = model_id.partition("/")
        if prefix.lower() in wanted and tag:
            out.append(tag)
    return out


def _native_api_base(base_url: str) -> str:
    """Return the native Ollama API root for a (possibly ``/v1``) base.

    Ollama Cloud's ``/api/tags`` and ``/api/show`` live at the root, not
    under the OpenAI-compatible ``/v1`` path. Strip a trailing ``/v1`` so
    the capability probe targets ``https://ollama.com`` rather than
    ``https://ollama.com/v1`` (which 404s the native endpoints). Defaults
    to ``https://ollama.com`` when the base is empty.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return _CLOUD_DEFAULT_BASE
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return base or _CLOUD_DEFAULT_BASE


def _build_request(
    url: str,
    *,
    data: bytes | None = None,
    method: str = "GET",
    auth_token: str | None = None,
) -> urllib.request.Request:
    """Build a urllib Request with optional JSON body + Bearer auth.

    Ollama Cloud requires ``Authorization: Bearer <key>``; local Ollama
    needs no auth, so ``auth_token`` is omitted there.
    """
    headers: dict[str, str] = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return urllib.request.Request(url, data=data, method=method, headers=headers)


def _default_opener(url_or_request: Any, timeout: float) -> Any:
    return urllib.request.urlopen(url_or_request, timeout=timeout)


def _running_in_wsl2() -> bool:
    """Detect whether the probe is running in (or talking to) a WSL2 host.

    Multiple signals — Decepticon agents run inside Docker containers,
    but the LiteLLM container can inspect environment variables passed
    in from the host. Most reliable signals:
    - ``/proc/version`` contains 'microsoft' or 'WSL'
    - ``WSL_DISTRO_NAME`` env var is set (Microsoft documented)
    - ``WSL_INTEROP`` env var exists

    Returns True on any positive signal. Best-effort — never raises.
    """
    if os.getenv("WSL_DISTRO_NAME") or os.getenv("WSL_INTEROP"):
        return True
    proc_version = Path("/proc/version")
    if proc_version.is_file():
        try:
            content = proc_version.read_text(errors="ignore").lower()
        except OSError:
            return False
        if "microsoft" in content or "wsl" in content:
            return True
    return False


def _classify_transport_error(base_url: str, err: BaseException) -> str:
    """Translate a transport error into a one-line operator hint."""
    text = str(err).lower()
    reason = str(getattr(err, "reason", err)).lower()
    combined = f"{text} {reason}"

    if "refused" in combined:
        wsl2_hint = ""
        if _running_in_wsl2():
            wsl2_hint = (
                " (WSL2 detected) On WSL2 the most common cause is "
                "Ollama bound only to the WSL2 loopback. Verify with "
                "`netstat -tlnp | grep 11434` on the WSL host — if the "
                "Local Address shows 127.0.0.1:11434, that's the bug. "
                "Restart Ollama with `OLLAMA_HOST=0.0.0.0:11434 ollama "
                "serve` (or set `OLLAMA_HOST=0.0.0.0` in the ollama "
                "systemd unit / launchd plist) so it binds to all "
                "interfaces."
            )
        return (
            f"Cannot reach {base_url}: connection refused. Ollama is most "
            "likely bound to 127.0.0.1 only — relaunch with "
            "OLLAMA_HOST=0.0.0.0:11434 ollama serve so the litellm "
            "container can reach it." + wsl2_hint
        )
    dns_signals = (
        "name or service not known",
        "name resolution",
        "nodename nor servname",
        "temporary failure in name resolution",
        "no address associated",
    )
    if any(signal in combined for signal in dns_signals):
        wsl2_hint = ""
        if _running_in_wsl2():
            wsl2_hint = (
                " (WSL2 detected) Docker Desktop registers "
                "host.docker.internal automatically — if you're using "
                "native Docker inside WSL (no Docker Desktop), make "
                "sure `docker-compose.yml`'s litellm service still "
                "has `extra_hosts: ['host.docker.internal:host-gateway']` "
                "(it does by default; check you're not running a stale "
                "compose override). As a workaround, set "
                "OLLAMA_API_BASE to your WSL distro's IP "
                "(`ip -4 addr show eth0 | grep inet | awk '{print $2}' "
                "| cut -d/ -f1`) — but prefer fixing the bridge resolution."
            )
        return (
            f"Cannot resolve host for {base_url}. The litellm service in "
            "docker-compose.yml needs "
            "extra_hosts: ['host.docker.internal:host-gateway'] for the "
            "default URL to resolve." + wsl2_hint
        )
    if "timed out" in combined or "timeout" in combined:
        wsl2_hint = ""
        if _running_in_wsl2():
            wsl2_hint = (
                " (WSL2 detected) WSL2's bridged networking can drop "
                "host-bound traffic when Windows Defender Firewall is "
                "blocking the inbound port. On Windows admin PowerShell: "
                "`New-NetFirewallRule -DisplayName 'Ollama for WSL2' "
                "-Direction Inbound -LocalPort 11434 -Protocol TCP "
                "-Action Allow`. If you're on WSL2 mirrored networking "
                "(Win11 22H2+), confirm `[wsl2] networkingMode=mirrored` "
                "in `%USERPROFILE%/.wslconfig` and restart with "
                "`wsl --shutdown`."
            )
        return (
            f"Cannot reach {base_url}: request timed out. The host is "
            "resolvable but not answering on port 11434 within the "
            "probe window." + wsl2_hint
        )
    return f"Cannot reach {base_url}: {err}"


def _classify_auth_error(base_url: str, code: int) -> str:
    """One-line hint for a 401/403 from Ollama Cloud — almost always a
    missing or wrong API key. The onboard wizard writes the key as
    OLLAMA_CLOUD_API_KEY; the runtime also accepts OLLAMA_API_KEY."""
    return (
        f"Ollama Cloud at {base_url} rejected the request (HTTP {code}). "
        "The API key is missing or invalid — set OLLAMA_CLOUD_API_KEY "
        "(or OLLAMA_API_KEY) to a valid key from "
        "https://ollama.com/settings/keys. Until then every agent turn "
        "401s and the Soundwave interview can't hand off."
    )


def reachability(
    base_url: str,
    *,
    timeout: float = 2.0,
    opener: _HttpOpener | None = None,
    auth_token: str | None = None,
) -> ProbeResult:
    """Probe ``base_url/api/tags``. Pre-flight rejects loopback hosts —
    from inside a container they're never the host running Ollama.

    ``auth_token`` attaches Bearer auth for Ollama Cloud; local Ollama
    omits it.
    """
    if not base_url.strip():
        return ProbeResult(False, "OLLAMA_API_BASE is empty.")

    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return ProbeResult(
            False,
            f"OLLAMA_API_BASE={base_url} points at the container's own "
            "loopback. From inside Docker localhost is the container, "
            "never the host. Use http://host.docker.internal:11434 — "
            "compose's extra_hosts mapping resolves that to the host.",
        )

    open_url = opener or _default_opener
    request = _build_request(f"{base_url.rstrip('/')}/api/tags", auth_token=auth_token)
    try:
        with open_url(request, timeout) as resp:
            status = getattr(resp, "status", 200)
            if status >= 400:
                return ProbeResult(
                    False,
                    f"Ollama responded with HTTP {status} at {base_url}.",
                )
            return ProbeResult(True)
    except urllib.error.HTTPError as err:
        if err.code in (401, 403):
            return ProbeResult(False, _classify_auth_error(base_url, err.code))
        return ProbeResult(
            False,
            f"Ollama responded with HTTP {err.code} at {base_url}: {err.reason}",
        )
    except (urllib.error.URLError, OSError) as err:
        return ProbeResult(False, _classify_transport_error(base_url, err))


def tool_capability(
    base_url: str,
    model: str,
    *,
    timeout: float = 5.0,
    opener: _HttpOpener | None = None,
    auth_token: str | None = None,
) -> ProbeResult:
    """Confirm ``model`` advertises ``tools`` via ``/api/show`` capabilities.

    ``auth_token`` attaches Bearer auth for Ollama Cloud; local Ollama
    omits it.
    """
    if not base_url.strip() or not model.strip():
        return ProbeResult(False, "Missing OLLAMA_API_BASE or model name for capability probe.")

    open_url = opener or _default_opener
    payload = json.dumps({"name": model}).encode("utf-8")
    request = _build_request(
        f"{base_url.rstrip('/')}/api/show",
        data=payload,
        method="POST",
        auth_token=auth_token,
    )

    try:
        with open_url(request, timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return ProbeResult(
                False,
                f"Ollama model {model!r} is not pulled on this host. Run: ollama pull {model}",
            )
        if err.code in (401, 403):
            return ProbeResult(False, _classify_auth_error(base_url, err.code))
        return ProbeResult(
            False,
            f"Ollama /api/show returned HTTP {err.code} for {model!r}: {err.reason}",
        )
    except (urllib.error.URLError, OSError) as err:
        return ProbeResult(False, _classify_transport_error(base_url, err))

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return ProbeResult(False, f"Ollama /api/show returned non-JSON body for {model!r}.")

    capabilities = data.get("capabilities")
    if not isinstance(capabilities, list):
        # Older Ollama versions (< 0.3) don't ship the capabilities
        # field. We can't determine tool support — emit a soft hint
        # and let the request path surface the real verdict.
        return ProbeResult(
            True,
            f"Ollama at {base_url} did not report capabilities for "
            f"{model!r} (Ollama < 0.3?). Tool calling may still work; "
            "if requests fail, upgrade Ollama and re-pull the model.",
        )

    if _TOOLS_CAPABILITY in capabilities:
        return ProbeResult(True)

    return ProbeResult(
        False,
        f"Model {model!r} does not advertise the 'tools' capability "
        f"(reported: {capabilities}). Decepticon agents always emit "
        "tool calls — pull a tool-capable model instead "
        "(e.g. qwen3-coder, llama3.3, mistral-small3) and set "
        "OLLAMA_MODEL accordingly.",
    )


def probe(
    base_url: str,
    models: Iterable[str],
    *,
    opener: _HttpOpener | None = None,
) -> list[str]:
    """Reachability + per-model tool-capability. Returns operator log
    lines; empty means clean. Reachability failure short-circuits."""
    lines: list[str] = []

    reach = reachability(base_url, opener=opener)
    if reach.message:
        lines.append(reach.message)
    if not reach.ok:
        return lines

    for model in models:
        cap = tool_capability(base_url, model, opener=opener)
        if cap.message:
            lines.append(cap.message)

    return lines


def probe_cloud(
    base_url: str,
    models: Iterable[str],
    *,
    api_key: str,
    opener: _HttpOpener | None = None,
) -> list[str]:
    """Ollama Cloud reachability + per-model tool-capability.

    Cloud differs from local Ollama in two ways the local ``probe`` can't
    handle: it requires a Bearer API key, and its native ``/api/show``
    capability endpoint lives at the root (``https://ollama.com``), not
    under the OpenAI-compatible ``/v1`` path that ``OLLAMA_CLOUD_API_BASE``
    defaults to. Returns operator log lines; empty means clean.

    A missing API key is reported up front — without it every request
    401s and the operator gets stuck on the Soundwave interview with no
    diagnostic, which is exactly the loop reported on Ollama Cloud.
    """
    lines: list[str] = []

    if not api_key.strip():
        lines.append(
            "Ollama Cloud is selected but no API key is set. `decepticon "
            "onboard` writes OLLAMA_CLOUD_API_KEY — set it (or "
            "OLLAMA_API_KEY) to a key from "
            "https://ollama.com/settings/keys, otherwise every request "
            "401s and the Soundwave interview can't hand off to Decepticon."
        )
        return lines

    native = _native_api_base(base_url)
    reach = reachability(native, opener=opener, auth_token=api_key)
    if reach.message:
        lines.append(reach.message)
    if not reach.ok:
        return lines

    for model in models:
        cap = tool_capability(native, model, opener=opener, auth_token=api_key)
        if cap.message:
            lines.append(cap.message)

    return lines


__all__ = [
    "CLOUD_OLLAMA_PREFIXES",
    "LOCAL_OLLAMA_PREFIXES",
    "ProbeResult",
    "extract_ollama_models",
    "has_ollama_route",
    "probe",
    "probe_cloud",
    "reachability",
    "tool_capability",
]
