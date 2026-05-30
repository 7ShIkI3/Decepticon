from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

if "litellm" not in sys.modules:
    _litellm_stub = types.ModuleType("litellm")

    class _AuthErr(Exception):
        def __init__(self, message: str = "", model: str = "", llm_provider: str = "") -> None:
            super().__init__(message)
            self.message = message

    class _RateLimitErr(Exception):
        pass

    class _APIError(Exception):
        def __init__(
            self, status_code: int = 0, message: str = "", model: str = "", llm_provider: str = ""
        ) -> None:
            super().__init__(message)

    class _CustomLLM:
        pass

    class _ModelResponse:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    _litellm_stub.AuthenticationError = _AuthErr
    _litellm_stub.RateLimitError = _RateLimitErr
    _litellm_stub.APIError = _APIError
    _litellm_stub.CustomLLM = _CustomLLM
    _litellm_stub.ModelResponse = _ModelResponse
    sys.modules["litellm"] = _litellm_stub

if "oauth_token_store" not in sys.modules:
    _ots_path = Path(__file__).resolve().parents[5] / "config" / "oauth_token_store.py"
    _ots_spec = importlib.util.spec_from_file_location("oauth_token_store", _ots_path)
    assert _ots_spec and _ots_spec.loader
    _ots_mod = importlib.util.module_from_spec(_ots_spec)
    sys.modules["oauth_token_store"] = _ots_mod
    _ots_spec.loader.exec_module(_ots_mod)

_MODULE_PATH = Path(__file__).resolve().parents[5] / "config" / "gemini_handler.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("decepticon_gemini_handler", _MODULE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_session_cookies_env_var_is_ignored_load_tokens_falls_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GEMINI_SESSION_COOKIES", '{"SID": "abc123", "HSID": "xyz"}')
    monkeypatch.delenv("GEMINI_ACCESS_TOKEN", raising=False)

    mod = _load_module()
    monkeypatch.setattr(mod, "GEMINI_TOKENS_PATH", tmp_path / "absent_tokens.json")
    monkeypatch.setattr(mod._gemini_file_cache, "get", lambda: None)

    result = mod._load_tokens()

    assert result is None, (
        f"GEMINI_SESSION_COOKIES must not produce a token dict; _load_tokens returned {result!r}"
    )


def test_get_gemini_access_token_raises_when_only_cookies_env_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GEMINI_SESSION_COOKIES", '{"SID": "abc123"}')
    monkeypatch.delenv("GEMINI_ACCESS_TOKEN", raising=False)

    mod = _load_module()
    monkeypatch.setattr(mod._gemini_file_cache, "get", lambda: None)

    import litellm

    with pytest.raises(litellm.AuthenticationError):
        mod.get_gemini_access_token()


def test_access_token_env_still_works_after_cookies_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_ACCESS_TOKEN", "ya29.real_token")
    monkeypatch.delenv("GEMINI_SESSION_COOKIES", raising=False)

    mod = _load_module()
    token = mod.get_gemini_access_token()

    assert token == "ya29.real_token"


def test_session_cookies_does_not_bleed_into_access_token_when_both_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_ACCESS_TOKEN", "ya29.priority")
    monkeypatch.setenv("GEMINI_SESSION_COOKIES", '{"SID": "ignored"}')

    mod = _load_module()
    token = mod.get_gemini_access_token()

    assert token == "ya29.priority"
