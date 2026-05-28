"""Tests for decepticon.middleware.budget."""

from __future__ import annotations

import pytest

from decepticon.middleware.budget import (
    BudgetEnforcementMiddleware,
    BudgetExceeded,
    _SpendCache,
)


def test_spend_cache_set_get():
    cache = _SpendCache(ttl_seconds=60.0)
    cache.set("k1", 1.23)
    assert cache.get("k1") == 1.23


def test_spend_cache_miss():
    cache = _SpendCache(ttl_seconds=60.0)
    assert cache.get("nope") is None


def test_spend_cache_eviction_at_capacity():
    cache = _SpendCache(ttl_seconds=60.0)
    for i in range(cache._MAX_ENTRIES + 10):
        cache.set(f"k{i}", float(i))
    assert len(cache._entries) <= cache._MAX_ENTRIES


def test_disabled_when_no_caps_set():
    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=0.0,
        per_agent_cap_usd=0.0,
        spend_provider=lambda _k: 1000.0,
    )
    assert mw._enabled() is False


def test_under_cap_does_not_raise():
    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=10.0,
        per_agent_cap_usd=0.0,
        soft_warn_at_pct=0.7,
        spend_provider=lambda _k: 5.0,
    )

    class _Req:
        state = {"engagement_name": "test"}
        runtime = None

    mw._enforce(_Req())


def test_over_cap_raises_budget_exceeded():
    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=10.0,
        per_agent_cap_usd=0.0,
        spend_provider=lambda _k: 15.0,
    )

    class _Req:
        state = {"engagement_name": "test"}
        runtime = None

    with pytest.raises(BudgetExceeded) as exc_info:
        mw._enforce(_Req())
    assert exc_info.value.scope == "engagement"
    assert exc_info.value.cap_usd == 10.0


def test_per_agent_cap_is_checked_separately():
    spends = {"engagement:test": 1.0, "agent:test:recon": 50.0}
    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=100.0,
        per_agent_cap_usd=10.0,
        spend_provider=spends.get,
    )

    class _RT:
        agent_name = "recon"

    class _Req:
        state = {"engagement_name": "test"}
        runtime = _RT()

    with pytest.raises(BudgetExceeded) as exc_info:
        mw._enforce(_Req())
    assert exc_info.value.scope == "agent"


def test_provider_exception_is_swallowed():
    def _bad_provider(_k):
        raise RuntimeError("postgres down")

    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=10.0,
        per_agent_cap_usd=0.0,
        spend_provider=_bad_provider,
    )

    class _Req:
        state = {"engagement_name": "test"}
        runtime = None

    mw._enforce(_Req())


def test_soft_warn_fires_once_per_scope():
    mw = BudgetEnforcementMiddleware(
        engagement_cap_usd=10.0,
        per_agent_cap_usd=0.0,
        soft_warn_at_pct=0.5,
        spend_provider=lambda _k: 7.0,
    )

    class _Req:
        state = {"engagement_name": "test"}
        runtime = None

    mw._enforce(_Req())
    assert "engagement:engagement:test" in mw._warned_scopes
    mw._enforce(_Req())
    assert len(mw._warned_scopes) == 1
