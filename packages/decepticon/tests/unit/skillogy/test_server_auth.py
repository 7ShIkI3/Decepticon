from __future__ import annotations

import pytest

from decepticon.skillogy.server.app import build_app
from decepticon.skillogy.server.registry import SkillRegistry

_SKILL_BODY = "---\nname: s1\ndescription: test\n---\nbody"


@pytest.fixture()
def _reg():
    reg = SkillRegistry()
    reg.ingest("/skills/s1/SKILL.md", _SKILL_BODY)
    return reg


@pytest.fixture()
def open_client(_reg):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    return TestClient(build_app(_reg))


@pytest.fixture()
def authed_client(_reg):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    return TestClient(build_app(_reg, api_key="test-secret"))


def test_no_key_configured_allows_ingest(open_client):
    r = open_client.post("/v1/skills:ingest", json={"path": "/x", "body": _SKILL_BODY})
    assert r.status_code == 200


def test_no_key_configured_allows_list(open_client):
    r = open_client.post("/v1/skills:list", json={})
    assert r.status_code == 200


def test_missing_token_blocked_on_ingest(authed_client):
    r = authed_client.post("/v1/skills:ingest", json={"path": "/x", "body": _SKILL_BODY})
    assert r.status_code == 401


def test_missing_token_blocked_on_list(authed_client):
    r = authed_client.post("/v1/skills:list", json={})
    assert r.status_code == 401


def test_missing_token_blocked_on_load(authed_client):
    r = authed_client.post("/v1/skills:load", json={"path": "/skills/s1/SKILL.md"})
    assert r.status_code == 401


def test_wrong_token_blocked(authed_client):
    r = authed_client.post(
        "/v1/skills:ingest",
        json={"path": "/x", "body": _SKILL_BODY},
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert r.status_code == 401


def test_correct_token_allows_ingest(authed_client):
    r = authed_client.post(
        "/v1/skills:ingest",
        json={"path": "/x", "body": _SKILL_BODY},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 200


def test_correct_token_allows_list(authed_client):
    r = authed_client.post(
        "/v1/skills:list",
        json={},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 200


def test_correct_token_allows_load(authed_client):
    r = authed_client.post(
        "/v1/skills:load",
        json={"path": "/skills/s1/SKILL.md"},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 200


def test_health_always_open(authed_client):
    r = authed_client.get("/v1/health")
    assert r.status_code == 200
