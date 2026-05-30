"""FastAPI REST app for Skillogy — the supported transport.

REST endpoints (named after the proto's RPC methods):
- ``POST /v1/skills:list``        -> ListSkills
- ``POST /v1/skills:load``        -> LoadSkill
- ``POST /v1/skills:ingest``      -> IngestSkill
- ``GET  /v1/health``             -> Health
- ``GET  /openapi.json``          -> generated OpenAPI 3.1 schema

A gRPC transport is sketched in ``skillogy.proto`` but is not yet wired
(no protoc-generated bindings), so ``build_grpc_server`` raises and the
service falls back to REST — see that function's docstring. The REST app
runs standalone without grpcio so the CLI / test paths don't require the
heavier dependency.
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from dataclasses import asdict
from typing import Any

from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillListRequest,
)
from decepticon.skillogy.server.registry import SkillRegistry

log = logging.getLogger(__name__)


def _envelope_to_payload(env: SkillEnvelope, include_refs: bool, include_scripts: bool) -> dict:
    return {
        "meta": asdict(env.meta),
        "body": env.body,
        "references": {k: v.decode("utf-8", errors="replace") for k, v in env.references.items()}
        if include_refs
        else {},
        "scripts": {k: v.decode("utf-8", errors="replace") for k, v in env.scripts.items()}
        if include_scripts
        else {},
    }


try:
    from pydantic import BaseModel
except ImportError:
    BaseModel = None  # type: ignore[assignment,misc]


if BaseModel is not None:

    class ListReq(BaseModel):
        subdomain_filter: list[str] = []
        tag_filter: list[str] = []
        mitre_filter: list[str] = []
        include_safety_critical: bool = True
        include_gated: bool = True
        page_size: int = 100
        page_token: str = ""

    class LoadReq(BaseModel):
        path: str
        include_references: bool = True
        include_scripts: bool = True

    class IngestReq(BaseModel):
        path: str
        body: str
        references: dict[str, str] = {}
        scripts: dict[str, str] = {}


def build_app(
    registry: SkillRegistry,
    *,
    started_at: float | None = None,
    api_key: str | None = None,
):
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Skillogy server requires FastAPI + Pydantic. Install with: "
            "pip install fastapi pydantic uvicorn"
        ) from exc

    _expected_key: str | None = (
        api_key if api_key is not None else os.environ.get("SKILLOGY_API_KEY")
    )

    async def _require_key(authorization: str | None = Header(default=None)) -> None:
        if _expected_key is None:
            return
        token = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(token, _expected_key):
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    _protected = [Depends(_require_key)]

    app = FastAPI(
        title="Skillogy",
        version="0.1.0",
        description="Decepticon skill catalog service. Speaks REST and gRPC.",
    )
    boot_time = started_at or time.time()

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "skill_count": len(registry),
            "uptime_seconds": int(time.time() - boot_time),
        }

    @app.post("/v1/skills:list", dependencies=_protected)
    async def list_skills(req: ListReq) -> dict[str, Any]:
        resp = registry.list(
            SkillListRequest(
                subdomain_filter=req.subdomain_filter,
                tag_filter=req.tag_filter,
                mitre_filter=req.mitre_filter,
                include_safety_critical=req.include_safety_critical,
                include_gated=req.include_gated,
                page_size=req.page_size,
                page_token=req.page_token,
            )
        )
        return {
            "skills": [asdict(s) for s in resp.skills],
            "next_page_token": resp.next_page_token,
            "total_count": resp.total_count,
        }

    @app.post("/v1/skills:load", dependencies=_protected)
    async def load_skill(req: LoadReq) -> dict[str, Any]:
        env = registry.load(req.path)
        if env is None:
            raise HTTPException(status_code=404, detail=f"skill not found: {req.path}")
        return {"skill": _envelope_to_payload(env, req.include_references, req.include_scripts)}

    @app.post("/v1/skills:ingest", dependencies=_protected)
    async def ingest_skill(req: IngestReq) -> dict[str, Any]:
        refs = {k: v.encode("utf-8") for k, v in req.references.items()}
        scripts = {k: v.encode("utf-8") for k, v in req.scripts.items()}
        resp = registry.ingest(req.path, req.body, references=refs, scripts=scripts)
        return asdict(resp)

    return app


def build_grpc_server(registry: SkillRegistry, *, port: int = 50051):
    """The gRPC transport is not wired yet — this always raises ``RuntimeError``.

    Skillogy ships a hand-rolled ``skillogy.proto`` but no ``protoc``-generated
    bindings, so there is no servicer registrar (``add_*Servicer_to_server``)
    and no message (de)serializers. A ``grpc.Server`` constructed here would
    bind ``port`` yet answer every RPC with ``UNIMPLEMENTED`` — a silent dead
    port that *looks* healthy. Until codegen is wired into the build, **REST is
    the only supported transport** (``build_app`` + ``RestSkillogyClient``);
    ``decepticon.skillogy.__main__._start_grpc`` already catches this
    ``RuntimeError`` and serves REST only.

    ``registry`` and ``port`` are accepted so this stays signature-compatible
    with its single call site and the future protoc-backed implementation.
    """
    raise RuntimeError(
        "Skillogy gRPC transport is not wired: skillogy.proto has no "
        "protoc-generated bindings, so the server would register no servicer "
        "and could not (de)serialize messages. Use the REST transport — "
        "build_app(registry) served by uvicorn, with RestSkillogyClient."
    )
