from __future__ import annotations

import json
from typing import Any

import pytest

from decepticon.tools.research import _state as state
from decepticon.tools.research import tools as research_tools
from decepticon.tools.research.dedupe import (
    DuplicateVerdict,
    find_duplicate,
    prefilter,
)
from decepticon_core.types.kg import KnowledgeGraph, Node, NodeKind


class _FakeStore:
    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph
        self.upsert_node_calls = 0
        self.upsert_edge_calls = 0

    def load_graph(self) -> KnowledgeGraph:
        return self.graph.model_copy(deep=True)

    def batch_upsert_nodes(self, nodes: list[Node]) -> int:
        for n in nodes:
            self.graph.upsert_node(n)
            self.upsert_node_calls += 1
        return len(nodes)

    def batch_upsert_edges(self, edges: list[Any]) -> int:
        for e in edges:
            self.graph.upsert_edge(e)
            self.upsert_edge_calls += 1
        return len(edges)

    def ensure_schema(self) -> None:
        pass

    def close(self) -> None:
        pass

    def stats(self) -> dict[str, int]:
        return self.graph.stats()


def _sqli_finding(label: str, host: str, *, cwe: str = "CWE-89", **extra: Any) -> Node:
    return Node.make(
        NodeKind.VULNERABILITY,
        label,
        key=f"vuln::{label}",
        host=host,
        cwe=[cwe],
        severity="high",
        **extra,
    )


def _same_bug_graph() -> KnowledgeGraph:
    graph = KnowledgeGraph()
    graph.upsert_node(
        _sqli_finding(
            "SQL injection in login form",
            "api.example.com",
            message="error-based SQLi on /login id param",
        )
    )
    graph.upsert_node(
        _sqli_finding(
            "Database injection via authentication endpoint",
            "https://API.example.com:443/login",
            message="union-based injection reachable from auth flow",
        )
    )
    return graph


def _distinct_pair_graph() -> KnowledgeGraph:
    graph = KnowledgeGraph()
    graph.upsert_node(_sqli_finding("SQL injection in login form", "api.example.com"))
    graph.upsert_node(
        Node.make(
            NodeKind.VULNERABILITY,
            "Reflected XSS in search box",
            key="vuln::xss-search",
            host="shop.other-site.net",
            cwe=["CWE-79"],
            severity="medium",
        )
    )
    return graph


def _always_duplicate(_a: Node, _b: Node) -> dict[str, Any]:
    return {"is_duplicate": True, "reason": "same root cause"}


def _never_duplicate(_a: Node, _b: Node) -> dict[str, Any]:
    return {"is_duplicate": False, "reason": "unrelated"}


def _exploding_judge(_a: Node, _b: Node) -> dict[str, Any]:
    raise AssertionError("judge must not be called when prefilter rejects")


def _configure_store(monkeypatch: pytest.MonkeyPatch, graph: KnowledgeGraph) -> _FakeStore:
    fake = _FakeStore(graph)
    monkeypatch.setattr(state, "_store", fake)
    return fake


class TestPrefilter:
    def test_pairs_same_host_and_cwe_findings(self) -> None:
        nodes = list(_same_bug_graph().nodes.values())
        assert prefilter(nodes[0], nodes[1]) is True

    def test_rejects_distinct_findings(self) -> None:
        nodes = list(_distinct_pair_graph().nodes.values())
        assert prefilter(nodes[0], nodes[1]) is False

    def test_rejects_identical_node(self) -> None:
        node = _sqli_finding("SQL injection in login form", "api.example.com")
        assert prefilter(node, node) is False

    def test_rejects_non_finding_kinds(self) -> None:
        a = Node.make(NodeKind.HOST, "api.example.com", host="api.example.com")
        b = Node.make(NodeKind.HOST, "api.example.com", key="other", host="api.example.com")
        assert prefilter(a, b) is False

    def test_endpoint_overlap_without_explicit_host(self) -> None:
        a = Node.make(
            NodeKind.FINDING,
            "IDOR on order endpoint",
            key="f::a",
            url="https://shop.example.com/api/orders/1?token=aaa",
        )
        b = Node.make(
            NodeKind.FINDING,
            "Broken access control reading orders",
            key="f::b",
            url="http://shop.example.com/api/orders/1?token=bbb",
        )
        assert prefilter(a, b) is True


class TestFindDuplicate:
    def test_returns_duplicate_when_judge_confirms(self) -> None:
        nodes = list(_same_bug_graph().nodes.values())
        verdict = find_duplicate(nodes[1], [nodes[0]], _always_duplicate)
        assert isinstance(verdict, DuplicateVerdict)
        assert verdict.is_duplicate is True
        assert verdict.canonical_id == nodes[0].id
        assert verdict.reason == "same root cause"

    def test_returns_not_duplicate_when_judge_rejects(self) -> None:
        nodes = list(_same_bug_graph().nodes.values())
        verdict = find_duplicate(nodes[1], [nodes[0]], _never_duplicate)
        assert verdict.is_duplicate is False
        assert verdict.canonical_id is None
        assert verdict.reason == "judge rejected all candidates"

    def test_distinct_findings_skip_judge_entirely(self) -> None:
        nodes = list(_distinct_pair_graph().nodes.values())
        verdict = find_duplicate(nodes[1], [nodes[0]], _exploding_judge)
        assert verdict.is_duplicate is False
        assert verdict.canonical_id is None
        assert verdict.reason == "no prefilter candidates"

    def test_empty_existing_returns_not_duplicate(self) -> None:
        node = _sqli_finding("SQL injection in login form", "api.example.com")
        verdict = find_duplicate(node, [], _exploding_judge)
        assert verdict.is_duplicate is False
        assert verdict.reason == "no prefilter candidates"


class TestKgDedupeFindingsTool:
    def test_reports_duplicate_cluster_for_same_bug(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _configure_store(monkeypatch, _same_bug_graph())

        payload = json.loads(research_tools.kg_dedupe_findings.invoke({}))

        assert payload["scanned_findings"] == 2
        assert payload["duplicate_clusters"] == 1
        assert payload["duplicate_nodes"] == 2
        cluster = payload["clusters"][0]
        assert cluster["size"] == 2
        assert cluster["host"] == "api.example.com"
        assert cluster["cwes"] == ["CWE-89"]
        member_ids = {m["id"] for m in cluster["members"]}
        assert member_ids == set(fake.graph.nodes.keys())

    def test_reports_no_clusters_for_distinct_findings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_store(monkeypatch, _distinct_pair_graph())

        payload = json.loads(research_tools.kg_dedupe_findings.invoke({}))

        assert payload["scanned_findings"] == 2
        assert payload["duplicate_clusters"] == 0
        assert payload["duplicate_nodes"] == 0
        assert payload["clusters"] == []

    def test_does_not_mutate_graph(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _configure_store(monkeypatch, _same_bug_graph())
        before_nodes = {nid: n.model_copy(deep=True) for nid, n in fake.graph.nodes.items()}
        before_edge_count = len(fake.graph.edges)

        research_tools.kg_dedupe_findings.invoke({})

        assert set(fake.graph.nodes.keys()) == set(before_nodes.keys())
        assert len(fake.graph.edges) == before_edge_count
        for nid, original in before_nodes.items():
            assert fake.graph.nodes[nid].props == original.props
            assert fake.graph.nodes[nid].label == original.label


class TestRegistry:
    def test_tool_is_registered_in_research_tools(self) -> None:
        names = {getattr(t, "name", None) for t in research_tools.RESEARCH_TOOLS}
        assert "kg_dedupe_findings" in names
