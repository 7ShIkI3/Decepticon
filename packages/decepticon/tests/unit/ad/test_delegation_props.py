from __future__ import annotations

from decepticon.tools.ad.bloodhound import merge_bloodhound_json
from decepticon.tools.ad.delegation import analyze_delegation
from decepticon_core.types.kg import KnowledgeGraph


def _bh_computer(sid: str, name: str, **extra_props: object) -> dict:
    return {
        "ObjectIdentifier": sid,
        "Properties": {"name": name, "domain": "CORP.LOCAL", **extra_props},
        "Aces": [],
        "MemberOf": [],
        "AllowedToDelegate": [],
        "AllowedToActOnBehalfOfOtherIdentity": [],
    }


def test_trustedfordelegation_prop_produces_unconstrained_finding() -> None:
    bh = {
        "meta": {"type": "computers"},
        "data": [
            _bh_computer(
                "S-1-5-21-1-1-1-2001",
                "WEB01.CORP.LOCAL",
                trustedfordelegation=True,
            )
        ],
    }
    g = KnowledgeGraph()
    merge_bloodhound_json(bh, g)

    node = next(
        (n for n in g.nodes.values() if "WEB01" in n.label),
        None,
    )
    assert node is not None, "computer node not created"
    assert node.props.get("trustedfordelegation") is True, (
        "trustedfordelegation was not stored on the node — Pass 1 would always skip"
    )

    findings = analyze_delegation(g)
    assert any(f.delegation_type == "unconstrained" and "WEB01" in f.target for f in findings), (
        "unconstrained delegation finding not emitted despite trustedfordelegation=True"
    )


def test_allowed_to_delegate_array_produces_constrained_finding() -> None:
    src_sid = "S-1-5-21-1-1-1-3001"
    dst_sid = "S-1-5-21-1-1-1-3002"
    bh_src = {
        "ObjectIdentifier": src_sid,
        "Properties": {"name": "SVC01.CORP.LOCAL", "domain": "CORP.LOCAL"},
        "Aces": [],
        "MemberOf": [],
        "AllowedToDelegate": [{"ObjectIdentifier": dst_sid, "Value": "cifs/DC01.CORP.LOCAL"}],
        "AllowedToActOnBehalfOfOtherIdentity": [],
    }
    bh_dst = _bh_computer(dst_sid, "DC01.CORP.LOCAL")
    bh = {
        "meta": {"type": "computers"},
        "data": [bh_src, bh_dst],
    }
    g = KnowledgeGraph()
    stats = merge_bloodhound_json(bh, g)

    assert stats.edges >= 1, "no delegation edge created"
    deleg_edges = [e for e in g.edges.values() if e.props.get("bh_right") == "AllowedToDelegate"]
    assert len(deleg_edges) == 1, f"expected 1 AllowedToDelegate edge, got {len(deleg_edges)}"

    findings = analyze_delegation(g)
    assert any(f.delegation_type == "constrained" for f in findings), (
        "constrained delegation finding not emitted despite AllowedToDelegate edge"
    )


def test_allowed_to_act_array_produces_rbcd_finding() -> None:
    actor_sid = "S-1-5-21-1-1-1-4001"
    target_sid = "S-1-5-21-1-1-1-4002"
    bh_target = {
        "ObjectIdentifier": target_sid,
        "Properties": {"name": "FILESRV.CORP.LOCAL", "domain": "CORP.LOCAL"},
        "Aces": [],
        "MemberOf": [],
        "AllowedToDelegate": [],
        "AllowedToActOnBehalfOfOtherIdentity": [{"ObjectIdentifier": actor_sid}],
    }
    bh_actor = _bh_computer(actor_sid, "ACTOR.CORP.LOCAL")
    bh = {
        "meta": {"type": "computers"},
        "data": [bh_target, bh_actor],
    }
    g = KnowledgeGraph()
    stats = merge_bloodhound_json(bh, g)

    assert stats.edges >= 1
    rbcd_edges = [e for e in g.edges.values() if e.props.get("bh_right") == "AllowedToAct"]
    assert len(rbcd_edges) == 1, f"expected 1 AllowedToAct edge, got {len(rbcd_edges)}"

    findings = analyze_delegation(g)
    assert any(f.delegation_type == "rbcd" for f in findings), (
        "RBCD finding not emitted despite AllowedToActOnBehalfOfOtherIdentity edge"
    )
