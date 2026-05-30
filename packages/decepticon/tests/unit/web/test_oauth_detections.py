"""Detection-branch coverage for ``decepticon.tools.web.oauth``.

``analyze_oauth_callback`` is an offline OAuth 2.0 / OIDC flow auditor. Each
uncovered branch is a *vulnerability detection rule* — a regression there is
a silent **false negative** (a real OAuth bug the agent fails to report
during an engagement). This pins the detections the existing suite left
uncovered: OIDC nonce-missing, code-in-fragment, weak/plain PKCE,
redirect_uri path-traversal + userinfo confusion, and the state-strength
branches.

Pure-logic; no network / docker / LLM.
"""

from __future__ import annotations

from decepticon.tools.web.oauth import OAuthFinding, analyze_oauth_callback

# A 48-char hex state: length >= 32 and high entropy, so a callback carrying
# it produces no state-missing / state-short / low-entropy noise — isolating
# whichever detection a test actually targets.
_GOOD_STATE = "0123456789abcdef0123456789abcdef0123456789abcdef"


def _ids(findings: list[OAuthFinding]) -> set[str]:
    return {f.id for f in findings}


# ---------------------------------------------------------------- dataclass


def test_oauth_finding_to_dict_roundtrips_fields():
    f = OAuthFinding(id="x", severity="high", title="t", detail="d", recommendation="r")
    assert f.to_dict() == {
        "id": "x",
        "severity": "high",
        "title": "t",
        "detail": "d",
        "recommendation": "r",
    }


# ---------------------------------------------------------------- OIDC nonce


def test_oidc_nonce_missing_flagged_when_openid_without_nonce():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url="https://as/authorize?response_type=code&scope=openid+profile",
    )
    assert "oidc.nonce-missing" in _ids(findings)


def test_oidc_nonce_present_is_not_flagged():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url=("https://as/authorize?response_type=code&scope=openid&nonce=n-9f3a2b"),
    )
    assert "oidc.nonce-missing" not in _ids(findings)


def test_non_oidc_scope_does_not_trigger_nonce_check():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url="https://as/authorize?response_type=code&scope=profile+email",
    )
    assert "oidc.nonce-missing" not in _ids(findings)


# ---------------------------------------------------------------- code in fragment


def test_code_delivered_in_fragment_is_flagged():
    findings = analyze_oauth_callback(f"https://app/cb#code=abc&state={_GOOD_STATE}")
    assert "oauth.code-in-fragment" in _ids(findings)


def test_code_in_query_is_not_fragment_flagged():
    findings = analyze_oauth_callback(f"https://app/cb?code=abc&state={_GOOD_STATE}")
    assert "oauth.code-in-fragment" not in _ids(findings)


# ---------------------------------------------------------------- PKCE


def test_public_client_without_pkce_flagged():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url="https://as/authorize?response_type=code",
        public_client=True,
    )
    assert "oauth.pkce-missing" in _ids(findings)


def test_public_client_plain_pkce_flagged():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url=(
            "https://as/authorize?response_type=code&code_challenge=XYZ&code_challenge_method=plain"
        ),
        public_client=True,
    )
    assert "oauth.pkce-plain" in _ids(findings)


def test_public_client_s256_pkce_is_clean():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url=(
            "https://as/authorize?response_type=code&code_challenge=XYZ&code_challenge_method=S256"
        ),
        public_client=True,
    )
    ids = _ids(findings)
    assert "oauth.pkce-missing" not in ids
    assert "oauth.pkce-plain" not in ids


# ---------------------------------------------------------------- redirect_uri


def test_redirect_uri_path_traversal_flagged():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url="https://as/authorize?redirect_uri=https://app/../../evil",
    )
    assert "oauth.redirect-uri-traversal" in _ids(findings)


def test_redirect_uri_userinfo_confusion_flagged():
    findings = analyze_oauth_callback(
        f"https://app/cb?code=abc&state={_GOOD_STATE}",
        initial_request_url="https://as/authorize?redirect_uri=https://app@evil.example/cb",
    )
    assert "oauth.redirect-uri-userinfo" in _ids(findings)


# ---------------------------------------------------------------- state strength


def test_short_state_flagged_short_but_not_low_entropy():
    findings = analyze_oauth_callback("https://app/cb?code=abc&state=ab12cd")  # 6 chars
    ids = _ids(findings)
    assert "oauth.state-short" in ids
    assert "oauth.state-low-entropy" not in ids  # 6 distinct chars -> entropy > 2.5


def test_long_low_entropy_state_flagged_low_entropy_not_short():
    findings = analyze_oauth_callback(f"https://app/cb?code=abc&state={'a' * 40}")
    ids = _ids(findings)
    assert "oauth.state-low-entropy" in ids
    assert "oauth.state-short" not in ids  # 40 chars >= 32


def test_strong_state_produces_no_state_findings():
    findings = analyze_oauth_callback(f"https://app/cb?code=abc&state={_GOOD_STATE}")
    ids = _ids(findings)
    assert "oauth.state-missing" not in ids
    assert "oauth.state-short" not in ids
    assert "oauth.state-low-entropy" not in ids
