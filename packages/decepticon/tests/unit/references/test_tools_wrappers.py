from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, cast

import pytest

from decepticon.tools.references import tools as T
from decepticon.tools.references.catalog import REFERENCES, references_by_category
from decepticon.tools.references.hydrate import HydrationResult
from decepticon.tools.references.payloads import PayloadBundle

_ref_list = cast(Any, T.ref_list)
_ref_suggest = cast(Any, T.ref_suggest)
_ref_topic = cast(Any, T.ref_topic)
_ref_fetch = cast(Any, T.ref_fetch)
_ref_status = cast(Any, T.ref_status)
_ref_grep = cast(Any, T.ref_grep)
_payload_search = cast(Any, T.payload_search)
_payload_classes = cast(Any, T.payload_classes)
_references_hydrate = cast(Any, T.references_hydrate)
_h1_search = cast(Any, T.h1_search)


def _load(result: str) -> Any:
    data = json.loads(result)
    if isinstance(data, dict) and data.get("trust") == "untrusted-external-corpus":
        return data.get("data", {})
    return data


class TestSanitizeCorpusText:
    def test_empty_string_returns_empty_immediately(self) -> None:
        assert T._sanitize_corpus_text("") == ""

    def test_control_chars_stripped_but_whitespace_kept(self) -> None:
        result = T._sanitize_corpus_text("a\x00b\x07c\tdone\n")
        assert result == "abc\tdone\n"

    def test_truncation_branch_appends_suffix(self) -> None:
        result = T._sanitize_corpus_text("x" * 50, limit=10)
        assert result.startswith("x" * 10)
        assert result.endswith("…[truncated by corpus sanitiser]")


class TestWrapCorpus:
    def test_envelope_shape_and_values(self) -> None:
        result = T._wrap_corpus("src", {"k": 1})
        assert result["source"] == "src"
        assert result["trust"] == "untrusted-external-corpus"
        assert result["notice"] == T._UNTRUSTED_HEADER
        assert result["data"] == {"k": 1}


class TestRefList:
    def test_all_branch_returns_full_catalog(self) -> None:
        data = json.loads(_ref_list.invoke({}))
        assert data["count"] == len(REFERENCES)
        assert data["count"] == len(data["references"])
        slugs = {r["slug"] for r in data["references"]}
        assert "hackerone-reports" in slugs

    def test_category_filter_branch_returns_subset(self) -> None:
        category = "report-corpus"
        expected = references_by_category(category)
        data = json.loads(_ref_list.invoke({"category": category}))
        assert data["count"] == len(expected)
        assert all(r["category"] == category for r in data["references"])

    def test_nonexistent_category_returns_empty(self) -> None:
        data = json.loads(_ref_list.invoke({"category": "nonexistent-cat"}))
        assert data["count"] == 0
        assert data["references"] == []


class TestRefSuggest:
    def test_vuln_class_branch_returns_results(self) -> None:
        data = json.loads(_ref_suggest.invoke({"vuln_class": "ssrf"}))
        assert data["count"] > 0

    def test_goal_branch_returns_results(self) -> None:
        data = json.loads(_ref_suggest.invoke({"goal": "recon"}))
        assert data["count"] > 0


class TestRefTopic:
    def test_known_topic_returns_matching_entries(self) -> None:
        data = json.loads(_ref_topic.invoke({"topic": "ssrf"}))
        assert data["topic"] == "ssrf"
        assert data["count"] >= 0

    def test_unknown_topic_returns_zero_count(self) -> None:
        data = json.loads(_ref_topic.invoke({"topic": "nonexistent-topic-xyz999"}))
        assert data["count"] == 0
        assert data["references"] == []


@dataclass
class _FakeCacheStatus:
    slug: str
    present: bool
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"slug": self.slug, "present": self.present, "size_bytes": self.size_bytes}


class TestRefFetch:
    def test_success_branch_returns_status_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeCacheStatus(slug="hackerone-reports", present=True, size_bytes=123)
        monkeypatch.setattr(T, "ensure_cached", lambda slug: fake)
        data = json.loads(_ref_fetch.invoke({"slug": "hackerone-reports"}))
        assert "error" not in data
        assert data["slug"] == "hackerone-reports"
        assert data["present"] is True

    def test_keyerror_branch_returns_error_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(slug: str) -> _FakeCacheStatus:
            raise KeyError("unknown reference slug: bogus")

        monkeypatch.setattr(T, "ensure_cached", _raise)
        data = json.loads(_ref_fetch.invoke({"slug": "bogus"}))
        assert "error" in data
        assert "unknown reference slug" in data["error"]


class TestRefStatus:
    def test_single_slug_success_branch(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        monkeypatch.setenv("DECEPTICON_REFERENCES_ROOT", str(tmp_path))
        fake = _FakeCacheStatus(slug="hackerone-reports", present=False, size_bytes=0)
        monkeypatch.setattr(T, "cache_status", lambda slug: fake)
        data = json.loads(_ref_status.invoke({"slug": "hackerone-reports"}))
        assert "error" not in data
        assert data["slug"] == "hackerone-reports"
        assert data["present"] is False

    def test_single_slug_keyerror_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(slug: str) -> _FakeCacheStatus:
            raise KeyError("unknown reference slug: bogus")

        monkeypatch.setattr(T, "cache_status", _raise)
        data = json.loads(_ref_status.invoke({"slug": "bogus"}))
        assert "error" in data

    def test_full_map_branch_returns_all_slugs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count: list[str] = []

        def _fake_cache_status(slug: str) -> _FakeCacheStatus:
            call_count.append(slug)
            return _FakeCacheStatus(slug=slug, present=False, size_bytes=0)

        monkeypatch.setattr(T, "cache_status", _fake_cache_status)
        data = json.loads(_ref_status.invoke({}))
        assert data["count"] == len(REFERENCES)
        assert all("slug" in row for row in data["cache"])
        assert len(call_count) == len(REFERENCES)


class TestRefGrep:
    def test_pattern_too_long_returns_error(self) -> None:
        data = json.loads(_ref_grep.invoke({"slug": "hackerone-reports", "pattern": "a" * 201}))
        assert data["ok"] is False
        assert data["error"] == "pattern too long (>200 chars)"

    def test_keyerror_branch_returns_ok_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(slug: str, pattern: str, **kwargs: Any) -> list[Any]:
            raise KeyError("unknown reference slug: bogus")

        monkeypatch.setattr(T, "search_cache", _raise)
        data = json.loads(_ref_grep.invoke({"slug": "bogus", "pattern": "x"}))
        assert data["ok"] is False
        assert "unknown reference slug" in data["error"]

    def test_success_branch_wraps_envelope_and_sanitizes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw_snip = "hit \x00line one" * 30
        monkeypatch.setattr(
            T, "search_cache", lambda slug, pattern, **kw: [("file.md", 7, raw_snip)]
        )
        outer = json.loads(_ref_grep.invoke({"slug": "hackerone-reports", "pattern": "hit"}))
        assert outer["trust"] == "untrusted-external-corpus"
        assert outer["source"] == "hackerone-reports"
        data = outer["data"]
        assert data["count"] == 1
        assert data["hits"][0]["file"] == "file.md"
        assert data["hits"][0]["line"] == 7
        snippet = data["hits"][0]["snippet"]
        assert "\x00" not in snippet
        assert len(snippet) <= 240 + len("\n\n…[truncated by corpus sanitiser]")


class TestPayloadSearchFallback:
    def test_fallback_branch_when_search_merged_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_payload = PayloadBundle(
            vuln_class="ssrf",
            title="SSRF basic",
            payload="http://169.254.169.254/",
        )
        monkeypatch.setattr(T, "search_merged", lambda **kw: [])
        monkeypatch.setattr(T, "search_payloads", lambda **kw: [fake_payload])
        data = json.loads(_payload_search.invoke({"vuln_class": "ssrf"}))
        assert data["count"] == 1
        assert data["payloads"][0]["vuln_class"] == "ssrf"

    def test_no_fallback_when_search_merged_returns_results(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_payload = PayloadBundle(
            vuln_class="ssrf",
            title="SSRF merged",
            payload="http://169.254.169.254/",
        )

        sentinel_called: list[bool] = []

        def _guard(**kw: Any) -> list[Any]:
            sentinel_called.append(True)
            return []

        monkeypatch.setattr(T, "search_merged", lambda **kw: [fake_payload])
        monkeypatch.setattr(T, "search_payloads", _guard)
        data = json.loads(_payload_search.invoke({"keyword": "imds"}))
        assert data["count"] == 1
        assert not sentinel_called


class TestPayloadClassesBundledFallback:
    def test_bundled_fallback_when_merged_payloads_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(T, "merged_payloads", lambda: [])
        data = json.loads(_payload_classes.invoke({}))
        assert data["count"] > 0
        classes = {c["vuln_class"] for c in data["classes"]}
        assert "ssrf" in classes


class TestReferencesHydrate:
    def test_success_branch_returns_report_and_results(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_result = HydrationResult(
            slug="hackerone-reports", ok=True, present=True, size_bytes=999
        )
        monkeypatch.setattr(T, "hydrate_all", lambda: [fake_result])
        monkeypatch.setattr(T, "format_report", lambda results: "REPORT")
        data = json.loads(_references_hydrate.invoke({}))
        assert data["report"] == "REPORT"
        assert len(data["results"]) == 1
        assert data["results"][0]["slug"] == "hackerone-reports"


class TestH1SearchTitleSanitization:
    def test_control_char_in_title_stripped_in_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from decepticon.tools.references.h1_corpus import BugReport

        fake_report = BugReport(title="evil\x07title", bounty=100.0)
        monkeypatch.setattr(T, "h1_search_corpus", lambda **kw: [fake_report])
        outer = json.loads(_h1_search.invoke({"keyword": "x"}))
        data = outer["data"]
        assert data["reports"][0]["title"] == "eviltitle"
