"""Tests for ``decepticon.tools.skills`` — skill loader tool and its helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from decepticon.tools.skills import (
    _format_skill_body,
    _list_dir_via_backend,
    _read_via_backend,
    _strip_frontmatter,
    _validate_skill_path,
    build_load_skill_tool,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _make_backend(
    *,
    read_result: Any = None,
    read_raises: Exception | None = None,
    ls_result: Any = None,
    ls_raises: Exception | None = None,
) -> Any:
    """Build a minimal fake backend for the protocol used by skills helpers."""

    class FakeBackend:
        def read(self, path: str) -> Any:
            if read_raises is not None:
                raise read_raises
            return read_result

        def ls(self, path: str) -> Any:
            if ls_raises is not None:
                raise ls_raises
            return ls_result

    return FakeBackend()


def _ok_read(content: str | list[str]) -> SimpleNamespace:
    """Build a successful backend read response."""
    return SimpleNamespace(error=None, file_data={"content": content})


def _err_read(error: str) -> SimpleNamespace:
    """Build an errored backend read response."""
    return SimpleNamespace(error=error, file_data=None)


def _ok_ls(entries: list[str]) -> SimpleNamespace:
    """Build a successful backend ls response with the common 'entries' key."""
    return SimpleNamespace(error=None, entries=entries, file_data=None)


# ── _strip_frontmatter ────────────────────────────────────────────────────────


class TestStripFrontmatter:
    def test_no_frontmatter_returns_original(self) -> None:
        text = "# body\nsome content\n"
        body, fm = _strip_frontmatter(text)
        assert body == text
        assert fm == {}

    def test_extracts_flat_key_value_pairs(self) -> None:
        text = "---\nname: my-skill\ndescription: does stuff\n---\n# body\n"
        body, fm = _strip_frontmatter(text)
        assert fm == {"name": "my-skill", "description": "does stuff"}
        assert body == "# body\n"

    def test_strips_double_quotes_from_values(self) -> None:
        text = '---\nname: "quoted-skill"\n---\nbody\n'
        _, fm = _strip_frontmatter(text)
        assert fm["name"] == "quoted-skill"

    def test_strips_single_quotes_from_values(self) -> None:
        text = "---\nname: 'single-quoted'\n---\nbody\n"
        _, fm = _strip_frontmatter(text)
        assert fm["name"] == "single-quoted"

    def test_lines_without_colon_are_ignored(self) -> None:
        text = "---\nname: skill\nno colon here\n---\nbody\n"
        _, fm = _strip_frontmatter(text)
        assert "no colon here" not in fm
        assert fm.get("name") == "skill"

    def test_missing_closing_fence_returns_original(self) -> None:
        text = "---\nname: skill\nbody without closing fence\n"
        body, fm = _strip_frontmatter(text)
        assert body == text
        assert fm == {}

    def test_empty_string_returns_empty(self) -> None:
        body, fm = _strip_frontmatter("")
        assert body == ""
        assert fm == {}

    def test_body_after_frontmatter_preserved_exactly(self) -> None:
        text = "---\nkey: val\n---\nline1\nline2\n"
        body, _ = _strip_frontmatter(text)
        assert body == "line1\nline2\n"

    def test_value_with_colon_partition_keeps_remainder(self) -> None:
        text = "---\nurl: http://example.com/path\n---\nbody\n"
        _, fm = _strip_frontmatter(text)
        # partition on first colon only — value includes the rest
        assert fm["url"] == "http://example.com/path"


# ── _read_via_backend ─────────────────────────────────────────────────────────


class TestReadViaBackend:
    def test_string_content_returned_directly(self) -> None:
        backend = _make_backend(read_result=_ok_read("hello world"))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content == "hello world"
        assert err is None

    def test_list_content_joined_with_newlines(self) -> None:
        backend = _make_backend(read_result=_ok_read(["line1", "line2"]))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content == "line1\nline2"
        assert err is None

    def test_backend_exception_returns_error(self) -> None:
        backend = _make_backend(read_raises=RuntimeError("connection refused"))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content is None
        assert err is not None
        assert "connection refused" in err

    def test_backend_error_attribute_surfaces_as_error(self) -> None:
        backend = _make_backend(read_result=_err_read("not found"))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content is None
        assert "not found" in (err or "")

    def test_none_file_data_returns_error(self) -> None:
        backend = _make_backend(read_result=SimpleNamespace(error=None, file_data=None))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content is None
        assert err is not None

    def test_empty_file_data_dict_returns_error(self) -> None:
        backend = _make_backend(read_result=SimpleNamespace(error=None, file_data={}))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content is None
        assert err is not None

    def test_non_string_non_list_content_returns_error(self) -> None:
        backend = _make_backend(read_result=SimpleNamespace(error=None, file_data={"content": 42}))
        content, err = _read_via_backend(backend, "/skills/x.md")
        assert content is None
        assert err is not None


# ── _list_dir_via_backend ─────────────────────────────────────────────────────


class TestListDirViaBackend:
    def test_returns_sorted_md_entries_from_entries_attr(self) -> None:
        backend = _make_backend(ls_result=_ok_ls(["z.md", "a.md", "b.md"]))
        result = _list_dir_via_backend(backend, "/skills/x/references")
        assert result == ["a.md", "b.md", "z.md"]

    def test_filters_non_md_entries(self) -> None:
        backend = _make_backend(ls_result=_ok_ls(["a.md", "b.txt", "c.py"]))
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == ["a.md"]

    def test_returns_empty_list_on_exception(self) -> None:
        backend = _make_backend(ls_raises=RuntimeError("backend down"))
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == []

    def test_returns_empty_list_on_backend_error_attribute(self) -> None:
        backend = _make_backend(ls_result=SimpleNamespace(error="dir not found", entries=None))
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == []

    def test_falls_back_to_files_attr(self) -> None:
        backend = _make_backend(
            ls_result=SimpleNamespace(error=None, entries=None, files=["a.md", "b.md"], items=None)
        )
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == ["a.md", "b.md"]

    def test_falls_back_to_items_attr(self) -> None:
        backend = _make_backend(
            ls_result=SimpleNamespace(error=None, entries=None, files=None, items=["b.md"])
        )
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == ["b.md"]

    def test_falls_back_to_file_data_entries(self) -> None:
        backend = _make_backend(
            ls_result=SimpleNamespace(
                error=None,
                entries=None,
                files=None,
                items=None,
                file_data={"entries": ["x.md"]},
            )
        )
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == ["x.md"]

    def test_empty_entries_returns_empty(self) -> None:
        backend = _make_backend(ls_result=_ok_ls([]))
        result = _list_dir_via_backend(backend, "/skills/x")
        assert result == []


# ── _validate_skill_path ──────────────────────────────────────────────────────


class TestValidateSkillPath:
    def test_valid_path_no_sources(self) -> None:
        assert _validate_skill_path("/skills/standard/exploit/SKILL.md", []) is None

    def test_non_string_rejected(self) -> None:
        err = _validate_skill_path(None, [])  # type: ignore[arg-type]
        assert err is not None
        assert "non-empty string" in err

    def test_empty_string_rejected(self) -> None:
        err = _validate_skill_path("", [])
        assert err is not None
        assert "non-empty string" in err

    def test_path_not_starting_with_skills_rejected(self) -> None:
        err = _validate_skill_path("/etc/passwd.md", [])
        assert err is not None
        assert "/skills/" in err

    def test_path_not_ending_in_md_rejected(self) -> None:
        err = _validate_skill_path("/skills/standard/SKILL.txt", [])
        assert err is not None
        assert ".md" in err

    def test_path_traversal_rejected(self) -> None:
        err = _validate_skill_path("/skills/../etc/passwd.md", [])
        assert err is not None
        assert "traversal" in err.lower()

    def test_path_traversal_inside_path_rejected(self) -> None:
        err = _validate_skill_path("/skills/standard/../../passwd.md", [])
        assert err is not None

    def test_sources_allowlist_accepts_matching_prefix(self) -> None:
        err = _validate_skill_path(
            "/skills/standard/exploit/SKILL.md",
            ["/skills/standard/"],
        )
        assert err is None

    def test_sources_allowlist_rejects_non_matching(self) -> None:
        err = _validate_skill_path(
            "/skills/shared/SKILL.md",
            ["/skills/standard/"],
        )
        assert err is not None
        assert "/skills/standard/" in err

    def test_sources_empty_list_allows_all(self) -> None:
        assert _validate_skill_path("/skills/anything/SKILL.md", []) is None

    def test_sources_without_trailing_slash_still_matches(self) -> None:
        err = _validate_skill_path(
            "/skills/standard/SKILL.md",
            ["/skills/standard"],
        )
        assert err is None


# ── _format_skill_body ────────────────────────────────────────────────────────


class TestFormatSkillBody:
    def test_base_dir_extracted_from_path(self) -> None:
        _, base_dir, _ = _format_skill_body("/skills/standard/exploit/SKILL.md", "# body\n")
        assert base_dir == "/skills/standard/exploit"

    def test_basename_extracted_from_path(self) -> None:
        _, _, basename = _format_skill_body("/skills/standard/exploit/SKILL.md", "# body\n")
        assert basename == "SKILL.md"

    def test_frontmatter_stripped_from_body(self) -> None:
        raw = "---\nname: my-skill\n---\n# body content\n"
        sections, _, _ = _format_skill_body("/skills/x/SKILL.md", raw)
        full = "\n".join(sections)
        assert "name: my-skill" not in full
        assert "# body content" in full

    def test_header_contains_base_dir(self) -> None:
        sections, _, _ = _format_skill_body("/skills/std/exploit/SKILL.md", "body\n")
        header = sections[0]
        assert "Base directory for this skill: /skills/std/exploit" in header

    def test_header_uses_frontmatter_name(self) -> None:
        raw = "---\nname: Fancy Skill\n---\nbody\n"
        sections, _, _ = _format_skill_body("/skills/x/stem.md", raw)
        header = sections[0]
        assert "Fancy Skill" in header

    def test_header_falls_back_to_stem_when_no_name(self) -> None:
        sections, _, _ = _format_skill_body("/skills/x/cool-tool.md", "body\n")
        header = sections[0]
        assert "cool-tool" in header

    def test_description_appended_when_present(self) -> None:
        raw = "---\nname: MySk\ndescription: does cool things\n---\nbody\n"
        sections, _, _ = _format_skill_body("/skills/x/SKILL.md", raw)
        header = sections[0]
        assert "does cool things" in header

    def test_description_omitted_when_absent(self) -> None:
        raw = "---\nname: MySk\n---\nbody\n"
        sections, _, _ = _format_skill_body("/skills/x/SKILL.md", raw)
        header = sections[0]
        assert "—" not in header

    def test_sections_end_with_empty_string(self) -> None:
        sections, _, _ = _format_skill_body("/skills/x/SKILL.md", "body\n")
        assert sections[-1] == ""


# ── build_load_skill_tool (integration of the full tool) ─────────────────────


class TestBuildLoadSkillTool:
    """Test the tool returned by ``build_load_skill_tool``."""

    def _make_tool(self, raw_content: str, sources: list[str] | None = None) -> Any:
        backend = _make_backend(
            read_result=_ok_read(raw_content),
            ls_result=_ok_ls([]),
        )
        return build_load_skill_tool(backend, sources or [])

    def test_returns_invokable_tool(self) -> None:
        tool = self._make_tool("body\n")
        # LangChain @tool returns a StructuredTool — not callable() but has .invoke()
        assert hasattr(tool, "invoke")

    def test_happy_path_returns_skill_body(self) -> None:
        tool = self._make_tool("---\nname: test\n---\n# Hello\n")
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert "# Hello" in result
        assert "Base directory" in result

    def test_output_ends_with_newline(self) -> None:
        tool = self._make_tool("body\n")
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert result.endswith("\n")

    def test_invalid_path_returns_error_string(self) -> None:
        tool = self._make_tool("body\n")
        result = tool.invoke({"skill_path": "not-valid"})
        assert result.startswith("[load_skill error]")

    def test_non_md_path_returns_error_string(self) -> None:
        tool = self._make_tool("body\n")
        result = tool.invoke({"skill_path": "/skills/standard/file.txt"})
        assert "[load_skill error]" in result

    def test_path_traversal_returns_error_string(self) -> None:
        tool = self._make_tool("body\n")
        result = tool.invoke({"skill_path": "/skills/../etc/passwd.md"})
        assert "[load_skill error]" in result

    def test_backend_error_returns_not_found_message(self) -> None:
        backend = _make_backend(read_result=_err_read("404"))
        tool = build_load_skill_tool(backend, [])
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert "[load_skill error]" in result
        assert "Skill not found" in result

    def test_references_included_when_present(self) -> None:
        backend = _make_backend(
            read_result=_ok_read("body\n"),
            ls_result=_ok_ls(["cheatsheet.md", "template.md"]),
        )
        tool = build_load_skill_tool(backend, [])
        result = tool.invoke({"skill_path": "/skills/standard/exploit/SKILL.md"})
        assert "References" in result
        assert "cheatsheet.md" in result
        assert "template.md" in result

    def test_no_references_section_when_empty(self) -> None:
        tool = self._make_tool("body\n")
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert "References" not in result

    def test_include_siblings_false_omits_siblings(self) -> None:
        backend = _make_backend(
            read_result=_ok_read("body\n"),
            ls_result=_ok_ls(["other.md"]),
        )
        tool = build_load_skill_tool(backend, [])
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md", "include_siblings": False})
        # references dir is separate from base dir — tool lists references, not siblings
        # with include_siblings=False the sibling section is absent
        assert "Related sub-skills" not in result

    def test_include_siblings_true_adds_siblings_section(self) -> None:
        call_args: list[str] = []

        class TrackingBackend:
            def read(self, path: str) -> Any:
                return _ok_read("body\n")

            def ls(self, path: str) -> Any:
                call_args.append(path)
                # Return siblings for base_dir, nothing for references dir
                if "references" in path:
                    return _ok_ls([])
                return _ok_ls(["SKILL.md", "other-skill.md"])

        tool = build_load_skill_tool(TrackingBackend(), [])
        result = tool.invoke(
            {
                "skill_path": "/skills/standard/exploit/SKILL.md",
                "include_siblings": True,
            }
        )
        assert "Related sub-skills" in result
        assert "other-skill.md" in result

    def test_sources_allowlist_enforced(self) -> None:
        tool = self._make_tool("body\n", sources=["/skills/standard/"])
        result = tool.invoke({"skill_path": "/skills/shared/SKILL.md"})
        assert "[load_skill error]" in result

    def test_sources_allowlist_passes_matching(self) -> None:
        tool = self._make_tool("body\n", sources=["/skills/standard/"])
        result = tool.invoke({"skill_path": "/skills/standard/exploit/SKILL.md"})
        assert "[load_skill error]" not in result

    def test_backend_exception_propagates_as_error_string(self) -> None:
        backend = _make_backend(read_raises=ConnectionError("network down"))
        tool = build_load_skill_tool(backend, [])
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert "[load_skill error]" in result
        assert "Skill not found" in result

    def test_list_content_format_accepted(self) -> None:
        backend = _make_backend(
            read_result=_ok_read(["# line one", "line two"]),
            ls_result=_ok_ls([]),
        )
        tool = build_load_skill_tool(backend, [])
        result = tool.invoke({"skill_path": "/skills/standard/SKILL.md"})
        assert "# line one" in result
        assert "line two" in result
