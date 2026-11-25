"""Unit tests for consolidated AssetResolver, macro substitution, and fallback behavior."""

from pathlib import Path

import pytest

from ether.gateway.gate import ActionGateway
from ether.registry import assets
from ether.registry.assets import (
    DEFAULT_WORDLIST_NAME,
    WORDLIST_MACRO_REGEX,
    AssetNotFoundError,
    resolve_wordlist,
    substitute_wordlist_macros,
)


@pytest.mark.fast
def test_resolve_wordlist_direct_and_prefix_stripping(tmp_path):
    custom_file = tmp_path / "my_custom_list.txt"
    custom_file.write_text("endpoint1\nendpoint2\n", encoding="utf-8")

    assert resolve_wordlist(str(custom_file), search_roots=[]) == custom_file
    assert resolve_wordlist(f"-w {custom_file}", search_roots=[]) == custom_file
    assert resolve_wordlist(f"@{custom_file}", search_roots=[]) == custom_file
    assert resolve_wordlist(f"wordlist:{custom_file}", search_roots=[]) == custom_file


@pytest.mark.fast
def test_resolve_wordlist_env_var(tmp_path, monkeypatch):
    env_dir = tmp_path / "env_wordlists"
    env_dir.mkdir()
    target_wl = env_dir / "custom_dirs.txt"
    target_wl.write_text("admin\nlogin\n", encoding="utf-8")

    monkeypatch.setenv("ETHER_WORDLISTS_DIR", str(env_dir))

    assert resolve_wordlist("custom_dirs", search_roots=[], data_dir=str(tmp_path / "data")) == target_wl
    assert resolve_wordlist("custom_dirs.txt", search_roots=[], data_dir=str(tmp_path / "data")) == target_wl


@pytest.mark.fast
def test_resolve_wordlist_injectable_search_roots(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHER_WORDLISTS_DIR", raising=False)
    root_dir = tmp_path / "seclists"
    nested = root_dir / "Discovery" / "Web-Content"
    nested.mkdir(parents=True)
    wl = nested / "subdomains_500.txt"
    wl.write_text("www\napi\n", encoding="utf-8")

    resolved = resolve_wordlist(
        "{wordlist:subdomains_500}",
        data_dir=str(tmp_path / "empty_data"),
        search_roots=[root_dir],
    )
    assert resolved == wl


@pytest.mark.fast
def test_resolve_wordlist_data_dir_tier(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHER_WORDLISTS_DIR", raising=False)
    data_dir = tmp_path / "ether_data"
    wl_dir = data_dir / "wordlists"
    wl_dir.mkdir(parents=True)
    wl = wl_dir / f"{DEFAULT_WORDLIST_NAME}.txt"
    wl.write_text("index\nrobots.txt\n", encoding="utf-8")

    resolved = resolve_wordlist(
        "{wordlist}",
        data_dir=str(data_dir),
        search_roots=[],
    )
    assert resolved == wl


@pytest.mark.fast
def test_resolve_wordlist_minimal_fallback_and_not_found(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHER_WORDLISTS_DIR", raising=False)

    # Empty spec or unknown name falls back to embedded minimal.txt
    p_empty = resolve_wordlist("", data_dir=str(tmp_path), search_roots=[])
    assert p_empty.name == "minimal.txt"
    assert p_empty.is_file()

    p_unknown = resolve_wordlist("nonexistent_list_xyz", data_dir=str(tmp_path), search_roots=[])
    assert p_unknown.name == "minimal.txt"
    assert p_unknown.is_file()

    # When allow_fallback=False or embedded minimal.txt is missing -> AssetNotFoundError
    with pytest.raises(AssetNotFoundError):
        resolve_wordlist(
            "nonexistent_list_xyz",
            data_dir=str(tmp_path),
            search_roots=[],
            allow_fallback=False,
        )

    monkeypatch.setattr(assets, "EMBEDDED_MINIMAL_WORDLIST", tmp_path / "missing_minimal.txt")
    with pytest.raises(AssetNotFoundError):
        resolve_wordlist("nonexistent_list_xyz", data_dir=str(tmp_path), search_roots=[])


@pytest.mark.fast
def test_substitute_wordlist_macros(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHER_WORDLISTS_DIR", raising=False)
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    common = roots_dir / f"{DEFAULT_WORDLIST_NAME}.txt"
    common.write_text("admin\n", encoding="utf-8")
    params_wl = roots_dir / "common_params.txt"
    params_wl.write_text("id\n", encoding="utf-8")

    assert WORDLIST_MACRO_REGEX.search("-w {wordlist}") is not None

    cmd = "gobuster dir -u http://127.0.0.1 -w {wordlist}"
    res_cmd, resolved = substitute_wordlist_macros(
        cmd, data_dir=str(tmp_path), search_roots=[roots_dir]
    )
    assert "{wordlist}" not in res_cmd
    assert str(common) in res_cmd
    assert resolved == [str(common)]

    cmd_named = "ffuf -u http://127.0.0.1 -w {wordlist:common_params}"
    res_named, resolved_named = substitute_wordlist_macros(
        cmd_named, data_dir=str(tmp_path), search_roots=[roots_dir]
    )
    assert "{wordlist:common_params}" not in res_named
    assert str(params_wl) in res_named
    assert resolved_named == [str(params_wl)]

    override = tmp_path / "override.txt"
    override.write_text("custom\n", encoding="utf-8")
    res_ov, resolved_ov = substitute_wordlist_macros(
        cmd, user_override=str(override), data_dir=str(tmp_path), search_roots=[roots_dir]
    )
    assert str(override) in res_ov
    assert resolved_ov == [str(override)]


@pytest.mark.fast
def test_action_gateway_resolves_wordlist():
    vars_dict = ActionGateway.resolve_entity_variables()
    assert "WORDLIST" in vars_dict
    assert Path(vars_dict["WORDLIST"]).is_file()
