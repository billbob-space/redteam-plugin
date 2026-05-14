from datetime import datetime, timezone

import pytest
from scope import Scope, ScopeResult, load_scope


def test_load_scope(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.client == "acme-corp"


def test_target_in_scope_wildcard(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("app.acme-corp.com") is ScopeResult.IN
    assert scope.contains("foo.bar.acme-corp.com") is ScopeResult.IN


def test_target_in_scope_exact(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("api.acme.io") is ScopeResult.IN


def test_target_out_of_scope_overrides(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("blog.acme-corp.com") is ScopeResult.OUT


def test_target_unknown(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("evil.com") is ScopeResult.OUT


def test_url_target_resolves_to_host(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("https://app.acme-corp.com/login") is ScopeResult.IN


def test_cidr_in_scope(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("203.0.113.42") is ScopeResult.IN


def test_cidr_excluded(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("203.0.113.5") is ScopeResult.OUT


def test_window_valid(sample_scope_path):
    scope = load_scope(sample_scope_path)
    now = datetime(2050, 1, 1, tzinfo=timezone.utc)
    assert scope.window_open(now=now) is True


def test_window_expired(sample_scope_path):
    scope = load_scope(sample_scope_path)
    now = datetime(2100, 1, 2, tzinfo=timezone.utc)
    assert scope.window_open(now=now) is False


def test_window_not_yet_open(sample_scope_path):
    scope = load_scope(sample_scope_path)
    now = datetime(2025, 12, 31, tzinfo=timezone.utc)
    assert scope.window_open(now=now) is False


def test_unparseable_target_returns_unknown(sample_scope_path):
    scope = load_scope(sample_scope_path)
    assert scope.contains("@file:hosts.txt") is ScopeResult.UNKNOWN


from scope import is_recon_artifact_file


def test_recon_artifact_file_exists_under_recon(tmp_path):
    eng = tmp_path
    (eng / "recon").mkdir()
    p = eng / "recon" / "subdomains.txt"
    p.write_text("a.com\nb.com\n")
    assert is_recon_artifact_file(f"@file:{p}", eng) is True


def test_recon_artifact_file_does_not_exist(tmp_path):
    eng = tmp_path
    (eng / "recon").mkdir()
    assert is_recon_artifact_file(f"@file:{eng}/recon/missing.txt", eng) is False


def test_recon_artifact_file_outside_recon_dir(tmp_path):
    eng = tmp_path
    (eng / "recon").mkdir()
    other = tmp_path / "other.txt"
    other.write_text("x")
    assert is_recon_artifact_file(f"@file:{other}", eng) is False


def test_recon_artifact_file_traversal_blocked(tmp_path):
    eng = tmp_path
    (eng / "recon").mkdir()
    outside = tmp_path / "evil.txt"
    outside.write_text("y")
    # resolve doit sortir du recon dir et bloquer
    assert is_recon_artifact_file(f"@file:{eng}/recon/../evil.txt", eng) is False


def test_recon_artifact_file_non_file_marker(tmp_path):
    assert is_recon_artifact_file("https://a.com", tmp_path) is False


def test_recon_artifact_symlink_escape_blocked(tmp_path):
    """Un symlink dans recon/ pointant hors recon/ ne doit PAS être whitelisté."""
    eng = tmp_path
    (eng / "recon").mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("s")
    sym = eng / "recon" / "link.txt"
    sym.symlink_to(outside)
    assert is_recon_artifact_file(f"@file:{sym}", eng) is False
