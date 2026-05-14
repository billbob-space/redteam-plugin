from datetime import datetime, timedelta, timezone

import yaml
import pytest

from approval import (
    is_approved,
    append_approval,
    find_dangerous_flags,
    normalize_target,
    ApprovalResult,
    APPROVAL_TTL_HOURS,
)
from scope import load_scope


# --- Tests réécrits depuis l'ancien is_already_approved ---

def test_approved_within_ttl(sample_scope_path):
    scope = load_scope(sample_scope_path)
    r = is_approved(
        scope,
        tool="sqlmap",
        target="https://app.acme-corp.com/login",
        now=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.APPROVED


def test_not_approved_for_different_target(sample_scope_path):
    scope = load_scope(sample_scope_path)
    r = is_approved(
        scope,
        tool="sqlmap",
        target="https://app.acme-corp.com/admin",
        now=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.NOT_APPROVED


def test_approval_expires_after_ttl(sample_scope_path):
    scope = load_scope(sample_scope_path)
    later = datetime(2099, 1, 1, 0, 0, tzinfo=timezone.utc) + timedelta(hours=APPROVAL_TTL_HOURS + 1)
    r = is_approved(
        scope,
        tool="sqlmap",
        target="https://app.acme-corp.com/login",
        now=later,
    )
    assert r is ApprovalResult.NOT_APPROVED


def test_append_approval_writes_to_yaml(tmp_path, sample_scope_path):
    target_file = tmp_path / "scope.yaml"
    target_file.write_text(sample_scope_path.read_text())
    scope = load_scope(target_file)
    append_approval(
        scope,
        tool="commix",
        target="https://app.acme-corp.com/feedback",
        approved_by="operator",
        approved_at=datetime(2050, 6, 1, tzinfo=timezone.utc),
    )
    reloaded = yaml.safe_load(target_file.read_text())
    found = [a for a in reloaded["intrusive_actions"] if a["tool"] == "commix"]
    assert len(found) == 1
    assert found[0]["target"] == "https://app.acme-corp.com/feedback"
    assert found[0]["approved_at"] == "2050-06-01T00:00:00+00:00"


# --- Nouveaux tests : normalize_target ---

def test_normalize_target_drops_query():
    assert normalize_target("https://app.acme/login?id=1") == "https://app.acme/login"


def test_normalize_target_lowercases_host():
    assert normalize_target("https://APP.ACME/Login") == "https://app.acme/Login"


def test_normalize_target_drops_trailing_slash():
    assert normalize_target("https://app.acme/login/") == "https://app.acme/login"


def test_normalize_target_passthrough_for_file():
    assert normalize_target("@file:hosts.txt") == "@file:hosts.txt"


def test_normalize_target_idempotent_on_bare_host():
    assert normalize_target("Example.COM/") == "example.com"


# --- Nouveaux tests : find_dangerous_flags ---

def test_find_dangerous_flags_sqlmap():
    assert find_dangerous_flags("sqlmap", ["--os-shell", "--batch"]) == ["--os-shell"]


def test_find_dangerous_flags_nuclei_always_empty():
    assert find_dangerous_flags("nuclei", ["-severity", "critical"]) == []


def test_find_dangerous_flags_unknown_tool_empty():
    assert find_dangerous_flags("unknown", ["--anything"]) == []


# --- Nouveaux tests : is_approved avec granularité ---

def test_approved_handles_query_difference(sample_scope_path):
    """Approve /login (sample), run /login?id=2 → APPROVED via normalize."""
    scope = load_scope(sample_scope_path)
    r = is_approved(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/login?id=2",
        now=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.APPROVED


def test_insufficient_scope_when_dangerous_flag_uncovered(sample_scope_path):
    scope = load_scope(sample_scope_path)
    r = is_approved(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/login",
        used_dangerous_flags=["--os-shell"],
        now=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.INSUFFICIENT_SCOPE


def test_approved_when_dangerous_flag_explicitly_covered(tmp_path, sample_scope_path):
    target_file = tmp_path / "scope.yaml"
    target_file.write_text(sample_scope_path.read_text())
    scope = load_scope(target_file)
    append_approval(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/admin",
        approved_by="operator",
        approved_flags=["--os-shell"],
        approved_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    scope = load_scope(target_file)
    r = is_approved(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/admin",
        used_dangerous_flags=["--os-shell"],
        now=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.APPROVED


def test_insufficient_when_only_subset_of_flags_covered(tmp_path, sample_scope_path):
    target_file = tmp_path / "scope.yaml"
    target_file.write_text(sample_scope_path.read_text())
    scope = load_scope(target_file)
    append_approval(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/admin",
        approved_by="operator",
        approved_flags=["--os-shell"],
        approved_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    scope = load_scope(target_file)
    r = is_approved(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/admin",
        used_dangerous_flags=["--os-shell", "--dump-all"],
        now=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert r is ApprovalResult.INSUFFICIENT_SCOPE


def test_append_approval_writes_approved_flags_field(tmp_path, sample_scope_path):
    target_file = tmp_path / "scope.yaml"
    target_file.write_text(sample_scope_path.read_text())
    scope = load_scope(target_file)
    append_approval(
        scope, tool="sqlmap",
        target="https://app.acme-corp.com/x",
        approved_by="op",
        approved_flags=["--os-shell"],
        approved_at=datetime(2050, 1, 1, tzinfo=timezone.utc),
    )
    reloaded = yaml.safe_load(target_file.read_text())
    new_entry = [a for a in reloaded["intrusive_actions"] if a["target"].endswith("/x")][0]
    assert new_entry["approved_flags"] == ["--os-shell"]


def test_find_dangerous_flags_handles_equals_form():
    """--dump=users doit être détecté comme dangereux (couvre la base --dump)."""
    result = find_dangerous_flags("sqlmap", ["--dump=users", "--batch"])
    assert result == ["--dump=users"]


def test_find_dangerous_flags_equals_form_for_value_taking():
    """Tous les flags value-taking (--file-write, --eval, etc.) en forme =value."""
    flags = ["--file-write=/tmp/x", "--eval=print(1)", "--os-cmd=id"]
    result = find_dangerous_flags("sqlmap", flags)
    assert result == flags  # tous détectés


def test_normalize_target_preserves_port():
    """Le port est préservé : :8443 != :9999 != pas de port."""
    assert normalize_target("https://app.com:8443/login") == "https://app.com:8443/login"
    assert normalize_target("https://app.com:9999/login") == "https://app.com:9999/login"
    assert normalize_target("https://app.com/login") == "https://app.com/login"
