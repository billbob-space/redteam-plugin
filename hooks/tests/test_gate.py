import pytest

from scope_gate import decide, Decision


@pytest.fixture
def engagement_dir(tmp_path, sample_scope_path):
    eng = tmp_path / "engagements" / "acme-corp"
    eng.mkdir(parents=True)
    (eng / "scope.yaml").write_text(sample_scope_path.read_text())
    return eng


def test_unknown_command_allowed(engagement_dir):
    d = decide(
        command="ls -la",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "allow"
    assert "non offens" in d.reason.lower()


def test_passive_tool_always_allowed(engagement_dir):
    d = decide("subfinder -d acme-corp.com", cwd=str(engagement_dir), env={})
    assert d.permission == "allow"


def test_in_scope_active_light_allowed(engagement_dir):
    d = decide(
        "nuclei -u https://app.acme-corp.com/ -severity info,low",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "allow"


def test_out_of_scope_denied(engagement_dir):
    d = decide(
        "nuclei -u https://evil.com/",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "deny"
    assert "scope" in d.reason.lower()


def test_naabu_out_of_scope_denied(engagement_dir):
    d = decide(
        "naabu -host evil-not-in-scope.example -p 1-65535",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "deny"


def test_naabu_in_scope_allowed(engagement_dir):
    d = decide(
        "naabu -host scan.acme-corp.com -p 80,443",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "allow"


def test_rpcinfo_out_of_scope_denied(engagement_dir):
    d = decide(
        "rpcinfo -p portmap.evil.example",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "deny"


def test_intrusive_asks(engagement_dir):
    d = decide(
        "sqlmap -u https://app.acme-corp.com/contact --batch",
        cwd=str(engagement_dir),
        env={},
    )
    assert d.permission == "ask"


def test_intrusive_pre_approved_allowed(engagement_dir):
    d = decide(
        "sqlmap -u https://app.acme-corp.com/login --batch",
        cwd=str(engagement_dir),
        env={},
        now_iso="2099-01-01T12:00:00+00:00",
    )
    assert d.permission == "allow"


def test_no_engagement_dir_allows_anything(tmp_path):
    d = decide("sqlmap -u https://anything.com", cwd=str(tmp_path), env={})
    assert d.permission == "allow"


def test_env_override_client(tmp_path, sample_scope_path):
    eng = tmp_path / "engagements" / "acme-corp"
    eng.mkdir(parents=True)
    (eng / "scope.yaml").write_text(sample_scope_path.read_text())
    d = decide(
        "sqlmap -u https://evil.com",
        cwd=str(tmp_path),
        env={"REDTEAM_CLIENT": "acme-corp", "REDTEAM_ROOT": str(tmp_path)},
    )
    assert d.permission == "deny"


def test_unparseable_target_fails_closed(engagement_dir):
    d = decide("nuclei -l hosts.txt", cwd=str(engagement_dir), env={})
    assert d.permission == "deny"


import json
from datetime import datetime, timezone
import yaml as _yaml


def test_bash_c_wrapper_blocks_out_of_scope(engagement_dir):
    d = decide(
        'bash -c "sqlmap -u https://evil.com"',
        cwd=str(engagement_dir), env={},
    )
    assert d.permission == "deny"
    assert "scope" in d.reason.lower()


def test_bash_c_wrapper_asks_for_in_scope_intrusive(engagement_dir):
    d = decide(
        'bash -c "sqlmap -u https://app.acme-corp.com/contact --batch"',
        cwd=str(engagement_dir), env={},
    )
    assert d.permission == "ask"


def test_pipe_into_bash_blocked_by_lexical(engagement_dir):
    d = decide(
        'echo "nuclei -u https://evil.com" | bash',
        cwd=str(engagement_dir), env={},
    )
    assert d.permission == "deny"
    assert "sans cible" in d.reason.lower()


def test_recon_artifact_file_allowed(engagement_dir):
    recon = engagement_dir / "recon"
    recon.mkdir()
    hosts = recon / "subdomains.txt"
    hosts.write_text("app.acme-corp.com\n")
    d = decide(
        f"nuclei -l {hosts} -severity low",
        cwd=str(engagement_dir), env={},
    )
    assert d.permission == "allow"


def test_random_hosts_file_denied(engagement_dir, tmp_path):
    outside = tmp_path / "evil.txt"
    outside.write_text("x")
    d = decide(
        f"nuclei -l {outside}",
        cwd=str(engagement_dir), env={},
    )
    assert d.permission == "deny"


def test_dangerous_flag_without_approval_asks(engagement_dir):
    # /login est déjà approuvé (sample), mais sans --os-shell dans approved_flags
    d = decide(
        "sqlmap -u https://app.acme-corp.com/login --os-shell",
        cwd=str(engagement_dir), env={},
        now_iso="2099-01-01T12:00:00+00:00",
    )
    assert d.permission == "ask"
    assert "--os-shell" in d.reason


def test_dangerous_flag_with_approval_allows(engagement_dir):
    # Ajouter une approbation avec --os-shell explicite
    scope_yaml = engagement_dir / "scope.yaml"
    raw = _yaml.safe_load(scope_yaml.read_text())
    raw["intrusive_actions"].append({
        "tool": "sqlmap",
        "target": "https://app.acme-corp.com/admin",
        "approved_at": "2099-01-01T00:00:00+00:00",
        "approved_by": "operator",
        "approved_flags": ["--os-shell"],
    })
    scope_yaml.write_text(_yaml.safe_dump(raw, sort_keys=False))
    d = decide(
        "sqlmap -u https://app.acme-corp.com/admin --os-shell --batch",
        cwd=str(engagement_dir), env={},
        now_iso="2099-01-01T12:00:00+00:00",
    )
    assert d.permission == "allow"


def test_json_malformed_fails_closed():
    import io, sys, scope_gate
    saved_stdin = sys.stdin
    saved_stdout = sys.stdout
    sys.stdin = io.StringIO("not json {")
    sys.stdout = io.StringIO()
    try:
        rc = scope_gate.main()
        out = sys.stdout.getvalue()
    finally:
        sys.stdin = saved_stdin
        sys.stdout = saved_stdout
    assert rc == 0
    parsed = json.loads(out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_logs_pre_entry_for_bash_tool(engagement_dir):
    import io, sys, scope_gate
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "subfinder -d acme-corp.com"},
        "cwd": str(engagement_dir),
    }
    saved_in, saved_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        scope_gate.main()
    finally:
        sys.stdin, sys.stdout = saved_in, saved_out
    audit = engagement_dir / "audit.jsonl"
    assert audit.exists()
    rec = json.loads(audit.read_text().splitlines()[0])
    assert rec["phase"] == "pre"
    assert rec["decision"] in ("allow", "deny", "ask")
    assert rec["cmd_sha256"]


def test_main_audit_corrupted_fails_closed(engagement_dir):
    import io, sys, scope_gate
    (engagement_dir / "audit.jsonl").write_text(
        '{"ts":"x","phase":"pre","hash":"' + 'a'*64 + '"}\nGARBAGE NOT JSON\n'
    )
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "subfinder -d acme-corp.com"},
        "cwd": str(engagement_dir),
    }
    saved_in, saved_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        scope_gate.main()
        out = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = saved_in, saved_out
    parsed = json.loads(out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "audit log" in parsed["hookSpecificOutput"]["permissionDecisionReason"].lower()
