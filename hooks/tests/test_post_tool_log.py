import io
import json
import sys
from datetime import datetime, timezone

import pytest

import post_tool_log
import audit_log


@pytest.fixture
def engagement_dir(tmp_path, sample_scope_path):
    eng = tmp_path / "engagements" / "acme-corp"
    eng.mkdir(parents=True)
    (eng / "scope.yaml").write_text(sample_scope_path.read_text())
    return eng


def _run(payload: dict) -> int:
    saved_in, saved_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        return post_tool_log.main()
    finally:
        sys.stdin, sys.stdout = saved_in, saved_out


def test_non_bash_tool_does_nothing(engagement_dir):
    rc = _run({"tool_name": "Read", "tool_input": {"path": "x"}, "cwd": str(engagement_dir)})
    assert rc == 0
    assert not (engagement_dir / "audit.jsonl").exists()


def test_logs_post_entry(engagement_dir):
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "subfinder -d acme-corp.com"},
        "tool_response": {"exit_code": 0, "stderr": ""},
        "cwd": str(engagement_dir),
    }
    _run(payload)
    rec = json.loads((engagement_dir / "audit.jsonl").read_text().splitlines()[-1])
    assert rec["phase"] == "post"
    assert rec["exit_code"] == 0
    assert rec["pre_missing"] is True  # pas de pre matchant


def test_links_to_pre_via_cmd_sha256(engagement_dir):
    cmd = "subfinder -d acme-corp.com"
    # Écrire un pre d'abord
    import hashlib
    cmd_sha = hashlib.sha256(cmd.encode()).hexdigest()
    audit_log.append(engagement_dir, {
        "ts": "2026-05-13T00:00:00+00:00",
        "phase": "pre",
        "cmd_sha256": cmd_sha,
        "decision": "allow",
    })
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "tool_response": {"exit_code": 0, "stderr": ""},
        "cwd": str(engagement_dir),
    }
    _run(payload)
    lines = (engagement_dir / "audit.jsonl").read_text().splitlines()
    post = json.loads(lines[-1])
    assert post["phase"] == "post"
    assert post["pre_missing"] is False
    assert post["cmd_sha256"] == cmd_sha
    assert post["duration_s"] is not None and post["duration_s"] > 0


def test_stderr_tail_truncated_to_200(engagement_dir):
    long = "X" * 500
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_response": {"exit_code": 1, "stderr": long},
        "cwd": str(engagement_dir),
    }
    _run(payload)
    rec = json.loads((engagement_dir / "audit.jsonl").read_text().splitlines()[-1])
    # ls n'est pas un outil offensif → pas d'engagement match… en fait si,
    # on est dans engagement_dir/, donc l'engagement EST trouvé, et le post
    # est loggé indépendamment de la nature de la commande.
    assert len(rec["stderr_tail"]) == 200


def test_no_engagement_no_log(tmp_path):
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_response": {"exit_code": 0, "stderr": ""},
        "cwd": str(tmp_path),
    }
    _run(payload)
    assert not (tmp_path / "audit.jsonl").exists()


def test_json_malformed_silent(tmp_path):
    saved_in, saved_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO("not json")
    sys.stdout = io.StringIO()
    try:
        rc = post_tool_log.main()
    finally:
        sys.stdin, sys.stdout = saved_in, saved_out
    assert rc == 0
