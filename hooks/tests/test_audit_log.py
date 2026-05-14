import json
from pathlib import Path

import pytest

from audit_log import (
    append,
    verify_chain,
    find_last_pre,
    AuditChainCorrupted,
    _compute_hash,
)

ZERO_HASH = "0" * 64


def test_compute_hash_deterministic():
    rec = {"a": 1, "b": "x"}
    h1 = _compute_hash(rec, ZERO_HASH)
    h2 = _compute_hash(rec, ZERO_HASH)
    assert h1 == h2 and len(h1) == 64


def test_compute_hash_changes_with_prev():
    rec = {"a": 1}
    assert _compute_hash(rec, ZERO_HASH) != _compute_hash(rec, "f" * 64)


def test_append_to_new_file(tmp_path):
    eng = tmp_path
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre", "decision": "allow"})
    lines = (eng / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["prev_hash"] == ZERO_HASH
    assert len(rec["hash"]) == 64
    assert rec["decision"] == "allow"


def test_append_sequential_chain(tmp_path):
    eng = tmp_path
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre", "i": 0})
    append(eng, {"ts": "2026-05-13T00:00:01+00:00", "phase": "pre", "i": 1})
    append(eng, {"ts": "2026-05-13T00:00:02+00:00", "phase": "pre", "i": 2})
    lines = (eng / "audit.jsonl").read_text().splitlines()
    recs = [json.loads(l) for l in lines]
    assert recs[0]["prev_hash"] == ZERO_HASH
    assert recs[1]["prev_hash"] == recs[0]["hash"]
    assert recs[2]["prev_hash"] == recs[1]["hash"]


def test_verify_chain_ok(tmp_path):
    eng = tmp_path
    for i in range(3):
        append(eng, {"ts": f"2026-05-13T00:00:0{i}+00:00", "phase": "pre", "i": i})
    ok, n = verify_chain(eng / "audit.jsonl")
    assert ok is True and n == 3


def test_verify_chain_detects_tampering(tmp_path):
    eng = tmp_path
    for i in range(3):
        append(eng, {"ts": f"2026-05-13T00:00:0{i}+00:00", "phase": "pre", "i": i})
    p = eng / "audit.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["i"] = 99
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, n = verify_chain(p)
    assert ok is False and n == 1


def test_verify_chain_on_missing_file(tmp_path):
    ok, n = verify_chain(tmp_path / "audit.jsonl")
    assert ok is True and n == 0


def test_append_raises_on_corrupted_last_line(tmp_path):
    eng = tmp_path
    p = eng / "audit.jsonl"
    p.write_text('{"ts":"x","phase":"pre"}\nnot-json\n')
    with pytest.raises(AuditChainCorrupted):
        append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre"})


def test_append_raises_on_missing_ts(tmp_path):
    with pytest.raises(ValueError):
        append(tmp_path, {"phase": "pre"})


def test_find_last_pre_matches(tmp_path):
    eng = tmp_path
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre",
                 "cmd_sha256": "abc", "decision": "allow"})
    rec = find_last_pre(eng, "abc")
    assert rec is not None and rec["decision"] == "allow"


def test_find_last_pre_ignores_post(tmp_path):
    eng = tmp_path
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre",
                 "cmd_sha256": "abc", "decision": "allow"})
    append(eng, {"ts": "2026-05-13T00:00:01+00:00", "phase": "post",
                 "cmd_sha256": "abc", "exit_code": 0})
    rec = find_last_pre(eng, "abc")
    assert rec["phase"] == "pre"


def test_find_last_pre_returns_none_if_no_match(tmp_path):
    eng = tmp_path
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre",
                 "cmd_sha256": "abc"})
    assert find_last_pre(eng, "zzz") is None


def test_find_last_pre_on_missing_file(tmp_path):
    assert find_last_pre(tmp_path, "abc") is None


def test_append_handles_record_larger_than_initial_window(tmp_path):
    eng = tmp_path
    # Premier record avec un champ blob de ~5000 octets (> fenêtre initiale de 4096)
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre", "blob": "x" * 5000})
    # Le second append ne doit pas lever AuditChainCorrupted
    append(eng, {"ts": "2026-05-13T00:00:01+00:00", "phase": "pre", "i": 1})
    lines = [l for l in (eng / "audit.jsonl").read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    # Les deux lignes doivent être du JSON valide
    recs = [json.loads(l) for l in lines]
    assert recs[0]["blob"] == "x" * 5000
    assert recs[1]["i"] == 1
    # La chaîne doit être intègre
    ok, n = verify_chain(eng / "audit.jsonl")
    assert ok is True and n == 2


def test_append_recovers_from_missing_trailing_newline(tmp_path):
    eng = tmp_path
    p = eng / "audit.jsonl"
    # Écrire un premier record valide SANS \n final (simule une troncature)
    append(eng, {"ts": "2026-05-13T00:00:00+00:00", "phase": "pre", "i": 0})
    content = p.read_bytes()
    assert content.endswith(b"\n")
    # Retirer le \n final pour simuler un write tronqué
    p.write_bytes(content.rstrip(b"\n"))
    assert not p.read_bytes().endswith(b"\n")
    # Le second append doit réussir et produire une chaîne valide
    append(eng, {"ts": "2026-05-13T00:00:01+00:00", "phase": "pre", "i": 1})
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    # Les deux lignes doivent être du JSON valide
    recs = [json.loads(l) for l in lines]
    assert recs[0]["i"] == 0
    assert recs[1]["i"] == 1
    ok, n = verify_chain(p)
    assert ok is True and n == 2
