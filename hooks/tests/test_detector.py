from detector import detect, unwrap_command, scan_offensive_tokens
from parser import ToolInvocation


def test_unwrap_bash_c():
    assert unwrap_command('bash -c "sqlmap -u https://a.com"') == \
           ["sqlmap -u https://a.com"]


def test_unwrap_sh_c():
    assert unwrap_command('sh -c "nuclei -u https://a.com"') == \
           ["nuclei -u https://a.com"]


def test_unwrap_eval():
    assert unwrap_command('eval "sqlmap -u https://a.com"') == \
           ["sqlmap -u https://a.com"]


def test_unwrap_nested_depth_2():
    assert unwrap_command("bash -c \"bash -c 'sqlmap -u https://a.com'\"") == \
           ["sqlmap -u https://a.com"]


def test_unwrap_no_wrapper_passes_through():
    assert unwrap_command("nuclei -u https://a.com") == ["nuclei -u https://a.com"]


def test_unwrap_depth_limit():
    # Profondeur 4 — tronquée à 3, on garde la dernière forme inattaquable.
    cmd = "bash -c \"bash -c 'bash -c \\\"bash -c sqlmap\\\"'\""
    result = unwrap_command(cmd)
    assert isinstance(result, list)


def test_scan_finds_tool_in_pipe():
    assert "nuclei" in scan_offensive_tokens('echo "nuclei -u evil.com" | bash')


def test_scan_finds_tool_in_xargs():
    assert "nuclei" in scan_offensive_tokens("xargs -I{} nuclei -u {}")


def test_scan_finds_tool_with_path():
    # /usr/local/bin/sqlmap -> on extrait basename
    assert "sqlmap" in scan_offensive_tokens("/usr/local/bin/sqlmap -u x")


def test_scan_finds_tool_in_echo_false_positive():
    # Faux positif assumé : echo nuclei → DENY plutôt qu'ALLOW
    assert "nuclei" in scan_offensive_tokens("echo nuclei is cool")


def test_scan_handles_unbalanced_quotes():
    # Le scan est regex-based : pas de dépendance à shlex, donc une string
    # mal formée n'empêche pas la détection.
    result = scan_offensive_tokens('echo "unbalanced sqlmap')
    assert "sqlmap" in result


def test_scan_does_not_match_substring():
    # 'xsqlmap', 'sqlmap_v2', 'use-sqlmap-mode' ne doivent PAS matcher.
    assert "sqlmap" not in scan_offensive_tokens("xsqlmap arg")
    assert "sqlmap" not in scan_offensive_tokens("sqlmap_v2 arg")
    assert "sqlmap" not in scan_offensive_tokens("use-sqlmap-mode arg")


def test_detect_bash_c_returns_real_invocation():
    invs = detect('bash -c "sqlmap -u https://a.com"')
    assert len(invs) == 1
    assert invs[0].tool == "sqlmap"
    assert invs[0].targets == ["https://a.com"]


def test_detect_falls_back_to_lexical():
    invs = detect("xargs -I{} nuclei -u {}")
    assert len(invs) == 1
    assert invs[0].tool == "nuclei"
    assert invs[0].targets == []  # pas de target → DENY côté gate


def test_detect_returns_empty_for_inert_text():
    assert detect("cat README.md") == []


def test_detect_timeout_wrapper_via_lexical():
    # timeout n'est pas dans WRAPPER_TOOLS — fallback scan attrape sqlmap
    invs = detect("timeout 60 sqlmap -u https://a.com")
    assert len(invs) == 1 and invs[0].tool == "sqlmap"
    assert invs[0].targets == []
