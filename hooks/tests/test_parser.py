from parser import parse_command, ToolInvocation


def test_simple_subfinder():
    invs = parse_command("subfinder -d acme-corp.com")
    assert len(invs) == 1
    assert invs[0].tool == "subfinder"
    assert invs[0].targets == ["acme-corp.com"]


def test_nuclei_with_url():
    invs = parse_command("nuclei -u https://app.acme-corp.com/")
    assert invs == [ToolInvocation("nuclei", ["https://app.acme-corp.com/"], ["-u"])]


def test_pipeline():
    invs = parse_command("subfinder -d acme-corp.com | httpx -silent")
    tools = [i.tool for i in invs]
    assert tools == ["subfinder", "httpx"]
    assert invs[0].targets == ["acme-corp.com"]
    # httpx without -u/-l has no explicit target, gets pipeline input
    assert invs[1].targets == []


def test_ignore_unknown_command():
    invs = parse_command("ls -la /tmp")
    assert invs == []


def test_sqlmap_url():
    invs = parse_command('sqlmap -u "https://app.acme-corp.com/login?id=1" --batch')
    assert len(invs) == 1
    assert invs[0].tool == "sqlmap"
    assert invs[0].targets == ["https://app.acme-corp.com/login?id=1"]


def test_chained_with_and():
    invs = parse_command("nuclei -u https://a.com && nuclei -u https://b.com")
    assert len(invs) == 2
    assert invs[0].targets == ["https://a.com"]
    assert invs[1].targets == ["https://b.com"]


def test_ffuf_url_with_fuzz():
    invs = parse_command("ffuf -u https://app.acme-corp.com/FUZZ -w wordlist.txt")
    assert invs[0].tool == "ffuf"
    assert invs[0].targets == ["https://app.acme-corp.com/FUZZ"]


def test_unparseable_returns_empty():
    invs = parse_command('echo "unbalanced quote')
    assert invs == []


def test_target_list_file_is_marker():
    invs = parse_command("nuclei -l hosts.txt")
    assert invs[0].tool == "nuclei"
    assert invs[0].targets == ["@file:hosts.txt"]


def test_threads_flag_preserved():
    invs = parse_command("ffuf -u https://a.com/FUZZ -t 50 -w w.txt")
    assert "-t" in invs[0].flags


def test_naabu_host_flag():
    invs = parse_command("naabu -host scan.acme-corp.com -p 1-1000")
    assert len(invs) == 1
    assert invs[0].tool == "naabu"
    assert invs[0].targets == ["scan.acme-corp.com"]


def test_naabu_list_flag():
    invs = parse_command("naabu -list hosts.txt -p 80,443")
    assert len(invs) == 1
    assert invs[0].tool == "naabu"
    assert invs[0].targets == ["@file:hosts.txt"]


def test_rpcinfo_positional_host():
    invs = parse_command("rpcinfo -p portmap.acme-corp.com")
    assert len(invs) == 1
    assert invs[0].tool == "rpcinfo"
    assert "portmap.acme-corp.com" in invs[0].targets
