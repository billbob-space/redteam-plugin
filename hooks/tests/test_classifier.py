from parser import ToolInvocation
from classifier import Category, classify


def test_passive_tools():
    assert classify(ToolInvocation("subfinder", ["acme.com"], [])) is Category.PASSIVE
    assert classify(ToolInvocation("dnsx", [], [])) is Category.PASSIVE
    assert classify(ToolInvocation("gau", ["acme.com"], [])) is Category.PASSIVE


def test_httpx_default_passive():
    assert classify(ToolInvocation("httpx", [], ["-silent"])) is Category.PASSIVE


def test_httpx_with_fr_is_active():
    assert classify(ToolInvocation("httpx", [], ["-fr"])) is Category.ACTIVE_LIGHT


def test_active_light_tools():
    assert classify(ToolInvocation("katana", ["https://a.com"], [])) is Category.ACTIVE_LIGHT
    assert classify(ToolInvocation("feroxbuster", ["https://a.com"], [])) is Category.ACTIVE_LIGHT


def test_nuclei_low_severity_active_light():
    inv = ToolInvocation("nuclei", ["https://a.com"], ["-severity", "info,low"])
    assert classify(inv) is Category.ACTIVE_LIGHT


def test_nuclei_high_severity_intrusive():
    inv = ToolInvocation("nuclei", ["https://a.com"], ["-severity", "critical,high"])
    assert classify(inv) is Category.INTRUSIVE


def test_nuclei_no_severity_is_active_light():
    inv = ToolInvocation("nuclei", ["https://a.com"], [])
    assert classify(inv) is Category.ACTIVE_LIGHT


def test_intrusive_tools():
    assert classify(ToolInvocation("sqlmap", ["https://a.com"], [])) is Category.INTRUSIVE
    assert classify(ToolInvocation("commix", ["https://a.com"], [])) is Category.INTRUSIVE
    assert classify(ToolInvocation("dalfox", ["https://a.com"], [])) is Category.INTRUSIVE


def test_high_thread_count_promotes_to_intrusive():
    inv = ToolInvocation("ffuf", ["https://a.com"], ["-t", "50"])
    assert classify(inv) is Category.INTRUSIVE


def test_low_thread_count_stays_active_light():
    inv = ToolInvocation("ffuf", ["https://a.com"], ["-t", "10"])
    assert classify(inv) is Category.ACTIVE_LIGHT
