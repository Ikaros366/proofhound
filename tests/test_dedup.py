"""去重指纹单元测试（M3a，§5.4.5）：规范化 + sha256 指纹。"""

from __future__ import annotations

from proofhound.findings.dedup import compute_dedup_key, normalize_asset


def test_normalize_asset_lowercase_and_strip_trailing_slash():
    assert normalize_asset("HTTP://Example.COM/") == "http://example.com"
    assert normalize_asset("http://Example.com/Admin/") == "http://example.com/admin"
    assert normalize_asset("  http://x:8080/a/  ") == "http://x:8080/a"
    assert normalize_asset("http://x//") == "http://x"


def test_same_key_for_case_and_trailing_slash_variants():
    key_a = compute_dedup_key("HTTP://Example.COM/", "sqli")
    key_b = compute_dedup_key("http://example.com", "sqli")
    assert key_a == key_b


def test_key_format_and_stability():
    key = compute_dedup_key("http://example.com/a", "xss", param="q")
    assert key.startswith("sha256:")
    assert len(key.removeprefix("sha256:")) == 64
    assert compute_dedup_key("http://example.com/a", "xss", param="q") == key


def test_vuln_type_case_insensitive():
    assert compute_dedup_key("http://x", "SQLI") == compute_dedup_key("http://x", "sqli")


def test_param_none_and_empty_equivalent():
    assert compute_dedup_key("http://x", "sqli") == compute_dedup_key(
        "http://x", "sqli", param=""
    )


def test_different_param_yields_different_key():
    assert compute_dedup_key("http://x/a", "sqli", param="id") != compute_dedup_key(
        "http://x/a", "sqli", param="name"
    )


def test_different_vuln_type_yields_different_key():
    assert compute_dedup_key("http://x/a", "sqli") != compute_dedup_key(
        "http://x/a", "xss"
    )


def test_nul_join_prevents_concatenation_ambiguity():
    """("ab","c") 与 ("a","bc") 不得得到同指纹。"""
    assert compute_dedup_key("http://ab", "c") != compute_dedup_key("http://a", "bc")
