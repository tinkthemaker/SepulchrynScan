"""Tests for CLI allowlist enforcement.

Covers:
  - target_allowed matching rules (exact, CIDR, IP)
  - CLI exits code 2 when target is denied
"""

from __future__ import annotations


from sepulchrynscan.cli import load_allowlist, main, target_allowed


class TestTargetAllowed:
    def test_exact_hostname_match(self):
        assert target_allowed("localhost", ["127.0.0.1", "localhost"]) is True

    def test_exact_ip_match(self):
        assert target_allowed("192.168.1.1", ["192.168.1.1"]) is True

    def test_cidr_match(self):
        assert target_allowed("10.0.0.5", ["10.0.0.0/24"]) is True

    def test_ip_does_not_match_hostname_entry(self):
        assert target_allowed("127.0.0.1", ["localhost"]) is False

    def test_hostname_does_not_match_cidr(self):
        assert target_allowed("localhost", ["127.0.0.0/24"]) is False

    def test_no_match(self):
        assert target_allowed("8.8.8.8", ["127.0.0.1", "10.0.0.0/8"]) is False

    def test_empty_allowlist_denies_everything(self):
        assert target_allowed("127.0.0.1", []) is False

    def test_strips_whitespace(self):
        assert target_allowed("  127.0.0.1  ", ["127.0.0.1"]) is True


class TestLoadAllowlist:
    def test_skips_comments_and_blank_lines(self, tmp_path):
        path = tmp_path / "allowlist"
        path.write_text("\n# comment\n127.0.0.1\n\nlocalhost\n")
        result = load_allowlist(path)
        assert result == ["127.0.0.1", "localhost"]

    def test_missing_file_returns_empty(self, tmp_path):
        path = tmp_path / "does_not_exist"
        assert load_allowlist(path) == []


class TestCliDenial:
    def test_scan_exits_2_when_target_not_allowed(self, capsys):
        exit_code = main(["scan", "8.8.8.8"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "8.8.8.8" in captured.err
        assert "not in" in captured.err
