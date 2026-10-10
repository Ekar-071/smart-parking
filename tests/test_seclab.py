from pathlib import Path

from seclab import log_analyzer, password_audit, secret_scanner
from seclab.__main__ import main

SAMPLE = Path(__file__).parent.parent / "data" / "sample_auth.log"


def test_log_analyzer_flags_bruteforce():
    rep = log_analyzer.analyze(SAMPLE.read_text().splitlines(), threshold=5)
    assert rep.suspects == ["198.51.100.23", "203.0.113.45"] or set(rep.suspects) == {"198.51.100.23", "203.0.113.45"}
    assert "192.0.2.10" not in rep.suspects              # 2 échecs seulement : normal
    assert rep.compromised == ["198.51.100.23"]          # a réussi après force brute
    assert len(rep.users_tried["203.0.113.45"]) == 6


def test_log_analyzer_clean():
    assert log_analyzer.analyze(["Oct 10 sshd: Accepted publickey for bob from 192.0.2.1 port 1 ssh2"]).suspects == []


def test_password_audit_levels():
    assert password_audit.audit("password")["level"] == "très faible"
    assert password_audit.audit("abc")["level"] == "faible"
    strong = password_audit.audit("Tr0ub4dor&3-Horse-Staple")
    assert strong["level"] == "fort" and strong["issues"] == []


def test_entropy_monotonic():
    assert password_audit.entropy_bits("aaaa") < password_audit.entropy_bits("aaaaaaaa")
    assert password_audit.entropy_bits("") == 0


def test_secret_scanner(tmp_path):
    (tmp_path / "config.py").write_text('API_KEY = "sk_live_abcdef123456"\nname = "ok"\n')
    (tmp_path / "aws.txt").write_text("key=AKIAABCDEFGHIJKLMNOP\n")
    (tmp_path / "img.bin").write_bytes(b"\xff\xfe\x00\x01")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x").write_text('password = "ignoreignore"')
    found = secret_scanner.scan_dir(str(tmp_path))
    assert len(found) == 2
    labels = {label for items in found.values() for _, label, _ in items}
    assert labels == {"Secret générique", "Clé d'accès AWS"}
    assert all("abcdef123456" not in masked for items in found.values() for *_, masked in items)  # valeurs masquées


def test_cli_logs(capsys):
    assert main(["logs", str(SAMPLE)]) == 0
    assert "compromis" in capsys.readouterr().out
    assert main(["logs", "inexistant.log"]) == 1
