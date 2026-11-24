from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "secret_scan.py"

spec = importlib.util.spec_from_file_location("secret_scan", SCRIPT)
assert spec and spec.loader
secret_scan = importlib.util.module_from_spec(spec)
sys.modules["secret_scan"] = secret_scan
spec.loader.exec_module(secret_scan)


def _parts(*chunks: str) -> str:
    return "".join(chunks)


def _names(findings) -> set[str]:
    return {f.pattern for f in findings}


def test_github_classic_and_pat_detected():
    classic = _parts("ghp_", "A" * 36)
    pat = _parts("github_pat_", "B" * 40)
    oauth = _parts("gho_", "C" * 36)
    text = f"a = {classic}\nb = {pat}\nc = {oauth}\n"
    found = secret_scan.scan_text("x.py", text)
    assert "github_token" in _names(found)
    assert len([f for f in found if f.pattern == "github_token"]) == 3
    for item in found:
        assert classic not in item.masked
        assert pat not in item.masked
        assert oauth not in item.masked


def test_aws_slack_stripe_jwt_render_and_private_key_detected():
    aws = _parts("AKIA", "ABCDEFGHIJKLMNOP")
    slack = _parts("xoxb-", "1234567890-ABCDEF")
    stripe = _parts("sk_live_", "abcdefghijklmnopqrstuv")
    jwt = _parts("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0In0", ".", "abcdefghijklmnop")
    render = _parts("rnd_", "abcdefghijklmnopqrstuvwxyz01")
    begin = _parts("-----BEGIN ", "RSA PRIVATE KEY-----")
    text = "\n".join([aws, slack, stripe, jwt, render, begin])
    found = secret_scan.scan_text("secrets.txt", text)
    names = _names(found)
    assert "aws_access_key" in names
    assert "slack_token" in names
    assert "stripe_live_key" in names
    assert "jwt" in names
    assert "render_api_key" in names
    assert "private_key" in names
    blob = " ".join(f.masked for f in found)
    for raw in (aws, slack, stripe, jwt, render):
        assert raw not in blob


def test_generic_assignment_non_placeholder_detected():
    value = _parts("nV8mQ2pL9wX4", "tK7sD1cB6hR3z")
    text = f'api_key = "{value}"\n'
    found = secret_scan.scan_text("cfg.py", text)
    assert "generic_secret_assignment" in _names(found)
    assert value not in found[0].masked


def test_placeholders_and_env_example_are_allowed():
    text = "\n".join(
        [
            'UNIVERSE_PHONE_TOKEN=metti-un-token-lungo-diverso-qui',
            'UNIVERSE_BOT_TOKENS={"test-client":"metti-un-token-lungo-casuale-qui"}',
            'password = "changeme"',
            'api_key = "your-api-key-here"',
            'SECRET="placeholder"',
            'token = "xxxx"',
            'API_TOKEN=${MY_TOKEN}',
            'UNIVERSE_BOT_TOKENS_FILE=/run/secrets/universe-tokens.json',
        ]
    )
    found = secret_scan.scan_text(".env.example", text)
    assert found == []


def test_repeated_char_and_short_values_ignored():
    text = "\n".join(
        [
            'BOT_A = "' + ("a" * 32) + '"',
            'token = "abc"',
            'phone_token: str = ""',
            'Authorization: Bearer zzz',
        ]
    )
    found = secret_scan.scan_text("tests/test_auth.py", text)
    assert found == []


def test_allow_marker_skips_line():
    token = _parts("ghp_", "Z" * 36)
    text = f"token = {token}  # secret-scan: allow\n"
    assert secret_scan.scan_text("x.py", text) == []
    assert "github_token" in _names(secret_scan.scan_text("x.py", f"token = {token}\n"))


def test_high_entropy_detected_low_entropy_ignored():
    high = _parts("nV8mQ2pL9wX4tK7s", "D1cB6hR3zY0aF5uJ")
    assert len(high) >= 32
    low = "alpha-beta-gamma-delta-epsilon-zzzz"
    text = f'alpha = "{high}"\nbeta = "{low}"\n'
    found = secret_scan.scan_text("rand.py", text)
    names_for = {(f.pattern, f.line) for f in found}
    assert ("high_entropy", 1) in names_for or "high_entropy" in _names(found)
    assert all(f.line != 2 for f in found)
    assert high not in "".join(f.masked for f in found)


def test_known_local_tokens_from_secrets_dir(tmp_path: Path):
    planted = _parts("localsecretVALUE", "0123456789abcd")
    payload = {
        "generated_at": "2026-11-24T00:00:00+01:00",
        "note": "questa e una nota descrittiva",
        "bots": {"demo": planted},
        "phone": _parts("phonetokenVALUE", "0123456789abcd"),
    }
    (tmp_path / "demo-tokens.json").write_text(json.dumps(payload), encoding="utf-8")
    known = secret_scan.load_known_secret_values([tmp_path])
    assert planted in known
    # le note e le date non devono entrare
    assert payload["note"] not in known
    text = f"command uses {planted} in the body\n"
    found = secret_scan.scan_text("leak.py", text, known_values=known)
    assert "known_local_token" in _names(found)
    assert planted not in found[0].masked
    assert found[0].masked.startswith("***")


def test_cli_clean_and_dirty(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    clean = tmp_path / "clean.py"
    clean.write_text('print("hello")\n', encoding="utf-8")
    assert secret_scan.main([str(clean)]) == 0
    dirty = tmp_path / "dirty.py"
    dirty.write_text("t = " + _parts("ghp_", "D" * 36) + "\n", encoding="utf-8")
    assert secret_scan.main([str(dirty)]) == 1
    captured = capsys.readouterr()
    assert "github_token" in captured.err
    assert "ghp_" + "D" * 36 not in captured.err
    assert "ghp_" + "D" * 36 not in captured.out


def test_scan_current_repo_is_clean():
    """La tree del repo, cosi com'e, non deve contenere segreti."""
    findings = secret_scan.scan_tree(ROOT, secret_scan.load_known_secret_values())
    assert findings == [], "\n".join(f.format() for f in findings)
