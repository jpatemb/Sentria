"""Fixtures below use fake, non-functional credential-shaped strings
(e.g. AKIAABCDEFGHIJKLMNOP, sk-ant-api03-abcdefghijklmnopqrstuvwx) chosen
only to match secrets_check's detection patterns. They are synthetic test
data, not real leaked secrets — GitHub's own secret scanning may still
flag them by shape once this repo is public; that's expected, and those
alerts should be dismissed as false positives / used-in-tests.
"""

from checks.secrets_check import scan_secrets


def test_finds_aws_access_key(tmp_path):
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    findings = scan_secrets(tmp_path)

    assert any("aws_access_key" in f.evidence for f in findings)
    assert all(f.severity == "critical" for f in findings if "aws_access_key" in f.evidence)


def test_finds_anthropic_api_key():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "settings.py").write_text('key = "sk-ant-api03-abcdefghijklmnopqrstuvwx"\n')

        findings = scan_secrets(root)

    assert any(f.category == "secrets" and "anthropic_api_key" in f.evidence for f in findings)


def test_finds_private_key_block(tmp_path):
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n")

    findings = scan_secrets(tmp_path)

    assert any(f.severity == "critical" and "private_key" in f.evidence for f in findings)


def test_ignores_short_non_secret_strings(tmp_path):
    (tmp_path / "plain.py").write_text('greeting = "hello world"\ncount = 42\n')

    findings = scan_secrets(tmp_path)

    assert findings == []


def test_skips_git_directory(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    findings = scan_secrets(tmp_path)

    assert findings == []


def test_skips_file_larger_than_size_cap(tmp_path, monkeypatch):
    """A file over the size cap must be skipped without ever being read into
    memory — read_text() on a genuinely huge file is what OOM-kills a broad
    scan, so this check has to happen before any read is attempted."""
    from checks import secrets_check

    monkeypatch.setattr(secrets_check, "_MAX_FILE_SIZE", 10)

    big = tmp_path / "big.py"
    big.write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    assert big.stat().st_size > 10

    findings = scan_secrets(tmp_path)

    assert findings == []
