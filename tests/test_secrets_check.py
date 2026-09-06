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
