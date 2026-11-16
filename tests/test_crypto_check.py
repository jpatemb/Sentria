from checks.crypto_check import scan_crypto
from context.escalation import crypto_severity


def _scan_one(tmp_path, filename, line):
    (tmp_path / filename).write_text(line + "\n")
    return scan_crypto(tmp_path)


def test_rsa_keygen_with_key_size_is_rsa_2048(tmp_path):
    result = _scan_one(tmp_path, "keys.py", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)")

    [asset] = result.assets
    assert asset.name == "RSA-2048"
    assert asset.parameter_set == "2048"
    assert asset.classical_security_level == 112
    assert asset.primitive == "pke"


def test_ecdhe_cipher_suite_is_key_exchange(tmp_path):
    result = _scan_one(tmp_path, "tls.conf", "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;")

    [asset] = result.assets
    assert asset.algorithm == "ecdh"
    assert asset.usage == "key_exchange"
    assert asset.primitive == "key-agree"


def test_ecdsa_is_signature(tmp_path):
    result = _scan_one(tmp_path, "sign.py", "signer = ec.ECDSA(hashes.SHA256())")

    [asset] = result.assets
    assert asset.usage == "signature"
    assert asset.primitive == "signature"


def test_pem_headers_are_classified_by_algorithm(tmp_path):
    (tmp_path / "rsa.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
    (tmp_path / "ec.pem").write_text("-----BEGIN EC PRIVATE KEY-----\n")
    (tmp_path / "dsa.pem").write_text("-----BEGIN DSA PRIVATE KEY-----\n")
    (tmp_path / "dh.pem").write_text("-----BEGIN DH PARAMETERS-----\n")

    algorithms = {a.location: a.algorithm for a in scan_crypto(tmp_path).assets}

    assert algorithms == {"rsa.pem": "rsa", "ec.pem": "ec_key", "dsa.pem": "dsa", "dh.pem": "dh"}


def test_ecdsa_does_not_also_match_dsa(tmp_path):
    result = _scan_one(tmp_path, "sign.py", "k = ec.generate_private_key(ec.SECP256R1()); k.sign(d, ec.ECDSA(h))")

    assert [a.algorithm for a in result.assets] == ["ecdsa"]


def test_post_quantum_and_symmetric_crypto_are_not_flagged(tmp_path):
    result = _scan_one(tmp_path, "pq.py", 'kem = "ML-KEM-768"; cipher = AES.new(key, AES.MODE_GCM)')

    assert result.assets == []
    assert result.findings == []


def test_key_exchange_outranks_signature():
    order = ("low", "medium", "high", "critical")
    assert order.index(crypto_severity("key_exchange")) > order.index(crypto_severity("signature"))


def test_finding_and_asset_from_one_detection_share_id_and_severity(tmp_path):
    result = _scan_one(tmp_path, "tls.conf", "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;")

    [finding] = result.findings
    [asset] = result.assets
    assert finding.id == asset.id
    assert finding.severity == asset.hndl_risk
    assert finding.category == "crypto"


def test_every_detection_yields_one_finding_and_one_asset(tmp_path):
    (tmp_path / "a.py").write_text(
        "rsa.generate_private_key(key_size=3072)\n"
        "ec.ECDSA(h)\n"
        "x = X25519PrivateKey.generate()\n"
        "ssh-ed25519 AAAA\n"
    )
    (tmp_path / "b.conf").write_text("ssl_ciphers DHE-RSA-AES128-SHA;\n")

    result = scan_crypto(tmp_path)

    assert len(result.findings) == len(result.assets) == 5
    assert {f.id for f in result.findings} == {a.id for a in result.assets}
