from context.escalation import dependency_severity, permission_severity, secret_severity


def test_aws_access_key_is_always_critical():
    assert secret_severity("aws_access_key") == "critical"


def test_generic_api_key_is_high_not_critical():
    assert secret_severity("generic_api_key") == "high"


def test_unrecognized_secret_kind_defaults_to_medium():
    assert secret_severity("something_new") == "medium"


def test_dependency_with_no_cvss_score_is_medium_not_dropped():
    assert dependency_severity(None) == "medium"


def test_dependency_cvss_9_8_is_critical():
    assert dependency_severity(9.8) == "critical"


def test_dependency_cvss_6_1_is_medium():
    assert dependency_severity(6.1) == "medium"


def test_dependency_cvss_3_0_is_low():
    assert dependency_severity(3.0) == "low"


def test_non_world_writable_file_is_low():
    assert permission_severity(world_writable=False, is_executable=True, path="/etc/foo") == "low"


def test_world_writable_executable_is_critical():
    assert permission_severity(world_writable=True, is_executable=True, path="/home/user/script.sh") == "critical"


def test_world_writable_file_in_system_path_is_high():
    assert permission_severity(world_writable=True, is_executable=False, path="/etc/passwd") == "high"


def test_world_writable_file_outside_system_path_is_low():
    assert permission_severity(world_writable=True, is_executable=False, path="/home/user/notes.txt") == "low"
