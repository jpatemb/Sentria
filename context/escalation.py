"""Explicit, testable severity criteria — one rulebook per category.

Kept separate from checks/ so severity is never a judgment call made ad hoc
inside a check (or, worse, left to the model). Each function here takes the
specific signals a check observed and returns a severity band; checks call
these rather than assigning severity themselves.
"""

from __future__ import annotations

_SYSTEM_PATH_PREFIXES = (
    "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib",
    "C:\\Windows", "C:\\Program Files",
)

# A live-looking credential is always critical: it grants access on its own,
# regardless of where it was found. Lower-confidence signals (a bare
# high-entropy string with no recognizable prefix) get a lower band.
SECRET_KIND_SEVERITY = {
    "aws_access_key": "critical",
    "aws_secret_key": "critical",
    "anthropic_api_key": "critical",
    "github_token": "critical",
    "private_key": "critical",
    "generic_api_key": "high",
    "high_entropy_string": "medium",
}

# (minimum CVSS base score, severity) bands, checked highest-first.
_CVSS_SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
)


def secret_severity(kind: str) -> str:
    return SECRET_KIND_SEVERITY.get(kind, "medium")


def dependency_severity(cvss_score: float | None) -> str:
    """Maps a CVE's CVSS base score to a severity band.

    A missing score (None) is treated as medium rather than dropped —
    'unscored' is not the same claim as 'safe'.
    """
    if cvss_score is None:
        return "medium"
    for threshold, severity in _CVSS_SEVERITY_BANDS:
        if cvss_score >= threshold:
            return severity
    return "low"


def permission_severity(*, world_writable: bool, is_executable: bool, path: str) -> str:
    """A world-writable executable is always critical: any local user can
    replace what runs. A world-writable file under a system path is high
    even if not executable, since system paths are a common
    privilege-escalation target. Everything else world-writable is low —
    still worth reporting, just not urgent."""
    if not world_writable:
        return "low"
    if is_executable:
        return "critical"
    if _is_system_path(path):
        return "high"
    return "low"


def _is_system_path(path: str) -> bool:
    return path.startswith(_SYSTEM_PATH_PREFIXES)
