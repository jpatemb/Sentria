"""Make Sentria's packages importable from its tests.

Puts the repo root on sys.path once for the whole tests/ directory, so
test files can do `from checks.secrets_check import scan_secrets`,
`from context.escalation import secret_severity`, etc. directly.

Offline guards (no API key, no network) come from the repo-root conftest.py.
Nothing offline-related belongs here.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
