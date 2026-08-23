"""Runtime configuration.

APICipher targets its own API, so that API has to be able to run in two states:

    SECURE_MODE=false  - intentionally vulnerable lab target (default)
    SECURE_MODE=true   - hardened, with every finding remediated

Keeping both in one codebase means the remediation can be demonstrated by
re-running the same scan against the same endpoints, rather than asserted.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes")


SECURE_MODE = _flag("SECURE_MODE")

# Only applied when SECURE_MODE is enabled.
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
