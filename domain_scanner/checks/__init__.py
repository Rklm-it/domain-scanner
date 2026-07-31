"""Check registry. Importing this package registers every built-in check."""

from .base import Check, ScanContext, all_checks, get_check, register, run_check  # noqa: F401

# Import for side effects: each module registers itself.
from . import blocklists  # noqa: F401,E402
from . import crtsh  # noqa: F401,E402
from . import dns_check  # noqa: F401,E402
from . import hosting  # noqa: F401,E402
from . import http_check  # noqa: F401,E402
from . import naming  # noqa: F401,E402
from . import rdap  # noqa: F401,E402
from . import reputation  # noqa: F401,E402
from . import tld  # noqa: F401,E402
from . import wayback  # noqa: F401,E402

__all__ = ["Check", "ScanContext", "all_checks", "get_check", "register", "run_check"]
