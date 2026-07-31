"""domain-scanner — pre-flight checks for domains used in paid traffic."""

__version__ = "1.0.0"

from .config import Config  # noqa: E402
from .models import CheckResult, DomainReport, Finding  # noqa: E402
from .scanner import scan_domain, scan_domains  # noqa: E402

__all__ = [
    "Config",
    "CheckResult",
    "DomainReport",
    "Finding",
    "scan_domain",
    "scan_domains",
    "__version__",
]
