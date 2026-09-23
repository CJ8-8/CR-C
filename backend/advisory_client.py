"""
CodeJev Advisory Client - Phase 9
==================================

Provides local dependency vulnerability lookup and mockable advisory client interface.
Supports offline execution with built-in advisory datasets and non-blocking error handling.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class Advisory:
    """
    Metadata representation of a known dependency vulnerability.
    """
    package_name: str
    vulnerable_version: str
    cve_id: str
    severity: str
    description: str


# Default offline advisory database mapping (package_name_lower, version) -> Advisory
DEFAULT_ADVISORIES: Dict[Tuple[str, str], Advisory] = {
    ("requests", "2.18.4"): Advisory(
        package_name="requests",
        vulnerable_version="2.18.4",
        cve_id="CVE-2018-18074",
        severity="HIGH",
        description="Requests before 2.20.0 sends HTTP Authorization header to HTTPS redirect target."
    ),
    ("urllib3", "1.24.1"): Advisory(
        package_name="urllib3",
        vulnerable_version="1.24.1",
        cve_id="CVE-2019-11324",
        severity="HIGH",
        description="urllib3 before 1.24.2 mishandles cert verification in TLS connections."
    ),
    ("django", "2.0.0"): Advisory(
        package_name="django",
        vulnerable_version="2.0.0",
        cve_id="CVE-2018-6188",
        severity="CRITICAL",
        description="Django 2.0.0 exposes sensitive user data via AuthenticationForm."
    ),
    ("pyyaml", "5.1"): Advisory(
        package_name="pyyaml",
        vulnerable_version="5.1",
        cve_id="CVE-2020-14343",
        severity="CRITICAL",
        description="PyYAML before 5.4 allows arbitrary code execution via unsafe load."
    ),
    ("flask", "0.12.0"): Advisory(
        package_name="flask",
        vulnerable_version="0.12.0",
        cve_id="CVE-2018-1000656",
        severity="HIGH",
        description="Flask before 0.12.3 contains denial of service vulnerability."
    ),
}


class AdvisoryClient:
    """
    Client interface for querying vulnerability advisories for dependencies.
    """
    def __init__(self, advisories: Optional[Dict[Tuple[str, str], Advisory]] = None):
        self.advisories = advisories if advisories is not None else DEFAULT_ADVISORIES

    def check_package(self, package_name: str, version: Optional[str]) -> Optional[Advisory]:
        """
        Looks up vulnerability advisory for package name and exact version string.
        Returns Advisory if vulnerable, or None if safe / unlisted.
        """
        if not package_name or not version:
            return None

        pkg_key = (package_name.strip().lower(), version.strip())
        return self.advisories.get(pkg_key)
