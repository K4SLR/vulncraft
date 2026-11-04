import fnmatch
from urllib.parse import urlparse
from typing import Tuple
from .models import ScopeConfig


class ScopeGuard:
    """
    Validates target URLs or hostnames against In-Scope and Out-of-Scope rules.
    Out-of-Scope rules strictly override In-Scope rules.
    """

    def __init__(self, config: ScopeConfig):
        self.config = config

    @staticmethod
    def extract_hostname_and_path(target: str) -> Tuple[str, str]:
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        return host, f"{host}{path}"

    @classmethod
    def matches_pattern(cls, host: str, host_path: str, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        if "://" in pattern:
            p = urlparse(pattern)
            pattern = f"{(p.hostname or '').lower()}{p.path or ''}".rstrip("/")

        # Wildcard subdomain matching: *.example.com also matches sub.example.com
        if "/" in pattern:
            return fnmatch.fnmatch(host_path.rstrip("/"), pattern.rstrip("/"))
        if pattern.startswith("*."):
            base_domain = pattern[2:]
            return host == base_domain or host.endswith("." + base_domain)
        return fnmatch.fnmatch(host, pattern)

    def validate(self, target: str) -> Tuple[bool, str]:
        host, host_path = self.extract_hostname_and_path(target)
        if not host:
            return False, "Invalid target hostname"

        for oos in self.config.out_of_scope:
            if self.matches_pattern(host, host_path, oos):
                return False, f"BLOCKED: Matches Out-of-Scope rule '{oos}'"

        for ins in self.config.in_scope:
            if self.matches_pattern(host, host_path, ins):
                return True, f"ALLOWED: Matches In-Scope rule '{ins}'"

        return False, "BLOCKED: Target does not match any In-Scope rule"
