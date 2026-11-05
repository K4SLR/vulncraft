import fnmatch
import posixpath
from urllib.parse import urlparse
from typing import Tuple
from .models import ScopeConfig


class ScopeGuard:
    """
    Validates target URLs or hostnames against In-Scope and Out-of-Scope rules.
    Out-of-Scope rules strictly override In-Scope rules.
    Includes POSIX path normalization to prevent '../' path-traversal scope bypasses.
    """

    def __init__(self, config: ScopeConfig):
        self.config = config

    @staticmethod
    def extract_hostname_and_path(target: str) -> Tuple[str, str]:
        target = target.strip()
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        raw_path = parsed.path or "/"
        norm_path = posixpath.normpath(raw_path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        return host, f"{host}{norm_path}"

    @classmethod
    def matches_pattern(cls, host: str, host_path: str, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        if "://" in pattern:
            p = urlparse(pattern)
            pattern = f"{(p.hostname or '').lower()}{p.path or ''}".rstrip("/")

        if "/" in pattern:
            clean_pat = pattern.rstrip("/")
            clean_hp = host_path.rstrip("/")
            if fnmatch.fnmatch(clean_hp, clean_pat):
                return True
            # Also match sub-paths if pattern specifies a directory/endpoint prefix without wildcard
            if "*" not in clean_pat and clean_hp.startswith(clean_pat + "/"):
                return True
            return False

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
