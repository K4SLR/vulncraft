import fnmatch
import posixpath
from urllib.parse import urlparse
from typing import Tuple
from .models import ScopeConfig


class ScopeGuard:
    """
    Validates target URLs or hostnames against In-Scope and Out-of-Scope rules.
    Out-of-Scope rules strictly override In-Scope rules.
    Includes POSIX path normalization and wildcard-subpath support.
    """

    def __init__(self, config: ScopeConfig):
        self.config = config

    @staticmethod
    def extract_hostname_and_path(target: str) -> Tuple[str, str, str]:
        target = target.strip()
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
        raw_path = parsed.path or "/"
        norm_path = posixpath.normpath(raw_path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        return host, f"{host}{norm_path}", f"{netloc}{norm_path}"

    @classmethod
    def matches_pattern(cls, host: str, host_path: str, netloc_path: str, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        if "://" in pattern:
            p = urlparse(pattern)
            pattern = f"{(p.netloc or p.hostname or '').lower()}{p.path or ''}".rstrip("/")

        clean_pat = pattern.rstrip("/")

        if "/" in pattern:
            clean_hp = host_path.rstrip("/")
            clean_np = netloc_path.rstrip("/")
            # Cocokkan dengan host_path maupun netloc_path (dengan port)
            for target_path in (clean_hp, clean_np):
                if fnmatch.fnmatch(target_path, clean_pat):
                    return True
                if fnmatch.fnmatch(target_path, clean_pat + "/*"):
                    return True
                if "*" not in clean_pat and target_path.startswith(clean_pat + "/"):
                    return True
            return False

        if pattern.startswith("*."):
            base_domain = pattern[2:]
            return host == base_domain or host.endswith("." + base_domain)
        return fnmatch.fnmatch(host, pattern)

    def validate(self, target: str) -> Tuple[bool, str]:
        host, host_path, netloc_path = self.extract_hostname_and_path(target)
        if not host:
            return False, "Invalid target hostname"

        for oos in self.config.out_of_scope:
            if self.matches_pattern(host, host_path, netloc_path, oos):
                return False, f"BLOCKED: Matches Out-of-Scope rule '{oos}'"

        for ins in self.config.in_scope:
            if self.matches_pattern(host, host_path, netloc_path, ins):
                return True, f"ALLOWED: Matches In-Scope rule '{ins}'"

        return False, "BLOCKED: Target does not match any In-Scope rule"