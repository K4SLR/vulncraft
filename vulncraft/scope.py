import fnmatch
import posixpath
from typing import List, Tuple
from urllib.parse import urlparse


class ScopeGuard:
    """Enforces target program scope boundaries against wildcards, explicit domains, and sub-paths."""

    def __init__(self, in_scope: List[str], out_of_scope: List[str]):
        self.in_scope = in_scope or ["*"]
        self.out_of_scope = out_of_scope or []

    @staticmethod
    def extract_hostname_and_path(target: str) -> Tuple[str, str, str]:
        """Extracts normalized hostname, host+path, and netloc+path tuples."""
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
        """Evaluates whether an endpoint matches a scope pattern."""
        pattern = pattern.lower().strip()
        if "://" in pattern:
            p = urlparse(pattern)
            pattern = f"{(p.netloc or p.hostname or '').lower()}{p.path or ''}".rstrip("/")

        clean_pat = pattern.rstrip("/")
        if "/" in pattern:
            clean_hp = host_path.rstrip("/")
            clean_np = netloc_path.rstrip("/")
            for target_path in (clean_hp, clean_np):
                if fnmatch.fnmatch(target_path, clean_pat):
                    return True
                if fnmatch.fnmatch(target_path, clean_pat + "/*"):
                    return True
                if "*" not in clean_pat and target_path.startswith(clean_pat + "/"):
                    return True
            return False

        if ":" in clean_pat:
            netloc_only = netloc_path.split("/", 1)[0]
            if clean_pat.startswith("*."):
                base_netloc = clean_pat[2:]
                return netloc_only == base_netloc or netloc_only.endswith("." + base_netloc)
            return fnmatch.fnmatch(netloc_only, clean_pat)

        if clean_pat.startswith("*."):
            base_domain = clean_pat[2:]
            return host == base_domain or host.endswith("." + base_domain)

        return fnmatch.fnmatch(host, clean_pat)

    def validate(self, target: str) -> Tuple[bool, str]:
        """Validates endpoint against Out-of-Scope rules followed by In-Scope allowlists."""
        host, host_path, netloc_path = self.extract_hostname_and_path(target)
        if not host:
            return False, "BLOCKED: Invalid target hostname"

        for oos in self.out_of_scope:
            if self.matches_pattern(host, host_path, netloc_path, oos):
                return False, f"BLOCKED: Matches Out-of-Scope rule '{oos}'"

        for ins in self.in_scope:
            if self.matches_pattern(host, host_path, netloc_path, ins):
                return True, f"ALLOWED: Matches In-Scope rule '{ins}'"

        return False, "BLOCKED: Target does not match any In-Scope rule"