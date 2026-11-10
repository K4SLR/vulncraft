import json
import re
from typing import Any, List


class HTTPSanitizer:
    """Sanitizes sensitive tokens, passwords, cookies, and secrets from HTTP traffic blocks."""

    SENSITIVE_HEADERS = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "api-key",
        "client-secret",
        "x-amz-security-token",
    }

    SENSITIVE_PARAM_NAMES = (
        r"(?:access_token|refresh_token|auth_token|id_token|token|api_key|apikey|"
        r"secret|client_secret|password|passwd|pwd|session_id|sessionid|sid|phpsessid|jwt|key)"
    )

    QUERY_PARAM_RE = re.compile(
        rf"([?&]{SENSITIVE_PARAM_NAMES}=)([^&\s#]+)",
        re.IGNORECASE,
    )

    COOKIE_PAIR_RE = re.compile(
        r"([A-Za-z0-9_\-]*?(?:sess|token|auth|sid|jwt|key|secret|id)[A-Za-z0-9_\-]*?=)([^;\s]+)",
        re.IGNORECASE,
    )

    BEARER_INLINE_RE = re.compile(
        r"\b(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)",
        re.IGNORECASE,
    )

    JSON_SECRET_KEY_RE = re.compile(
        r"(?:token|secret|password|passwd|pwd|api_key|apikey|auth|session|jwt|private_key|access_key|credential)",
        re.IGNORECASE,
    )

    @classmethod
    def _redact_json_recursive(cls, obj: Any) -> Any:
        """Recursively replaces values of sensitive JSON keys with [REDACTED]."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if cls.JSON_SECRET_KEY_RE.search(str(k)) and isinstance(v, (str, int, float)):
                    out[k] = "[REDACTED]"
                else:
                    out[k] = cls._redact_json_recursive(v)
            return out
        if isinstance(obj, list):
            return [cls._redact_json_recursive(item) for item in obj]
        return obj

    @classmethod
    def sanitize(cls, raw_http: str) -> str:
        """Performs full sanitization across HTTP headers, query strings, cookies, and bodies."""
        if not raw_http or not raw_http.strip():
            return ""

        normalized = raw_http.replace("\r\n", "\n")
        if "\n\n" in normalized:
            header_part, body_part = normalized.split("\n\n", 1)
        else:
            header_part, body_part = normalized, ""

        header_lines = header_part.split("\n")
        sanitized_headers: List[str] = []

        for idx, line in enumerate(header_lines):
            if idx == 0:
                # Sanitize query parameters in request line
                sanitized_headers.append(cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", line))
                continue

            if ":" in line:
                h_name, h_val = line.split(":", 1)
                h_lower = h_name.strip().lower()

                if h_lower in cls.SENSITIVE_HEADERS:
                    val_strip = h_val.strip()
                    if val_strip.lower().startswith("bearer "):
                        sanitized_headers.append(f"{h_name}: Bearer [REDACTED]")
                    elif val_strip.lower().startswith("basic "):
                        sanitized_headers.append(f"{h_name}: Basic [REDACTED]")
                    else:
                        sanitized_headers.append(f"{h_name}: [REDACTED]")
                    continue

                if h_lower in ("cookie", "set-cookie"):
                    redacted_cookie = cls.COOKIE_PAIR_RE.sub(r"\1[REDACTED]", h_val)
                    if redacted_cookie == h_val and "=" in h_val:
                        first_eq = h_val.find("=")
                        semi = h_val.find(";", first_eq)
                        if semi != -1:
                            redacted_cookie = h_val[: first_eq + 1] + "[REDACTED]" + h_val[semi:]
                        else:
                            redacted_cookie = h_val[: first_eq + 1] + "[REDACTED]"
                    sanitized_headers.append(f"{h_name}:{redacted_cookie}")
                    continue

            line = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", line)
            line = cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", line)
            sanitized_headers.append(line)

        sanitized_body = body_part.strip()
        if sanitized_body:
            if (sanitized_body.startswith("{") and sanitized_body.endswith("}")) or (
                sanitized_body.startswith("[") and sanitized_body.endswith("]")
            ):
                try:
                    parsed_json = json.loads(sanitized_body)
                    redacted_json = cls._redact_json_recursive(parsed_json)
                    sanitized_body = json.dumps(redacted_json, indent=2)
                except Exception:
                    sanitized_body = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", sanitized_body)
            else:
                sanitized_body = cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", "?" + sanitized_body)[1:]
                sanitized_body = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", sanitized_body)

        if sanitized_body:
            return "\n".join(sanitized_headers) + "\n\n" + sanitized_body
        return "\n".join(sanitized_headers)