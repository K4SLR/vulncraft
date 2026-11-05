import re
from typing import Dict, Any


class HTTPSanitizer:
    """
    Parses raw HTTP requests/responses and redacts sensitive secrets
    (Bearer tokens, JWTs, session cookies, API keys, form/JSON passwords) for safe PoC sharing.
    """

    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "proxy-authorization",
    }

    COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority"}

    JSON_SECRET_REGEX = re.compile(
        r'("(?:password|passwd|secret|token|api_key|apikey|access_token|refresh_token|client_secret|private_key)"\s*:\s*)"([^"]+)"',
        re.IGNORECASE,
    )

    QUERY_OR_FORM_SECRET_REGEX = re.compile(
        r"((?:^|[?&])(?:token|key|api_key|apikey|password|passwd|secret|auth|access_token|refresh_token|client_secret)=)([^&\s]+)",
        re.IGNORECASE,
    )

    BEARER_REGEX = re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+/]+=*", re.IGNORECASE)
    RAW_JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

    @classmethod
    def _redact_cookie_header(cls, header_val: str) -> str:
        parts = header_val.split(";")
        redacted_parts = []
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip().lower() in cls.COOKIE_ATTRS:
                    redacted_parts.append(part)
                else:
                    redacted_parts.append(f"{k}=[REDACTED]")
            else:
                redacted_parts.append(part)
        return ";".join(redacted_parts)

    @classmethod
    def sanitize_http_block(cls, raw_http: str) -> str:
        if not raw_http:
            return ""

        lines = raw_http.splitlines()
        sanitized_lines = []
        in_headers = True

        for idx, line in enumerate(lines):
            if idx == 0:
                line = cls.QUERY_OR_FORM_SECRET_REGEX.sub(r"\1[REDACTED]", line)
                line = cls.RAW_JWT_REGEX.sub("[REDACTED_JWT]", line)
                sanitized_lines.append(line)
                continue

            if in_headers:
                if line.strip() == "":
                    in_headers = False
                    sanitized_lines.append(line)
                    continue

                if ":" in line:
                    h_name, h_val = line.split(":", 1)
                    h_lower = h_name.strip().lower()
                    if h_lower in cls.SENSITIVE_HEADERS:
                        if h_lower == "authorization" and "bearer" in h_val.lower():
                            sanitized_lines.append(f"{h_name}: Bearer [REDACTED_TOKEN]")
                        elif h_lower in ("cookie", "set-cookie"):
                            sanitized_lines.append(f"{h_name}:{cls._redact_cookie_header(h_val)}")
                        else:
                            sanitized_lines.append(f"{h_name}: [REDACTED]")
                    else:
                        clean_val = cls.RAW_JWT_REGEX.sub("[REDACTED_JWT]", h_val)
                        sanitized_lines.append(f"{h_name}:{clean_val}")
                else:
                    sanitized_lines.append(line)
            else:
                body_line = cls.JSON_SECRET_REGEX.sub(r'\1"[REDACTED]"', line)
                body_line = cls.QUERY_OR_FORM_SECRET_REGEX.sub(r"\1[REDACTED]", body_line)
                body_line = cls.BEARER_REGEX.sub(r"\1[REDACTED_TOKEN]", body_line)
                body_line = cls.RAW_JWT_REGEX.sub("[REDACTED_JWT]", body_line)
                sanitized_lines.append(body_line)

        return "\n".join(sanitized_lines)

    @classmethod
    def parse_raw_request_metadata(cls, raw_http: str) -> Dict[str, Any]:
        lines = [line.strip() for line in raw_http.strip().splitlines() if line.strip()]
        if not lines:
            return {"method": "GET", "path": "/", "host": "unknown", "endpoint": "/"}

        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else "GET"
        path = first_line[1] if len(first_line) > 1 else "/"
        host = "unknown"

        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        return {
            "method": method,
            "path": path,
            "host": host,
            "endpoint": f"https://{host}{path}" if host != "unknown" else path,
        }
