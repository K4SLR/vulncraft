import re
from typing import Dict, Any


class HTTPSanitizer:
    """
    Parses raw HTTP requests/responses and redacts sensitive secrets
    (Bearer tokens, session cookies, API keys, passwords) for safe PoC sharing.
    """

    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }

    JSON_SECRET_REGEX = re.compile(
        r'("(?:password|passwd|secret|token|api_key|access_token|refresh_token|client_secret)"\s*:\s*)"([^"]+)"',
        re.IGNORECASE,
    )

    BEARER_REGEX = re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+/]+=*", re.IGNORECASE)

    @classmethod
    def sanitize_http_block(cls, raw_http: str) -> str:
        if not raw_http:
            return ""

        lines = raw_http.splitlines()
        sanitized_lines = []
        in_headers = True

        for idx, line in enumerate(lines):
            if idx == 0:
                # Request or status line: redact query params if sensitive
                line = re.sub(
                    r"((?:token|key|password|secret|auth)=)[^&\s]+",
                    r"\1[REDACTED]",
                    line,
                    flags=re.IGNORECASE,
                )
                sanitized_lines.append(line)
                continue

            if in_headers:
                if line.strip() == "":
                    in_headers = False
                    sanitized_lines.append(line)
                    continue

                if ":" in line:
                    h_name, h_val = line.split(":", 1)
                    if h_name.strip().lower() in cls.SENSITIVE_HEADERS:
                        if h_name.strip().lower() == "authorization" and "bearer" in h_val.lower():
                            sanitized_lines.append(f"{h_name}: Bearer [REDACTED_TOKEN]")
                        elif h_name.strip().lower() in ("cookie", "set-cookie"):
                            # Keep cookie keys, redact values
                            redacted_cookies = re.sub(r"=([^;\s]+)", "=[REDACTED]", h_val)
                            sanitized_lines.append(f"{h_name}:{redacted_cookies}")
                        else:
                            sanitized_lines.append(f"{h_name}: [REDACTED]")
                    else:
                        sanitized_lines.append(line)
                else:
                    sanitized_lines.append(line)
            else:
                # Body sanitization
                body_line = cls.JSON_SECRET_REGEX.sub(r'\1"[REDACTED]"', line)
                body_line = cls.BEARER_REGEX.sub(r"\1[REDACTED_TOKEN]", body_line)
                sanitized_lines.append(body_line)

        return "\n".join(sanitized_lines)

    @classmethod
    def parse_raw_request_metadata(cls, raw_http: str) -> Dict[str, Any]:
        lines = [line.strip() for line in raw_http.strip().splitlines() if line.strip()]
        if not lines:
            return {"method": "GET", "path": "/", "host": "unknown"}

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
