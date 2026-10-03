"""Minimal interactive client for external HTTP and redirect validation."""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import sys
import uuid
from dataclasses import dataclass
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_BODY_BYTES = 64 * 1024
DEFAULT_MAX_REDIRECTS = 10
CORRELATION_HEADER = "X-Validation-ID"
PUBLIC_IP_ENDPOINT = os.environ.get(
    "EVENTGEN_IP_ECHO_URL",
    "https://api64.ipify.org?format=json",
)

TLS_WARNING = (
    "WARNING: TLS certificate verification is DISABLED. "
    "The server's identity has not been verified."
)


@dataclass(frozen=True)
class UserAgentOption:
    name: str
    value: str
    note: str = ""


# Version references reviewed 2026-10-03. Desktop Chromium user agents use the
# reduced version format, while Chrome on iOS includes its full CriOS version.
USER_AGENT_OPTIONS: tuple[UserAgentOption, ...] = (
    UserAgentOption(
        name="Microsoft Edge 154 on Windows",
        value=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 "
            "Safari/537.36 Edg/154.0.0.0"
        ),
        note="default",
    ),
    UserAgentOption(
        name="Google Chrome 154 on Windows",
        value=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 "
            "Safari/537.36"
        ),
    ),
    UserAgentOption(
        name="Google Chrome 154 on iPhone",
        value=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_1 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/154.0.8037.41 Mobile/15E148 Safari/604.1"
        ),
    ),
    UserAgentOption(
        name="Palo Alto Prisma Browser on Windows",
        value=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 "
            "Safari/537.36 PrismaAccessBrowser/1.0"
        ),
        note="Chrome-compatible UA with a configured Prisma identification component",
    ),
    UserAgentOption(
        name="SOC testing browser",
        value=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 "
            "Safari/537.36 soc_testing/1.0"
        ),
        note="contains the explicit soc_testing marker",
    ),
    UserAgentOption(
        name="Axios 1.7.9 token-replay indicator",
        value="axios/1.7.9",
        note="observed by Microsoft in token-theft activity; Axios itself is legitimate",
    ),
)

DEFAULT_USER_AGENT = USER_AGENT_OPTIONS[0]


class RedirectBlocked(HTTPRedirectHandler):
    """Return redirects to the caller instead of following them automatically."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class ResponseSnapshot:
    request_url: str
    validation_id: str
    user_agent: str
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_truncated: bool
    tls_verified: bool

    def header(self, name: str) -> str | None:
        wanted = name.casefold()
        for header_name, value in self.headers:
            if header_name.casefold() == wanted:
                return value
        return None


def normalize_url(raw_url: str) -> str:
    """Normalize an operator-entered URL and reject ambiguous forms."""

    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("A URL is required.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    if parts.scheme.casefold() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ValueError("The URL must contain a hostname.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials embedded in URLs are not supported.")

    # URL fragments are browser-local and are never sent in an HTTP request.
    return urlunsplit((parts.scheme.casefold(), parts.netloc, parts.path or "/", parts.query, ""))


def redirect_target(current_url: str, location: str) -> str:
    """Resolve a relative Location header and validate the resulting URL."""

    return normalize_url(urljoin(current_url, location))


def build_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def send_once(
    url: str,
    *,
    verify_tls: bool = True,
    user_agent: str = DEFAULT_USER_AGENT.value,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ResponseSnapshot:
    """Send one GET and capture its response without following redirects."""

    normalized_url = normalize_url(url)
    validation_id = str(uuid.uuid4())
    request = Request(
        normalized_url,
        method="GET",
        headers={
            "User-Agent": user_agent,
            CORRELATION_HEADER: validation_id,
            "Accept": "*/*",
        },
    )
    opener = build_opener(
        HTTPSHandler(context=build_ssl_context(verify_tls)),
        RedirectBlocked(),
    )

    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        # With redirects blocked, urllib exposes 3xx responses as HTTPError.
        # Other HTTP error responses are also useful validation evidence.
        response = exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ConnectionError(f"Request failed: {reason}") from exc
    except (TimeoutError, ssl.SSLError) as exc:
        raise ConnectionError(f"Request failed: {exc}") from exc

    with response:
        body = response.read(max_body_bytes + 1)
        truncated = len(body) > max_body_bytes
        if truncated:
            body = body[:max_body_bytes]
        return ResponseSnapshot(
            request_url=normalized_url,
            validation_id=validation_id,
            user_agent=user_agent,
            status=response.getcode(),
            reason=str(getattr(response, "reason", "")),
            headers=tuple(response.headers.items()),
            body=body,
            body_truncated=truncated,
            tls_verified=verify_tls,
        )


def get_public_egress_ip(
    *,
    endpoint: str = PUBLIC_IP_ENDPOINT,
    verify_tls: bool = True,
    user_agent: str = DEFAULT_USER_AGENT.value,
) -> str:
    """Return the public IPv4 or IPv6 address observed by an echo service."""

    snapshot = send_once(
        endpoint,
        verify_tls=verify_tls,
        user_agent=user_agent,
        max_body_bytes=1024,
    )
    if not 200 <= snapshot.status < 300:
        raise ConnectionError(
            f"IP echo service returned HTTP {snapshot.status} {snapshot.reason}".rstrip()
        )
    try:
        payload = json.loads(snapshot.body.decode("utf-8"))
        reported_address = payload["ip"]
        parsed_address = ipaddress.ip_address(reported_address)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectionError("IP echo service returned an invalid address.") from exc
    return str(parsed_address)

