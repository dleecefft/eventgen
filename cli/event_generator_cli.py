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
    "EVENT_GENERATOR_IP_ECHO_URL",
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


def _print_rule(character: str = "-") -> None:
    print(character * 72)


def _print_headers(headers: Iterable[tuple[str, str]]) -> None:
    for name, value in headers:
        print(f"{name}: {value}")


def _decode_body(snapshot: ResponseSnapshot) -> str:
    content_type = snapshot.header("Content-Type") or ""
    charset = "utf-8"
    for item in content_type.split(";")[1:]:
        name, separator, value = item.strip().partition("=")
        if separator and name.casefold() == "charset":
            charset = value.strip(' "\'') or charset
            break
    try:
        return snapshot.body.decode(charset, errors="replace")
    except LookupError:
        return snapshot.body.decode("utf-8", errors="replace")


def display_response(snapshot: ResponseSnapshot) -> None:
    print()
    _print_rule("=")
    if not snapshot.tls_verified:
        print(TLS_WARNING)
        _print_rule("!")
    print(f"URL:            {snapshot.request_url}")
    print(f"Validation ID:  {snapshot.validation_id}")
    print(f"User-Agent:     {snapshot.user_agent}")
    print(f"TLS verified:   {'yes' if snapshot.tls_verified else 'NO'}")
    print(f"Status:         {snapshot.status} {snapshot.reason}".rstrip())
    print("Response headers:")
    _print_headers(snapshot.headers)
    _print_rule()
    print("Response body preview:")
    print(_decode_body(snapshot))
    if snapshot.body_truncated:
        print(f"\n[Body preview truncated at {len(snapshot.body)} bytes]")
    _print_rule("=")


def request_flow(
    initial_url: str,
    *,
    verify_tls: bool,
    user_agent: str = DEFAULT_USER_AGENT.value,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> None:
    """Send a request and let the operator approve each redirect."""

    current_url = normalize_url(initial_url)
    visited: set[str] = set()

    for redirect_number in range(max_redirects + 1):
        if current_url in visited:
            print(f"Redirect loop detected at {current_url}; dropping the request chain.")
            return
        visited.add(current_url)

        print(f"\nSending GET {current_url}")
        print(f"User-Agent: {user_agent}")
        if not verify_tls:
            print(TLS_WARNING)

        try:
            snapshot = send_once(
                current_url,
                verify_tls=verify_tls,
                user_agent=user_agent,
            )
        except (ConnectionError, ValueError) as exc:
            print(f"ERROR: {exc}")
            return

        display_response(snapshot)
        location = snapshot.header("Location")
        if snapshot.status not in {300, 301, 302, 303, 305, 307, 308} or not location:
            print("Request complete; there is no redirect to review.")
            return

        try:
            next_url = redirect_target(current_url, location)
        except ValueError as exc:
            print(f"Unsafe or invalid redirect target: {exc}")
            return

        print(f"Redirect Location: {location}")
        print(f"Resolved target:   {next_url}")
        while True:
            action = input("[P]roceed to redirect or [D]rop? ").strip().casefold()
            if action in {"p", "proceed"}:
                current_url = next_url
                break
            if action in {"d", "drop", ""}:
                print("Redirect dropped. No request was sent to the redirect target.")
                return
            print("Enter P to proceed or D to drop.")

        if redirect_number == max_redirects:
            print(f"Maximum redirect count ({max_redirects}) reached; dropping the chain.")
            return


def select_user_agent(current: UserAgentOption) -> UserAgentOption:
    """Display the numbered catalog and return the operator's selection."""

    print("\nAvailable User-Agent profiles:")
    for index, option in enumerate(USER_AGENT_OPTIONS):
        selected = " *" if option is current else ""
        note = f" - {option.note}" if option.note else ""
        print(f"[{index}] {option.name}{note}{selected}")
        print(f"    {option.value}")

    while True:
        raw_choice = input(
            f"Select User-Agent [0-{len(USER_AGENT_OPTIONS) - 1}] "
            "or press Enter to keep the current selection: "
        ).strip()
        if not raw_choice:
            return current
        try:
            selected_index = int(raw_choice)
            if not 0 <= selected_index < len(USER_AGENT_OPTIONS):
                raise ValueError
            return USER_AGENT_OPTIONS[selected_index]
        except ValueError:
            print(f"Enter a number from 0 to {len(USER_AGENT_OPTIONS) - 1}.")


def main() -> int:
    verify_tls = True
    selected_user_agent = DEFAULT_USER_AGENT

    print("External Web Log and WAF Validation CLI")
    print("Requests are sent one at a time and redirects are never automatic.")

    while True:
        print()
        print("1. Send a GET request")
        print(f"2. Select User-Agent (currently {selected_user_agent.name})")
        print("3. Show public egress IP")
        print(f"4. Toggle TLS verification (currently {'ON' if verify_tls else 'OFF'})")
        print("Q. Quit")
        choice = input("Select an option: ").strip().casefold()

        if choice == "1":
            raw_url = input("URL: ")
            try:
                request_flow(
                    raw_url,
                    verify_tls=verify_tls,
                    user_agent=selected_user_agent.value,
                )
            except ValueError as exc:
                print(f"ERROR: {exc}")
        elif choice == "2":
            selected_user_agent = select_user_agent(selected_user_agent)
            print(f"User-Agent set to: {selected_user_agent.name}")
        elif choice == "3":
            print(f"Contacting IP echo service: {PUBLIC_IP_ENDPOINT}")
            if not verify_tls:
                print(TLS_WARNING)
            try:
                public_ip = get_public_egress_ip(
                    verify_tls=verify_tls,
                    user_agent=selected_user_agent.value,
                )
                print(f"Public egress IP: {public_ip}")
                print("Use this address when searching ingress, proxy, or WAF events.")
            except (ConnectionError, ValueError) as exc:
                print(f"ERROR: Unable to determine public egress IP: {exc}")
        elif choice == "4":
            verify_tls = not verify_tls
            if verify_tls:
                print("TLS certificate verification is now ON.")
            else:
                _print_rule("!")
                print(TLS_WARNING)
                _print_rule("!")
        elif choice in {"q", "quit", "exit"}:
            print("Goodbye.")
            return 0
        else:
            print("Enter 1, 2, 3, 4, or Q.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped by operator.")
        sys.exit(130)
