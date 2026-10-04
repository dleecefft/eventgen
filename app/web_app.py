"""Authenticated Flask MVP for controlled external web validation."""

from __future__ import annotations

import hmac
import io
import ipaddress
import json
import os
import secrets
import socket
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from app.http_client import (
    TLS_WARNING,
    USER_AGENT_OPTIONS,
    ResponseSnapshot,
    get_public_egress_ips,
    normalize_url,
    redirect_target,
    send_once,
)
from app.certificate_inspector import inspect_certificate_chain
from app.waf_tester import WafRunManager, create_waf_blueprint


APP_VERSION = "0.2.1"
USERNAME_ENV = "EVENTGEN_USERNAME"
PASSWORD_ENV = "EVENTGEN_PASSWORD"
SECRET_KEY_ENV = "EVENTGEN_SECRET_KEY"
ALLOWED_HOSTS_ENV = "EVENTGEN_ALLOWED_HOSTS"
SESSION_DIR_ENV = "EVENTGEN_SESSION_DIR"
SECURE_COOKIES_ENV = "EVENTGEN_SECURE_COOKIES"

SENSITIVE_QUERY_FRAGMENTS = (
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "code",
    "credential",
    "key",
    "password",
    "secret",
    "session",
    "token",
)
SENSITIVE_RESPONSE_HEADERS = {
    "authentication-info",
    "proxy-authenticate",
    "set-cookie",
    "www-authenticate",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def parse_allowed_hosts(value: str) -> tuple[str, ...]:
    patterns = tuple(
        pattern.strip().casefold().rstrip(".")
        for pattern in value.split(",")
        if pattern.strip()
    )
    if not patterns:
        raise RuntimeError(f"{ALLOWED_HOSTS_ENV} must contain at least one hostname pattern.")
    if any(pattern in {"*", "*.*"} for pattern in patterns):
        raise RuntimeError(f"{ALLOWED_HOSTS_ENV} cannot allow every hostname.")
    return patterns


def hostname_is_allowed(hostname: str, patterns: tuple[str, ...]) -> bool:
    hostname = hostname.casefold().rstrip(".")
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.endswith(suffix) and hostname != suffix[1:]:
                return True
        elif hostname == pattern:
            return True
    return False


def validate_target(url: str, allowed_hosts: tuple[str, ...]) -> str:
    """Validate scheme, configured scope, port, and all current DNS answers."""

    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    hostname = parts.hostname
    if hostname is None or not hostname_is_allowed(hostname, allowed_hosts):
        raise ValueError("The destination hostname is outside the configured target scope.")

    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("The destination contains an invalid port.") from exc
    if port not in {80, 443}:
        raise ValueError("Only destination ports 80 and 443 are allowed in the web MVP.")

    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Destination DNS resolution failed: {exc}") from exc

    addresses = {answer[4][0] for answer in answers}
    if not addresses:
        raise ValueError("Destination DNS resolution returned no addresses.")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("Destination DNS returned an invalid address.") from exc
        if not parsed.is_global:
            raise ValueError(
                "The destination resolved to a private, local, reserved, or otherwise "
                "non-public address."
            )
    return normalized


def sanitize_url_for_log(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[INVALID URL REDACTED]"
    sanitized_query: list[tuple[str, str]] = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        normalized_name = name.casefold()
        if any(fragment in normalized_name for fragment in SENSITIVE_QUERY_FRAGMENTS):
            value = "[REDACTED]"
        sanitized_query.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(sanitized_query), "")
    )


def sanitize_response_headers(
    headers: tuple[tuple[str, str], ...],
) -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "value": "[REDACTED]"
            if name.casefold() in SENSITIVE_RESPONSE_HEADERS
            else value,
        }
        for name, value in headers
    ]


def body_preview(snapshot: ResponseSnapshot) -> str:
    return snapshot.body.decode("utf-8", errors="replace")


class SessionLogStore:
    """Append-only per-browser-session JSONL storage on disposable local disk."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, session_id: str) -> Path:
        if not session_id or any(character not in "0123456789abcdef" for character in session_id):
            raise ValueError("Invalid session identifier.")
        return self.root / f"{session_id}.jsonl"

    def append(self, session_id: str, event: dict[str, object]) -> None:
        record = {"timestamp_utc": utc_now(), **event}
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self._path(session_id).open("a", encoding="utf-8") as output:
            output.write(encoded)
            output.write("\n")

    def read(self, session_id: str) -> list[dict[str, object]]:
        path = self._path(session_id)
        if not path.exists():
            return []
        with self._lock, path.open("r", encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]


def create_app(test_config: dict[str, object] | None = None) -> Flask:
    username = os.getenv(USERNAME_ENV)
    password = os.getenv(PASSWORD_ENV)
    allowed_hosts_value = os.getenv(ALLOWED_HOSTS_ENV)
    missing = [
        name
        for name, value in (
            (USERNAME_ENV, username),
            (PASSWORD_ENV, password),
            (ALLOWED_HOSTS_ENV, allowed_hosts_value),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    allowed_hosts = parse_allowed_hosts(allowed_hosts_value or "")
    session_root = Path(
        os.getenv(SESSION_DIR_ENV, os.path.join(tempfile.gettempdir(), "eventgen_sessions"))
    )

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv(SECRET_KEY_ENV) or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=env_bool(SECURE_COOKIES_ENV, True),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    log_store = SessionLogStore(session_root)
    app.extensions["eventgen_log_store"] = log_store
    app.extensions["eventgen_allowed_hosts"] = allowed_hosts

    def session_id() -> str:
        value = session.get("eventgen_session_id")
        if not isinstance(value, str):
            value = secrets.token_hex(16)
            session["eventgen_session_id"] = value
        return value

    def csrf_token() -> str:
        value = session.get("csrf_token")
        if not isinstance(value, str):
            value = secrets.token_urlsafe(32)
            session["csrf_token"] = value
        return value

    waf_manager = WafRunManager(
        target_validator=lambda url: validate_target(url, allowed_hosts),
        log_store=log_store,
        url_sanitizer=sanitize_url_for_log,
        response_header_sanitizer=sanitize_response_headers,
    )
    app.extensions["eventgen_waf_manager"] = waf_manager

    def unauthorized() -> Response:
        return Response(
            "Authentication required.\n",
            401,
            {"WWW-Authenticate": 'Basic realm="EventGen", charset="UTF-8"'},
            mimetype="text/plain",
        )

    @app.before_request
    def authenticate_and_protect_forms() -> Response | None:
        if request.endpoint == "healthz":
            return None
        authorization = request.authorization
        if (
            authorization is None
            or (authorization.type or "").casefold() != "basic"
            or not hmac.compare_digest(authorization.username or "", username or "")
            or not hmac.compare_digest(authorization.password or "", password or "")
        ):
            return unauthorized()

        session_id()
        expected_csrf = csrf_token()
        if request.method == "POST":
            submitted_csrf = request.form.get("csrf_token", "")
            if not hmac.compare_digest(submitted_csrf, expected_csrf):
                abort(400, description="Invalid or missing CSRF token.")
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.context_processor
    def template_context() -> dict[str, object]:
        return {
            "csrf_token": csrf_token(),
            "app_version": APP_VERSION,
            "session_event_count": len(log_store.read(session_id())),
        }

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "ok"})

    @app.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            user_agents=USER_AGENT_OPTIONS,
            tls_warning=TLS_WARNING,
            allowed_hosts=allowed_hosts,
        )

    @app.post("/request")
    def make_request() -> str | Response:
        raw_url = request.form.get("url", "")
        verify_tls = request.form.get("verify_tls") == "on"
        try:
            user_agent_index = int(request.form.get("user_agent_index", "0"))
            user_agent = USER_AGENT_OPTIONS[user_agent_index]
            if user_agent_index < 0:
                raise IndexError
            validated_url = validate_target(raw_url, allowed_hosts)
            snapshot = send_once(
                validated_url,
                verify_tls=verify_tls,
                user_agent=user_agent.value,
            )
        except (ConnectionError, IndexError, ValueError) as exc:
            log_store.append(
                session_id(),
                {
                    "event_type": "request_error",
                    "url": sanitize_url_for_log(raw_url),
                    "tls_verified": verify_tls,
                    "error": str(exc),
                },
            )
            flash(str(exc), "error")
            return redirect(url_for("index"))

        location = snapshot.header("Location")
        resolved_redirect = None
        if snapshot.status in {300, 301, 302, 303, 305, 307, 308} and location:
            try:
                resolved_redirect = redirect_target(snapshot.request_url, location)
            except ValueError:
                resolved_redirect = None

        log_store.append(
            session_id(),
            {
                "event_type": "request",
                "request": {
                    "method": "GET",
                    "url": sanitize_url_for_log(snapshot.request_url),
                    "validation_id": snapshot.validation_id,
                    "user_agent": snapshot.user_agent,
                    "tls_verified": snapshot.tls_verified,
                },
                "response": {
                    "status": snapshot.status,
                    "reason": snapshot.reason,
                    "headers": sanitize_response_headers(snapshot.headers),
                    "body_preview": body_preview(snapshot),
                    "body_truncated": snapshot.body_truncated,
                    "redirect_location": location,
                    "resolved_redirect": sanitize_url_for_log(resolved_redirect)
                    if resolved_redirect
                    else None,
                },
            },
        )
        return render_template(
            "response.html",
            snapshot=snapshot,
            response_body=body_preview(snapshot),
            response_headers=sanitize_response_headers(snapshot.headers),
            user_agent_index=user_agent_index,
            resolved_redirect=resolved_redirect,
            location=location,
            tls_warning=TLS_WARNING,
        )

    @app.post("/drop-redirect")
    def drop_redirect() -> Response:
        source_url = request.form.get("source_url", "")
        target_url = request.form.get("target_url", "")
        log_store.append(
            session_id(),
            {
                "event_type": "redirect_dropped",
                "source_url": sanitize_url_for_log(source_url),
                "target_url": sanitize_url_for_log(target_url),
            },
        )
        flash("Redirect dropped. No request was sent to the redirect target.", "success")
        return redirect(url_for("index"))

    @app.post("/public-ip")
    def public_ip() -> Response:
        verify_tls = request.form.get("verify_tls") == "on"
        try:
            user_agent_index = int(request.form.get("user_agent_index", "0"))
            user_agent = USER_AGENT_OPTIONS[user_agent_index]
            if user_agent_index < 0:
                raise IndexError
            addresses = get_public_egress_ips(
                verify_tls=verify_tls,
                user_agent=user_agent.value,
            )
        except (ConnectionError, IndexError, ValueError) as exc:
            log_store.append(
                session_id(),
                {"event_type": "public_ip_error", "error": str(exc)},
            )
            flash(f"Unable to determine public egress IP: {exc}", "error")
        else:
            log_store.append(
                session_id(),
                {
                    "event_type": "public_ip_observed",
                    # Preserve the original single-address fields for existing
                    # report consumers while adding explicit dual-stack data.
                    "public_ip": addresses.ipv4 or addresses.ipv6,
                    "service": addresses.ipv4_service
                    if addresses.ipv4
                    else addresses.ipv6_service,
                    "public_ips": addresses.to_dict(),
                    "tls_verified": verify_tls,
                    "user_agent": user_agent.value,
                },
            )
            observations = [
                f"IPv4: {addresses.ipv4 or 'unavailable'}",
                f"IPv6: {addresses.ipv6 or 'unavailable'}",
            ]
            flash(f"Public egress IPs — {'; '.join(observations)}", "success")
        return redirect(url_for("index"))

    @app.post("/certificate-chain")
    def certificate_chain() -> str | Response:
        raw_url = request.form.get("url", "")
        verify_tls = request.form.get("verify_tls") == "on"
        try:
            validated_url = validate_target(raw_url, allowed_hosts)
            chain = inspect_certificate_chain(
                validated_url,
                verify_tls=verify_tls,
            )
        except (ConnectionError, ValueError) as exc:
            log_store.append(
                session_id(),
                {
                    "event_type": "certificate_chain_error",
                    "url": sanitize_url_for_log(raw_url),
                    "tls_verified": verify_tls,
                    "error": str(exc),
                },
            )
            flash(str(exc), "error")
            return redirect(url_for("index"))

        log_store.append(
            session_id(),
            {
                "event_type": "certificate_chain_observed",
                "certificate_chain": chain.to_dict(),
            },
        )
        return render_template(
            "certificate_chain.html",
            chain=chain,
            tls_warning=TLS_WARNING,
        )

    @app.get("/session-log.json")
    def download_session_log() -> Response:
        current_session_id = session_id()
        log_store.append(
            current_session_id,
            {"event_type": "session_log_downloaded"},
        )
        report = {
            "schema_version": 1,
            "application": "eventgen",
            "application_version": APP_VERSION,
            "generated_at_utc": utc_now(),
            "session_id": current_session_id,
            "ephemeral_storage": True,
            "events": log_store.read(current_session_id),
        }
        content = io.BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))
        return send_file(
            content,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"eventgen-session-{current_session_id}.json",
            max_age=0,
        )

    app.register_blueprint(
        create_waf_blueprint(
            manager=waf_manager,
            session_id=session_id,
            target_validator=lambda url: validate_target(url, allowed_hosts),
        )
    )

    return app
