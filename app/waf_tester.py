"""Bounded, request-driven WAF validation workflow for EventGen."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import quote, urlsplit

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for

from app.http_client import TLS_WARNING, USER_AGENT_OPTIONS, ResponseSnapshot, send_once


MAX_MARKERS = 3
MAX_REQUESTS = 25
MAX_TEMPLATE_LENGTH = 8 * 1024
MAX_PAYLOAD_LENGTH = 2 * 1024
MARKERS = ("[replaceme]", "[replaceme2]", "[replaceme3]")
RATE_PROFILES = {"fast": 5, "standard": 15, "slow": 60}
SUBSTITUTION_MODES = {"isolated", "synchronized"}
REDIRECT_STATUSES = {300, 301, 302, 303, 305, 307, 308}
PAYLOAD_PACK_PATH = Path(__file__).with_name("payloads") / "waf_xss_core.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class LogStore(Protocol):
    def append(self, session_id: str, event: dict[str, object]) -> None: ...


@dataclass(frozen=True)
class WafPayload:
    id: str
    category: str
    logical_value: str
    description: str
    source: str
    source_url: str
    reviewed_at: str


@dataclass(frozen=True)
class PayloadPack:
    name: str
    version: str
    digest_sha256: str
    payloads: tuple[WafPayload, ...]


@dataclass(frozen=True)
class MarkerPosition:
    marker: str
    location: str
    parameter_name: str | None = None


@dataclass(frozen=True)
class PlannedRequest:
    sequence: int
    validation_id: str
    payload_id: str
    category: str
    logical_value: str
    encoded_value: str
    active_markers: tuple[str, ...]
    marker_values: tuple[tuple[str, str], ...]
    url: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["marker_values"] = dict(self.marker_values)
        return value


@dataclass(frozen=True)
class WafPlan:
    preview_id: str
    owner_session_id: str
    created_at_utc: str
    run_correlation_prefix: str
    url_template: str
    substitution_mode: str
    marker_positions: tuple[MarkerPosition, ...]
    requests: tuple[PlannedRequest, ...]
    rate_name: str
    interval_seconds: int
    user_agent_index: int
    user_agent: str
    verify_tls: bool
    payload_pack_name: str
    payload_pack_version: str
    payload_pack_digest: str

    @property
    def estimated_spacing_seconds(self) -> int:
        return max(0, len(self.requests) - 1) * self.interval_seconds

    def to_dict(self) -> dict[str, object]:
        return {
            "preview_id": self.preview_id,
            "created_at_utc": self.created_at_utc,
            "run_correlation_prefix": self.run_correlation_prefix,
            "url_template": self.url_template,
            "substitution_mode": self.substitution_mode,
            "marker_positions": [asdict(item) for item in self.marker_positions],
            "requests": [item.to_dict() for item in self.requests],
            "rate_name": self.rate_name,
            "interval_seconds": self.interval_seconds,
            "estimated_spacing_seconds": self.estimated_spacing_seconds,
            "user_agent_index": self.user_agent_index,
            "user_agent": self.user_agent,
            "tls_verified": self.verify_tls,
            "payload_pack": {
                "name": self.payload_pack_name,
                "version": self.payload_pack_version,
                "digest_sha256": self.payload_pack_digest,
            },
        }


@dataclass
class WafRun:
    run_id: str
    owner_session_id: str
    plan: WafPlan
    state: str = "ready"
    current_index: int = 0
    created_at_utc: str = field(default_factory=utc_now)
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    last_request_at_utc: str | None = None
    next_eligible_monotonic: float = 0.0
    stop_reason: str | None = None
    results: list[dict[str, object]] = field(default_factory=list)

    @property
    def is_finished(self) -> bool:
        return self.state in {"cancelled", "completed", "failed"}


class RateLimitError(RuntimeError):
    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = max(0.0, retry_after_seconds)
        super().__init__(
            f"The next request is available in {self.retry_after_seconds:.1f} seconds."
        )


class RunConflictError(RuntimeError):
    pass


def load_payload_pack(path: Path = PAYLOAD_PACK_PATH) -> PayloadPack:
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    payloads = tuple(
        WafPayload(
            id=item["id"],
            category=item["category"],
            logical_value=item["logical_value"],
            description=item["description"],
            source=item["source"],
            source_url=item["source_url"],
            reviewed_at=item["reviewed_at"],
        )
        for item in document["payloads"]
        if item.get("enabled", False)
    )
    if not payloads:
        raise RuntimeError("The WAF payload pack contains no enabled payloads.")
    if any(len(item.logical_value) > MAX_PAYLOAD_LENGTH for item in payloads):
        raise RuntimeError("The WAF payload pack contains an oversized payload.")
    return PayloadPack(
        name=document["name"],
        version=document["version"],
        digest_sha256=hashlib.sha256(raw).hexdigest(),
        payloads=payloads,
    )


def inspect_template(url_template: str) -> tuple[str, tuple[MarkerPosition, ...]]:
    """Validate marker syntax and return the normalized template and positions."""

    template = url_template.strip()
    if not template:
        raise ValueError("A URL template is required.")
    if len(template) > MAX_TEMPLATE_LENGTH:
        raise ValueError("The URL template exceeds the 8 KiB limit.")
    if "#" in template:
        raise ValueError("URL fragments are browser-only and are not supported in a WAF template.")

    try:
        parts = urlsplit(template)
        port = parts.port
    except ValueError as exc:
        raise ValueError("The URL template is invalid.") from exc
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Enter a complete http:// or https:// URL template.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials embedded in URLs are not supported.")
    del port

    bracket_candidates: set[str] = set()
    cursor = 0
    while True:
        start = template.find("[replaceme", cursor)
        if start < 0:
            break
        end = template.find("]", start)
        if end < 0:
            bracket_candidates.add(template[start:])
            break
        bracket_candidates.add(template[start : end + 1])
        cursor = end + 1
    unknown = sorted(candidate for candidate in bracket_candidates if candidate not in MARKERS)
    if unknown:
        raise ValueError(f"Unsupported replacement marker: {unknown[0]}")

    counts = [template.count(marker) for marker in MARKERS]
    if counts[0] != 1:
        raise ValueError("The template must contain [replaceme] exactly once.")
    if any(count > 1 for count in counts):
        raise ValueError("Each replacement marker may appear only once.")
    if counts[2] and not counts[1]:
        raise ValueError("[replaceme3] requires [replaceme2].")
    marker_count = sum(counts)
    if marker_count > MAX_MARKERS:
        raise ValueError("A maximum of three replacement markers is supported.")

    authority = f"{parts.scheme}://{parts.netloc}"
    if any(marker in authority for marker in MARKERS):
        raise ValueError("Replacement markers are not allowed in the scheme, hostname, or port.")

    positions: list[MarkerPosition] = []
    for marker in MARKERS[:marker_count]:
        if marker in parts.path:
            positions.append(MarkerPosition(marker=marker, location="path"))
            continue
        found_parameter: str | None = None
        for component in parts.query.split("&") if parts.query else ():
            name, separator, value = component.partition("=")
            if marker in name:
                raise ValueError("Replacement markers are not allowed in query-parameter names.")
            if separator and marker in value:
                found_parameter = name
                break
        if found_parameter is None:
            raise ValueError(
                "Replacement markers must be in a path segment or query-parameter value."
            )
        positions.append(
            MarkerPosition(marker=marker, location="query", parameter_name=found_parameter)
        )
    return template, tuple(positions)


def _replace_markers(template: str, mapping: dict[str, str]) -> str:
    result = template
    for marker, logical_value in mapping.items():
        result = result.replace(marker, quote(logical_value, safe=""))
    if len(result) > MAX_TEMPLATE_LENGTH:
        raise ValueError("A generated URL exceeds the 8 KiB limit.")
    return result


def build_plan(
    *,
    owner_session_id: str,
    url_template: str,
    substitution_mode: str,
    rate_name: str,
    user_agent_index: int,
    verify_tls: bool,
    payload_pack: PayloadPack,
    target_validator: Callable[[str], str],
) -> WafPlan:
    if substitution_mode not in SUBSTITUTION_MODES:
        raise ValueError("Choose isolated or synchronized substitution mode.")
    if rate_name not in RATE_PROFILES:
        raise ValueError("Choose the 5, 15, or 60 second rate profile.")
    try:
        user_agent = USER_AGENT_OPTIONS[user_agent_index]
        if user_agent_index < 0:
            raise IndexError
    except IndexError as exc:
        raise ValueError("Choose a valid User-Agent.") from exc

    template, positions = inspect_template(url_template)
    prefix = secrets.token_hex(6)
    control = f"soc_testing_control_{prefix}"
    markers = tuple(item.marker for item in positions)
    requests: list[PlannedRequest] = []

    def append_request(
        payload_id: str,
        category: str,
        logical_value: str,
        active_markers: tuple[str, ...],
        mapping: dict[str, str],
    ) -> None:
        url = _replace_markers(template, mapping)
        validated_url = target_validator(url)
        requests.append(
            PlannedRequest(
                sequence=len(requests) + 1,
                validation_id=(
                    f"{prefix}-{len(requests) + 1:02d}-{payload_id}"
                ),
                payload_id=payload_id,
                category=category,
                logical_value=logical_value,
                encoded_value=quote(logical_value, safe=""),
                active_markers=active_markers,
                marker_values=tuple((marker, mapping[marker]) for marker in markers),
                url=validated_url,
            )
        )

    baseline = {marker: control for marker in markers}
    append_request("benign-control", "control", control, (), baseline)
    if substitution_mode == "isolated":
        for payload in payload_pack.payloads:
            for marker in markers:
                mapping = dict(baseline)
                mapping[marker] = payload.logical_value
                append_request(
                    payload.id,
                    payload.category,
                    payload.logical_value,
                    (marker,),
                    mapping,
                )
    else:
        for payload in payload_pack.payloads:
            mapping = {marker: payload.logical_value for marker in markers}
            append_request(
                payload.id,
                payload.category,
                payload.logical_value,
                markers,
                mapping,
            )

    if len(requests) > MAX_REQUESTS:
        raise ValueError(
            f"The plan contains {len(requests)} requests and exceeds the {MAX_REQUESTS}-request cap."
        )
    return WafPlan(
        preview_id=secrets.token_hex(16),
        owner_session_id=owner_session_id,
        created_at_utc=utc_now(),
        run_correlation_prefix=prefix,
        url_template=template,
        substitution_mode=substitution_mode,
        marker_positions=positions,
        requests=tuple(requests),
        rate_name=rate_name,
        interval_seconds=RATE_PROFILES[rate_name],
        user_agent_index=user_agent_index,
        user_agent=user_agent.value,
        verify_tls=verify_tls,
        payload_pack_name=payload_pack.name,
        payload_pack_version=payload_pack.version,
        payload_pack_digest=payload_pack.digest_sha256,
    )


class WafRunManager:
    """Process-local preview/run state with a global single-request gate."""

    def __init__(
        self,
        *,
        target_validator: Callable[[str], str],
        log_store: LogStore,
        url_sanitizer: Callable[[str], str] = lambda value: value,
        response_header_sanitizer: Callable[
            [tuple[tuple[str, str], ...]], list[dict[str, str]]
        ] = lambda headers: [
            {"name": name, "value": value} for name, value in headers
        ],
        clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], str] = utc_now,
        sender: Callable[..., ResponseSnapshot] = send_once,
    ) -> None:
        self.target_validator = target_validator
        self.log_store = log_store
        self.url_sanitizer = url_sanitizer
        self.response_header_sanitizer = response_header_sanitizer
        self.clock = clock
        self.utc_clock = utc_clock
        self.sender = sender
        self.payload_pack = load_payload_pack()
        self.previews: dict[str, WafPlan] = {}
        self.runs: dict[str, WafRun] = {}
        self.active_run_id: str | None = None
        self._lock = threading.RLock()

    def save_preview(self, plan: WafPlan) -> None:
        with self._lock:
            self.previews[plan.preview_id] = plan

    def get_preview(self, preview_id: str, owner: str) -> WafPlan:
        with self._lock:
            plan = self.previews.get(preview_id)
            if plan is None or plan.owner_session_id != owner:
                raise KeyError("WAF preview not found.")
            return plan

    def create_run(self, preview_id: str, owner: str) -> WafRun:
        with self._lock:
            plan = self.get_preview(preview_id, owner)
            if plan.payload_pack_digest != self.payload_pack.digest_sha256:
                raise ValueError("The payload pack changed after preview. Create a new preview.")
            run = WafRun(run_id=secrets.token_hex(16), owner_session_id=owner, plan=plan)
            self.runs[run.run_id] = run
            del self.previews[preview_id]
            logged_plan = plan.to_dict()
            logged_plan["url_template"] = self.url_sanitizer(plan.url_template)
            for request_record in logged_plan["requests"]:
                request_record["url"] = self.url_sanitizer(str(request_record["url"]))
            self.log_store.append(
                owner,
                {"event_type": "waf_run_created", "run_id": run.run_id, "plan": logged_plan},
            )
            return run

    def get_run(self, run_id: str, owner: str) -> WafRun:
        with self._lock:
            run = self.runs.get(run_id)
            if run is None or run.owner_session_id != owner:
                raise KeyError("WAF run not found.")
            return run

    def resume(self, run_id: str, owner: str) -> WafRun:
        with self._lock:
            run = self.get_run(run_id, owner)
            if run.is_finished:
                raise ValueError("A finished WAF run cannot be resumed.")
            if self.active_run_id not in {None, run_id}:
                raise RunConflictError("Another WAF run is active on this instance.")
            self.active_run_id = run_id
            run.state = "running"
            if run.started_at_utc is None:
                run.started_at_utc = self.utc_clock()
            return run

    def pause(self, run_id: str, owner: str) -> WafRun:
        with self._lock:
            run = self.get_run(run_id, owner)
            if not run.is_finished:
                run.state = "paused"
            if self.active_run_id == run_id:
                self.active_run_id = None
            return run

    def cancel(self, run_id: str, owner: str) -> WafRun:
        with self._lock:
            run = self.get_run(run_id, owner)
            if not run.is_finished:
                run.state = "cancelled"
                run.stop_reason = "Cancelled by operator."
                run.completed_at_utc = self.utc_clock()
                self.log_store.append(
                    owner,
                    {"event_type": "waf_run_cancelled", "run_id": run_id},
                )
            if self.active_run_id == run_id:
                self.active_run_id = None
            return run

    def seconds_until_next(self, run: WafRun) -> float:
        return max(0.0, run.next_eligible_monotonic - self.clock())

    def execute_next(self, run_id: str, owner: str) -> dict[str, object]:
        with self._lock:
            run = self.get_run(run_id, owner)
            if run.is_finished:
                raise ValueError("This WAF run has already finished.")
            if self.active_run_id not in {None, run_id}:
                raise RunConflictError("Another WAF run is active on this instance.")
            remaining = self.seconds_until_next(run)
            if remaining > 0:
                raise RateLimitError(remaining)
            if run.current_index >= len(run.plan.requests):
                self._complete(run)
                raise ValueError("This WAF run has already finished.")

            self.active_run_id = run_id
            if run.started_at_utc is None:
                run.started_at_utc = self.utc_clock()
            planned = run.plan.requests[run.current_index]
            scheduled_at = self.utc_clock()
            started_monotonic = self.clock()
            result: dict[str, object] = {
                "sequence": planned.sequence,
                "scheduled_at_utc": scheduled_at,
                "actual_start_at_utc": scheduled_at,
                "payload_id": planned.payload_id,
                "category": planned.category,
                "logical_value": planned.logical_value,
                "encoded_value": planned.encoded_value,
                "active_markers": list(planned.active_markers),
                "marker_values": dict(planned.marker_values),
                "url": planned.url,
                "user_agent": run.plan.user_agent,
                "tls_verified": run.plan.verify_tls,
                "payload_pack_version": run.plan.payload_pack_version,
                "payload_pack_digest": run.plan.payload_pack_digest,
            }
            try:
                validated_url = self.target_validator(planned.url)
                snapshot = self.sender(
                    validated_url,
                    verify_tls=run.plan.verify_tls,
                    user_agent=run.plan.user_agent,
                    validation_id=planned.validation_id,
                )
            except (ConnectionError, ValueError) as exc:
                result.update(
                    {
                        "outcome": "error",
                        "error": str(exc),
                        "elapsed_ms": round((self.clock() - started_monotonic) * 1000, 1),
                    }
                )
            else:
                location = snapshot.header("Location")
                result.update(
                    {
                        "outcome": "response",
                        "validation_id": snapshot.validation_id,
                        "status": snapshot.status,
                        "reason": snapshot.reason,
                        "elapsed_ms": round((self.clock() - started_monotonic) * 1000, 1),
                        "response_size": len(snapshot.body),
                        "body_truncated": snapshot.body_truncated,
                        "redirect_location": location if snapshot.status in REDIRECT_STATUSES else None,
                        "target_date_header": snapshot.header("Date"),
                        "response_headers": self.response_header_sanitizer(snapshot.headers),
                        "body_preview": snapshot.body.decode("utf-8", errors="replace"),
                    }
                )

            run.results.append(result)
            run.current_index += 1
            run.last_request_at_utc = self.utc_clock()
            run.next_eligible_monotonic = started_monotonic + run.plan.interval_seconds
            logged_result = dict(result)
            logged_result["url"] = self.url_sanitizer(str(result["url"]))
            self.log_store.append(
                owner,
                {"event_type": "waf_request", "run_id": run_id, "result": logged_result},
            )
            if run.current_index >= len(run.plan.requests):
                self._complete(run)
            elif run.state != "running":
                run.state = "paused"
                if self.active_run_id == run_id:
                    self.active_run_id = None
            return result

    def _complete(self, run: WafRun) -> None:
        run.state = "completed"
        run.completed_at_utc = self.utc_clock()
        if self.active_run_id == run.run_id:
            self.active_run_id = None
        self.log_store.append(
            run.owner_session_id,
            {"event_type": "waf_run_completed", "run_id": run.run_id},
        )


def create_waf_blueprint(
    *,
    manager: WafRunManager,
    session_id: Callable[[], str],
    target_validator: Callable[[str], str],
) -> Blueprint:
    blueprint = Blueprint("waf", __name__, url_prefix="/waf")

    def owned_run(run_id: str) -> WafRun:
        try:
            return manager.get_run(run_id, session_id())
        except KeyError:
            abort(404)

    @blueprint.get("")
    def configure() -> str:
        return render_template(
            "waf_configure.html",
            user_agents=USER_AGENT_OPTIONS,
            payload_pack=manager.payload_pack,
            rate_profiles=RATE_PROFILES,
            tls_warning=TLS_WARNING,
        )

    @blueprint.post("/preview")
    def preview() -> str | Response:
        raw_url = request.form.get("url_template", "")
        verify_tls = request.form.get("verify_tls") == "on"
        try:
            user_agent_index = int(request.form.get("user_agent_index", "0"))
            plan = build_plan(
                owner_session_id=session_id(),
                url_template=raw_url,
                substitution_mode=request.form.get("substitution_mode", "isolated"),
                rate_name=request.form.get("rate_name", "standard"),
                user_agent_index=user_agent_index,
                verify_tls=verify_tls,
                payload_pack=manager.payload_pack,
                target_validator=target_validator,
            )
            if plan.rate_name == "fast" and request.form.get("confirm_fast") != "on":
                raise ValueError("Confirm the 5-second maximum rate before previewing.")
        except (TypeError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("waf.configure"))
        manager.save_preview(plan)
        return render_template("waf_preview.html", plan=plan, tls_warning=TLS_WARNING)

    @blueprint.post("/runs")
    def create_run_route() -> Response:
        try:
            run = manager.create_run(request.form.get("preview_id", ""), session_id())
        except KeyError:
            abort(404)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("waf.configure"))
        return redirect(url_for("waf.run_detail", run_id=run.run_id))

    @blueprint.get("/runs/<run_id>")
    def run_detail(run_id: str) -> str:
        run = owned_run(run_id)
        return render_template(
            "waf_run.html",
            run=run,
            seconds_until_next=manager.seconds_until_next(run),
            tls_warning=TLS_WARNING,
        )

    @blueprint.post("/runs/<run_id>/resume")
    def resume(run_id: str) -> Response:
        try:
            manager.resume(run_id, session_id())
        except KeyError:
            abort(404)
        except (RunConflictError, ValueError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("waf.run_detail", run_id=run_id))

    @blueprint.post("/runs/<run_id>/pause")
    def pause(run_id: str) -> Response:
        try:
            manager.pause(run_id, session_id())
        except KeyError:
            abort(404)
        return redirect(url_for("waf.run_detail", run_id=run_id))

    @blueprint.post("/runs/<run_id>/cancel")
    def cancel(run_id: str) -> Response:
        try:
            manager.cancel(run_id, session_id())
        except KeyError:
            abort(404)
        return redirect(url_for("waf.run_detail", run_id=run_id))

    @blueprint.post("/runs/<run_id>/next")
    def execute_next(run_id: str) -> Response:
        try:
            manager.execute_next(run_id, session_id())
        except KeyError:
            abort(404)
        except RateLimitError as exc:
            response = redirect(url_for("waf.run_detail", run_id=run_id))
            response.status_code = 429
            response.headers["Retry-After"] = str(max(1, round(exc.retry_after_seconds)))
            return response
        except RunConflictError as exc:
            flash(str(exc), "error")
            response = redirect(url_for("waf.run_detail", run_id=run_id))
            response.status_code = 409
            return response
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("waf.run_detail", run_id=run_id))

    return blueprint
