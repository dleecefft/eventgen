# Intruder-Style WAF Tester Plan

## Goal

Add a deliberately slow GET-only WAF validation workflow to the Flask
application. An analyst supplies a complete approved URL containing between one
and three named replacement markers, selects a reviewed payload profile and a
speed, previews the exact requests, and then runs them sequentially.

Example template:

```text
https://testingsite.com/search/[replaceme]
```

Query-parameter example with two inputs:

```text
https://testingsite.com/search?customer=[replaceme]&city=[replaceme2]
```

The first release is intended to create searchable WAF and ingress events. It
is not a crawler, exploit framework, vulnerability verdict engine, or general
purpose Burp Intruder replacement.

## MVP operator workflow

1. Open **WAF Tester** from the authenticated application.
2. Enter a complete `https://` URL containing one to three supported markers:
   `[replaceme]`, `[replaceme2]`, and `[replaceme3]`. Markers may be in path
   segments or query-parameter values, but never in the scheme, hostname, port,
   or query-parameter name.
3. Select:
   - a built-in, versioned payload profile;
   - isolated or synchronized substitution mode when multiple markers exist;
   - a User-Agent from the existing catalog;
   - TLS verification on or explicitly off; and
   - one of the three fixed speeds.
4. Select **Preview**. No target request is sent at this stage.
5. Review the target, payload count, exact encoded URLs, estimated minimum
   duration, selected egress IP, and safety limits.
6. Confirm that the target is authorized and start the run.
7. Watch a results table update one request at a time. The display shows the
   next eligible send time and allows pause, resume, single-step, or stop.
8. Download the session log at any time. A partial run remains useful evidence
   if the operator stops the run or the ephemeral container is removed.

## URL-template and parameter rules

- Require one to three case-sensitive, named markers. `[replaceme]` is required;
  `[replaceme2]` and `[replaceme3]` are optional.
- Require contiguous numbering. For example, `[replaceme]` plus `[replaceme3]`
  without `[replaceme2]` is invalid.
- Permit each named marker exactly once. Reject duplicate markers, unknown
  marker spellings, and `[replaceme4]` or higher rather than guessing intent.
- Parse and validate the template before preview. The scheme and authority must
  be complete without interpreting the marker.
- Permit markers in URL path segments and query-parameter values. Do not permit
  a marker in a query-parameter name because that would change the parameter
  schema between requests.
- Preserve every non-marker character exactly. Do not rebuild or reorder query
  parameters during replacement.
- Percent-encode each logical payload separately as a single URL component
  before literal replacement. Display the complete token-to-value mapping, the
  logical values, and final wire URL in preview.
- Apply the existing hostname allowlist, port restrictions, public-IP checks,
  and TLS policy to the harmless preview URL and again to every generated URL.
- Never follow redirects during a run. Record the response and `Location`
  header, but do not offer automatic redirect continuation from the loop.
- Cap the encoded final URL length. A proposed MVP maximum is 8 KiB, with a
  smaller per-payload logical limit of 2 KiB.

Supporting path and parameter-value placement covers examples such as:

```text
https://testingsite.com/search/[replaceme]
https://testingsite.com/search?q=[replaceme]&environment=test
https://testingsite.com/search?customer=[replaceme]&city=[replaceme2]
https://testingsite.com/search?customer=[replaceme]&city=[replaceme2]&region=[replaceme3]
```

The `&` characters above are ordinary URL query separators. HTML or Markdown
may display them as `&amp;` or escape square brackets, but those presentation
escapes are not part of the URL entered into the application.

## Multiple-input substitution modes

Keep the workflow understandable for SOC analysts by offering only two modes.
Do not reproduce Burp Intruder's full attack-type matrix.

### Isolated positions (default)

Apply each payload to one marker at a time. Replace every other marker with a
fixed benign value containing the run ID, such as `soc_testing_control_<run>`.

For this template:

```text
https://testingsite.com/search?customer=[replaceme]&city=[replaceme2]
```

the planner produces a benign baseline, then a request with the test payload in
`customer` and the benign control in `city`, followed by a request with the
control in `customer` and the test payload in `city`. This makes the resulting
log and WAF evidence attributable to a specific parameter.

Request-count formula, including one baseline:

```text
1 + (payload count * marker count)
```

### Synchronized positions

Apply the same payload to all markers in one request. This supports cases where
multiple populated inputs change WAF normalization, application routing, or log
formatting.

Request-count formula, including one baseline:

```text
1 + payload count
```

### Explicitly out of scope

Do not generate Cartesian combinations where each marker receives a different
payload. With `P` payloads and `M` markers that would create `P^M` requests,
which is unnecessary for the SOC validation use case and conflicts with the
low-volume safety boundary. Per-marker custom payload assignment can be
reconsidered later only if a concrete logging use case requires it.

## Fixed rate profiles

The application, not JavaScript, enforces the interval between request start
times. Runs are always sequential and have zero request concurrency.

| UI option | Minimum interval | Intended use |
| --- | ---: | --- |
| Fast | 5 seconds | Maximum permitted rate for a short, supervised validation |
| Standard | 15 seconds | Default; separates events for log and alert review |
| Slow | 60 seconds | Noisy pipelines, consolidation testing, or manual SOC observation |

Additional enforcement:

- Use a monotonic server clock for rate decisions and UTC for evidence.
- Reject a step request received before `next_eligible_at`; do not merely trust
  or delay in the browser.
- Hold one application-wide run lock as well as a per-session run state. Only
  one WAF run may actively send from an MVP instance.
- Impose a hard cap of 25 requests per run initially, including a benign control
  request if enabled.
- Require explicit confirmation to use the 5-second profile.
- Do not retry automatically. A retry would create a second event and undermine
  correlation.
- A slow response may naturally make the interval longer. Never send the next
  request concurrently to catch up.

For `N` requests, the minimum spacing time is `(N - 1) * interval`, plus network
and response handling time. Preview must calculate this before confirmation.
If a payload pack, marker count, and substitution mode exceed the 25-request
cap, preview must refuse to start and ask the analyst to choose a smaller pack
or synchronized mode. Never truncate the plan silently.

## Payload-pack design

Do not scrape or fetch payloads at runtime. Ship a small reviewed local pack
with the image so a run is reproducible and cannot change between preview and
execution.

The first profile should be a curated subset inspired by the
[OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html),
not a wholesale copy of every example. That source intentionally includes
filter-evasion techniques and examples with external resources or harmful
behavior. Exclude payloads that:

- load a remote script, image, frame, object, or other network resource;
- read cookies, storage, tokens, DOM content, or user data;
- submit data, change state, persist content, or perform post-exploitation;
- depend on a third-party callback domain; or
- are obsolete without adding WAF-validation value.

Use inert `soc_testing` markers in the curated variants. The application only
displays target responses as escaped text and must never render returned HTML.

Each payload record should contain:

```json
{
  "id": "xss-basic-tag-001",
  "category": "xss-basic",
  "logical_value": "reviewed inert test value",
  "description": "Expected WAF signature family",
  "source": "OWASP XSS Filter Evasion Cheat Sheet",
  "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html",
  "reviewed_at": "YYYY-MM-DD",
  "enabled": true
}
```

The checked-in pack should have its own semantic version and SHA-256 digest.
Record both in preview, every run, and the downloaded session log. The initial
categories can cover a benign control, basic markup, attribute/event syntax,
URI-scheme syntax, SVG/event syntax, malformed markup, and selected encoding
variants. Arbitrary file upload and remote payload-list URLs are out of scope
for the first release.

## Cloud Run execution model

Use a request-driven state machine instead of an in-process background thread or
one long HTTP request:

1. `POST /waf/preview` validates the template and builds an immutable plan.
2. `POST /waf/runs` confirms and creates a run record on ephemeral storage.
3. `POST /waf/runs/<run_id>/next` checks authorization, CSRF, state, global
   lock, and `next_eligible_at`, then sends at most one request.
4. `GET /waf/runs/<run_id>` renders current results and the countdown.
5. A small browser timer may call the next-step endpoint when eligible. Closing
   the page pauses progress because there is no detached worker.
6. Pause, resume, single-step, and cancel are explicit state transitions.

This model keeps each Cloud Run request short and ensures work occurs while the
service is processing a request. It also avoids relying on a background thread
after a response, when request-based Cloud Run CPU may not be allocated.

For the ephemeral MVP deployment:

- keep Cloud Run maximum instances at one;
- set container/request concurrency to one for the tester revision, or enforce
  equivalent serialization before sending;
- keep minimum instances at zero so the service can scale down when unused;
- retain the existing single Gunicorn worker;
- store run state and results beside the existing session JSONL evidence; and
- present a clear error if an instance restart loses an unfinished run.

The browser must remain open for automatic progression. A future durable mode
could move run state to Firestore and execution to Cloud Tasks or a Cloud Run
Job, but that is unnecessary for an on-demand MVP.

## Run-state model

Suggested states:

```text
previewed -> ready -> running -> paused -> running
                              -> cancelled
                              -> completed
                              -> failed
```

A run record should contain:

- run ID and owning application session ID;
- created, started, last-request, next-eligible, and completed UTC timestamps;
- original URL template and sanitized display form;
- ordered marker names, their path/query locations, associated query-parameter
  names where applicable, and selected substitution mode;
- payload-pack name, version, digest, and ordered payload IDs;
- speed name and interval seconds;
- selected User-Agent and TLS-verification state;
- current index, total count, state, and stop reason;
- hard request cap and target-policy snapshot; and
- a random run correlation prefix.

The state transition and evidence append for each request should be performed
under the same process lock. Write evidence immediately after every response or
error rather than waiting for the run to finish.

## Request and evidence model

Every generated request receives a unique validation ID derived from the run
correlation prefix and payload ID. Record:

- scheduled and actual start timestamps;
- request sequence number and payload ID;
- logical payload, encoded replacement, sanitized final URL, active marker or
  markers, and the complete marker-to-value mapping;
- payload-pack version and digest;
- selected User-Agent and TLS-verification state;
- validation ID and observed public egress IP;
- response status, reason, latency, size, selected sanitized headers, and
  redirect location;
- bounded escaped-text response preview or response-body hash;
- network/TLS/timeout error without an automatic retry; and
- analyst-entered downstream log ID, alert ID, observed WAF action, and notes.

Do not translate HTTP `403`, `406`, `429`, connection reset, or another response
into a claim that the WAF detected or blocked the payload. Show these as
observations. Keep `waf_detected` and `waf_blocked` unset until the analyst
confirms corresponding downstream evidence.

## UI outline

### Configure and preview

- URL template field with a visible `[replaceme]` example.
- Parameter example using `customer=[replaceme]&city=[replaceme2]` and a visible
  maximum of three markers.
- Payload-profile selector showing pack version and request count.
- Substitution-mode selector shown only when the template has multiple markers:
  **Isolated positions** (default) or **Synchronized positions**.
- Speed radio buttons: 5 seconds, 15 seconds (default), and 60 seconds.
- Existing User-Agent and TLS-verification controls.
- Optional benign-control checkbox, enabled by default.
- Preview table with sequence, payload ID/category, active marker and parameter,
  complete marker mapping, encoded replacement, final URL, and projected
  earliest send time.
- Duration estimate, target hostname, current egress IP, and authorization
  confirmation.

### Run monitor

- State, progress, chosen rate, last send, and next eligible send countdown.
- Pause/resume, send-next, and stop controls.
- Results table with timestamp, validation ID, payload ID, status/error,
  latency, size, and redirect indicator.
- Download-session-log action available throughout the run.
- No target response is rendered as HTML.

## Failure and recovery behavior

- Validation failure: send nothing and keep the operator on preview.
- Individual request failure: record it once, then wait for the next operator or
  timer step; do not retry.
- Browser closes: leave the run paused/incomplete; no hidden work continues.
- Container termination: local state is lost, but any previously downloaded
  partial log remains valid.
- Rate-limit violation or concurrent tab: return `409` or `429` with the next
  eligible time; send nothing.
- Payload-pack change after preview: refuse to start if its digest differs.
- Target DNS or policy change: revalidate before each request and fail the run
  closed if the destination is no longer approved and public.

## Test plan

- Marker validation: none, one through three, four or more, duplicates, numbering
  gaps, unknown spellings, hostname placement, parameter-name placement, path
  placement, and parameter-value placement.
- Literal replacement preserves all non-marker URL characters and performs the
  documented encoding exactly once.
- Isolated mode generates a baseline plus `payloads * markers` requests and
  places benign controls in every inactive marker.
- Synchronized mode generates a baseline plus one request per payload and uses
  the same payload at every marker.
- No planner path can generate Cartesian payload combinations, silently
  truncate a plan, or exceed the 25-request hard cap.
- All generated URLs pass the existing target and public-IP policy before send.
- Rate tests with a fake monotonic clock prove that 4.999 seconds is rejected,
  5 seconds is accepted, and longer profiles enforce 15 and 60 seconds.
- Multiple tabs/sessions cannot create concurrent sends or bypass the global
  limiter.
- Redirects are recorded but never followed.
- Pause, resume, cancel, completion, and per-request failures produce correct
  state transitions and evidence.
- Pack version/digest and payload IDs appear in downloaded session JSON.
- Response content containing active markup is escaped in every UI view.
- An interrupted run can still download all evidence appended before the
  interruption.
- Cloud Run smoke test confirms one active instance/concurrency setting and
  observes the requested spacing in external logs.

## Recommended implementation order

1. Define immutable payload and run-plan models plus a reviewed test fixture.
2. Implement one-to-three-marker validation, parameter-location reporting,
   deterministic encoding, both substitution modes, plan preview, duration
   calculation, and unit tests without sending traffic.
3. Implement the server-side interval gate, global run lock, and single-step
   executor using a fake clock in tests.
4. Add run-state persistence and immediate session-log events.
5. Build configure, preview, and run-monitor pages with manual single-step.
6. Add browser-driven automatic stepping, pause/resume/cancel, and countdown.
7. Curate and review the first OWASP-inspired local payload pack.
8. Run a controlled Cloud Run smoke test against an approved test endpoint and
   confirm actual WAF/log timestamps before enabling production targets.

## Acceptance criteria

The WAF tester MVP is ready when an authenticated analyst can enter one approved
GET URL containing one to three supported markers in path segments or
query-parameter values, preview a versioned local payload plan in isolated or
synchronized mode, run no more than one request every selected 5/15/60-second
interval with no concurrency, Cartesian combinations, or redirect following,
pause or stop the run, and download partial or complete evidence that attributes
each request to its parameter inputs and distinguishes HTTP observations from
analyst-confirmed WAF detection and blocking.
