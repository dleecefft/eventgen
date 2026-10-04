# Change Log

This file records material EventGen changes and their validation boundaries.

## 2026-10-04 — Version 0.2.2 — Testing MVP accepted

EventGen is considered sufficient for the current on-demand SOC testing use
case. It remains a controlled external request and evidence-generation utility,
not a vulnerability scanner or a source of independent WAF verdicts.

### Added

- Standard-library CLI for single GET requests, explicit redirect decisions,
  TLS-verification control, selectable User-Agents and public-egress discovery.
- Authenticated Flask application with environment-provided credentials,
  deployment-managed target scope, CSRF protection and downloadable ephemeral
  session evidence.
- Response review with bounded body capture, sensitive-header redaction and
  server-presented certificate-chain inspection.
- Independent IPv4-only and IPv6-only egress probes. Session evidence retains
  the original single-address fields for compatibility and adds explicit
  address-family results, services and per-family errors.
- Modular WAF tester in `app/waf_tester.py`, separate from `web_app.py`, with a
  checked-in, versioned payload pack.
- One-to-three replacement markers in paths or query-parameter values, with
  isolated and synchronized substitution modes and no Cartesian combinations.
- Exact request preview, deterministic encoding, a 25-request cap, no automatic
  redirect following or retries, and sequential 5/15/60-second rate profiles.
- Request-driven automatic progression while the browser is open, plus pause,
  manual single-step, stop and partial evidence download.
- Immutable per-run User-Agent selection applied to every generated request and
  repeated in every `waf_request` evidence record.
- Google Cloud Run provisioning, deployment, verification and teardown scripts.

### Validation recorded

- The complete `cloud_install` workflow was successfully run from a remote
  Linux server connected to Google Cloud with an authenticated `gcloud` CLI.
- Direct execution from Google Cloud Shell is expected to work but has not been
  confirmed.
- A Cloud Run session successfully captured both IPv4 and IPv6 egress results,
  performed a manual redirect drop and completed a seven-request WAF run.
- The WAF run produced one benign baseline response followed by six distinct
  payload responses, with unique validation IDs and request-start gaps greater
  than the configured 15-second minimum.
- TLS verification was enabled, response bodies were not truncated, sensitive
  cookie headers were redacted and the completed session log was downloadable.
- The local automated suite passed all 37 tests after User-Agent persistence
  was added.

### Validation boundary

- The observed HTTP responses confirm that requests were transmitted and that
  the destination responded differently to the test inputs.
- HTTP `400`, `403`, `406`, `429`, connection resets or similar observations do
  not independently establish that a WAF detected or blocked a request.
- Analysts must correlate validation IDs, timestamps, User-Agent and candidate
  IPv4/IPv6 source addresses with downstream WAF, ingress or SIEM records.
- Default Cloud Run internet egress uses dynamic addresses. Stable source IP
  requirements need additional VPC egress and Cloud NAT configuration.
- Container-local run state and session evidence are ephemeral and must be
  downloaded before the instance is stopped, replaced or reclaimed.
