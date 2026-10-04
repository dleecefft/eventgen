# External Web Log and WAF Validation Tool

## Purpose

Build a small, containerized web application that sends controlled HTTP(S)
requests from outside the company network. Its purpose is to verify that:

- internet-originated requests reach an approved website;
- ingress, web-server, proxy, and WAF logs contain the requests;
- expected WAF rules detect or block selected test patterns; and
- support teams can be given reproducible evidence tied to exact requests.

The interaction should feel like a very small Burp Repeater with an optional,
bounded Intruder-style loop: send one request, inspect the raw response, decide
whether to follow a redirect, edit the next request, or apply a small test
profile.

## Boundaries and non-goals

This is a validation utility, not a vulnerability scanner.

- Only explicitly approved target hostnames may be contacted.
- No crawling, discovery, exploitation, credential attacks, or high-volume
  traffic generation.
- No automatic redirect following. Every redirect is shown and requires an
  explicit action unless the operator enabled a bounded redirect policy.
- Fuzzing is limited by request count, rate, methods, target, and runtime.
- The tool reports requests sent and responses received. It must not claim
  that logging or WAF detection succeeded until the corresponding downstream
  evidence is supplied or confirmed.

## Primary workflow

1. The operator signs in and starts a validation session.
2. They type or paste the complete destination URL into an input field, label
   the environment (for example development, test, or production), and choose a
   method, headers, query parameters, and optional body. The URL is not selected
   from a fixed deployment-time list, but its hostname and port must satisfy the
   deployment's target policy.
3. The application resolves and validates the destination, then shows the
   exact outbound request it will send.
4. The application adds a unique correlation value to a configurable header
   and, optionally, a query parameter.
5. It sends a single request with redirects disabled. TLS certificate
   verification is enabled by default, but the operator may disable it for a
   target with an invalid or privately issued certificate.
6. The UI displays the request, resolved address, timing, status, response
   headers, a size-limited response preview, and any redirect destination. A
   persistent warning is displayed whenever certificate verification is
   disabled.
7. The operator may edit and resend, explicitly follow the redirect, or select
   a small WAF-validation profile.
8. For a profile, the application previews the planned mutations and request
   count. The operator starts a rate-limited run and can stop it at any time.
9. The operator exports a session report containing correlation values,
   timestamps, request/response summaries, and operator-entered log or alert
   confirmation.

## MVP scope

### 1. Request workbench

- Prominent editable full-URL input accepting scheme, hostname, optional port,
  path, and query string, with a separate structured query-parameter editor.
- Optional environment label such as development, test, or production. The
  label is evidence metadata and does not replace validation of the actual URL.
- Allow the operator to change the URL before every send so equivalent requests
  can be exercised against different approved environments.
- GET, HEAD, and POST initially; additional methods disabled by default.
- Editable headers and text, JSON, or form body.
- TLS certificate verification on by default, with a per-request option to
  accept an unverified certificate.
- When verification is disabled, show a prominent warning beside the request
  controls and in the response view stating that server identity was not
  verified. Preserve the warning while cloning, editing, or resending the
  request.
- Redirect handling disabled in the HTTP client.
- Per-request connect/read timeout and response-size limit.
- Raw and formatted views for requests and responses.
- Clear handling of DNS, TLS, timeout, and connection errors.
- Unique session ID and request ID on every outbound request.

### 2. Controlled tampering

- Clone a prior request into the editor.
- Clone a request to another URL/environment while preserving the method,
  headers, parameters, body, and test profile; show the destination change
  clearly and issue a confirmation prompt before sending to an environment
  labelled production.
- Manually change path, query, headers, or body.
- Show a diff between the previous and next request.
- Present redirect targets without fetching them automatically.
- Require destination validation again after every URL or redirect change.

### 3. Bounded WAF test profiles

Start with small, versioned payload packs rather than embedding a full scanner.
Profiles should represent common WAF signature categories, such as encoding and
parser edge cases, injection-shaped markers, traversal-shaped markers, and
cross-site-scripting-shaped markers. Payloads are validation signals only and
must not include post-exploitation behavior.

Each run must support:

- accepting a complete GET URL containing one to three named markers:
  `[replaceme]`, `[replaceme2]`, and `[replaceme3]`, placed in path segments or
  query-parameter values;
- offering isolated-position substitution by default and synchronized
  substitution when testing combined inputs, without generating Cartesian
  payload combinations;
- replacing active markers with one reviewed, deterministically encoded payload
  at a time and inactive markers with a run-specific benign control;
- previewing every mutation before execution;
- one mutation per request by default so log evidence is unambiguous;
- a hard maximum request count and runtime;
- three server-enforced, sequential rate profiles: one request every 5 seconds
  maximum, every 15 seconds by default, and every 60 seconds for the slow mode;
- pause, stop, and single-step operation;
- per-payload results with correlation IDs; and
- a configurable stop condition, such as first block response.

Payload sources will be wrapped behind a simple provider interface. The first
release should ship a small reviewed local corpus. External corpora such as
SecLists or FuzzDB can be considered later only after licensing, provenance,
size, and payload safety are reviewed; versions must be pinned.

The detailed MVP workflow, Cloud Run step-execution model, payload provenance,
rate enforcement, evidence schema, and acceptance tests are specified in
[WAF_TESTER_PLAN.md](WAF_TESTER_PLAN.md).

### 4. Evidence and reporting

- Record UTC timestamp, operator, session ID, request ID, destination hostname,
  operator-entered environment label, complete sanitized URL, resolved public
  IP, method, sanitized request summary, response status, latency, and response
  size.
- Record whether TLS certificate verification was enabled for every request,
  and clearly mark unverified connections in JSON and HTML reports.
- Let the operator record the downstream log source, event/alert identifier,
  observed action, and notes.
- Distinguish `request_observed`, `log_confirmed`, `waf_detected`, and
  `waf_blocked`; do not infer these states from an HTTP status alone.
- Export JSON for machine use and a concise HTML report for support cases.
- Redact configured sensitive headers, cookies, authorization data, and body
  fields from storage and exports.
- Include application version and payload-pack version in every report.

## Proposed architecture

Use a small server-rendered application to keep deployment and maintenance
simple:

- **Web layer:** Flask, Jinja templates, and lightweight progressive updates
  (plain forms or HTMX); no separate frontend build is required.
- **HTTP engine:** `httpx`, configured with redirects off, strict timeouts,
  bounded response streaming, TLS verification enabled by default with an
  explicit per-request override, and a deliberately restricted method set.
- **Validation layer:** target policy, DNS/IP checks, redirect revalidation,
  request limits, payload planning, redaction, and correlation ID generation.
- **Run engine:** a bounded sequential executor. The MVP should avoid durable
  background workers; interactive single-step and short synchronous batches
  fit the intended traffic level and portable-container goal.
- **Storage:** ephemeral session storage for the first deployment, with explicit
  report download. Add a persistence adapter later if central retention is
  required. Do not rely on the container filesystem for durable evidence.
- **Deployment:** one OCI image usable on Cloud Run or a DigitalOcean service.
  Provider-specific configuration belongs outside the application.

Suggested internal modules:

```text
app/
  web/             routes, forms, templates
  requests/        request models, sender, response capture
  policy/          target validation, limits, redaction
  payloads/        provider interface and reviewed built-in profiles
  runs/            mutation planner and sequential executor
  evidence/        session records and JSON/HTML export
tests/
deploy/
```

## Security and abuse controls

Because this application is a server-side request generator, these controls are
part of the MVP rather than deployment polish:

- Require authentication at the platform boundary and in the application;
  Cloud Run IAM/IAP or an equivalent identity-aware proxy is preferred.
- Configure approved hostname patterns and ports through deployment settings.
  Within that policy, operators may freely enter and change complete URLs for
  development, test, and production. The policy is a safety boundary, not a
  fixed list of URLs presented by the UI, and an operator cannot expand it from
  the UI.
- Resolve the hostname before each request and reject loopback, private,
  link-local, multicast, reserved, and cloud-metadata destinations.
- Validate every resolved address, and validate again for redirects and retries,
  to reduce DNS rebinding and SSRF risk.
- Allow HTTPS by default; permit HTTP only through deployment configuration for
  a documented test target.
- Permit TLS verification to be disabled only through an explicit per-request
  control. Display a persistent warning before and after the request, and add
  the unverified state to audit records and exported evidence.
- Strip or reject hop-by-hop headers and protect the Host header.
- Apply CSRF protection, secure cookies, body/response limits, request timeouts,
  global and per-session rate limits, and a maximum active run count.
- Do not accept executable plugins, shell commands, arbitrary Python, or remote
  payload-list URLs.
- Log administrative and test actions without retaining secrets or full
  sensitive response bodies.
- Display the instance's current observed egress IP so support teams can
  distinguish this validator from unrelated traffic.

## Deployment considerations

### Cloud Run

- Deploy authenticated, with minimum instances set according to desired startup
  latency and maximum instances/concurrency kept deliberately low.
- If a stable egress address is required for log correlation, allowlisting, or
  scanner-ban testing, configure provider networking and NAT explicitly; do not
  assume the default serverless egress address is stable.
- Keep secrets in the platform secret manager and configuration in environment
  variables.
- Treat the container filesystem as disposable.

### DigitalOcean

- Use the same container and environment contract.
- Confirm the chosen service's outbound-address behavior before relying on an IP
  as evidence. A small VM offers simpler stable-egress behavior than some
  managed application runtimes, but carries more patching responsibility.
- Terminate inbound TLS at the provider edge and keep the application private
  behind authenticated access where possible.

## Configuration contract

Initial settings should include:

- approved hostname patterns;
- optional environment presets that populate, but do not replace, the editable
  URL field;
- optional approved ports;
- correlation header name and optional query-parameter name;
- maximum requests per run, requests per second, run duration, and response
  bytes;
- connection and read timeouts;
- permitted HTTP methods, whether plain HTTP is allowed, and whether operators
  may disable TLS certificate verification;
- redacted header and body-field names;
- authentication/identity header mapping; and
- report retention mode.

Ship conservative defaults and fail startup when no target allowlist is set.

## Delivery phases

### Phase 0: CLI interaction prototype

- Build a standard-library Python menu before introducing Flask or browser UI
  concerns.
- Let the operator type or paste a URL and send one GET request at a time.
- Display status, headers, a bounded body preview, TLS-verification state, and a
  unique correlation ID.
- Provide an expandable numbered User-Agent catalog, defaulting to Edge on
  Windows, and preserve the selected string across manually approved redirects.
- Provide an explicit public-egress-IP lookup so analysts can search downstream
  logs by the NAT address observed outside the deployment. Make the echo service
  configurable and disclose that the lookup contacts it.
- Never follow redirects automatically; display the resolved destination and
  require the operator to choose **Proceed** or **Drop** for each hop.
- Support accepting an unverified certificate with the same persistent warning
  expected from the future web interface.
- Use local fixture tests to prove that redirects are not followed implicitly.

Exit criterion: the CLI can reach a controlled website, present the response,
and demonstrate that dropping a redirect results in no request to its target.

### Phase 1: acceptance examples and threat model

- Define two or three approved test targets and the expected ingress/WAF event
  for each.
- Decide how operators authenticate and how target ownership is approved.
- Document SSRF, credential leakage, abusive scanning, and evidence-retention
  threats.
- Agree on request/rate limits and the correlation field that downstream teams
  can search.

### Phase 2: single-request Flask explorer

- Scaffold Flask application and tests.
- Implement target policy and hardened HTTP client.
- Build request editor, response review, explicit redirect workflow, and
  correlation IDs.
- Add on-demand display and session logging of the certificate chain presented
  by an approved HTTPS target, clearly distinguishing verified and unverified
  inspection.
- Add a local Docker image and health endpoints.
- Require environment-provided Basic Auth credentials, fail startup when they
  are absent, and serve the application through HTTPS at the deployment edge.
- Write append-only session evidence to disposable instance storage and provide
  an authenticated JSON download before the on-demand container is stopped.

Exit criterion: an authenticated operator can send one request to an approved
public target, inspect the un-followed response, and find the exact request in a
downstream log using its correlation ID.

### Phase 3: tampering and WAF profiles

- Add request cloning and diffs.
- Add the payload provider interface and a small, versioned, reviewed built-in
  XSS corpus inspired by OWASP but stripped of external callbacks, data access,
  persistence, and post-exploitation behavior.
- Add one-to-three-marker URL-template and query-parameter validation, isolated
  and synchronized substitution modes, and exact preview of encoded GET
  requests.
- Add server-enforced 5/15/60-second profiles, with 15 seconds as the default,
  one active run per instance, no concurrency, and no automatic retries.
- Add request-driven single-step execution suitable for Cloud Run request-based
  CPU, followed by browser-controlled automatic stepping, pause, resume,
  cancellation, partial evidence download, and results.

Exit criterion: an operator can demonstrate a chosen test marker being logged,
detected, or blocked without exceeding the configured traffic envelope.

### Phase 4: evidence package

- Add confirmation states, notes, redaction, JSON export, and HTML reports.
- Include configuration, application, and payload-pack versions.
- Add a support-oriented summary showing what was sent, what was observed, and
  what remains unconfirmed.

### Phase 5: provider deployments

- Add Cloud Run and DigitalOcean deployment examples.
- Verify identity enforcement, secret handling, egress behavior, health checks,
  instance limits, and disposable storage assumptions on each provider.
- Document how to create a fresh instance with a new egress identity when
  exercising automated scanner-ban controls.

## Test strategy

- Unit tests for URL normalization, hostname allowlists, IP-range rejection,
  DNS rebinding defenses, redirect validation, mutation planning, limits,
  redaction, correlation IDs, and propagation of the unverified-TLS warning and
  evidence flag.
- HTTP-engine tests against a local fixture server for redirects, large bodies,
  slow responses, TLS errors, malformed responses, and connection failures.
- UI tests for preview/send/follow/edit/stop/export workflows.
- UI tests for entering a complete URL, switching an otherwise identical
  request among approved development/test/production URLs, production
  confirmation, and rejection of a URL outside the target policy.
- UI tests confirming that disabling certificate verification produces a
  persistent warning in request, response, cloned-request, and report views.
- Container tests running as a non-root user with a read-only root filesystem
  where supported.
- Deployment smoke tests using a controlled public echo target and a separate
  test WAF policy.
- Negative tests proving private addresses, cloud metadata endpoints,
  unapproved domains, excessive runs, and unsafe headers cannot be reached.

## Initial definition of done

The first usable release is complete when it can be deployed from one container,
is accessible only to authenticated operators, refuses destinations outside a
deployment-managed allowlist, sends single or tightly bounded sequential HTTPS
requests without automatic redirects, supports manual request editing and a
small reviewed WAF-validation corpus, and exports a redacted evidence report
whose claims distinguish transmitted requests from independently confirmed logs
and WAF actions.

## Decisions needed before implementation

1. Which hostname patterns and ports form the first approved target set?
2. Which deployment is first: Cloud Run or DigitalOcean?
3. Is a stable egress IP required, or is a fresh/dynamic egress identity useful
   for validating scanner-ban behavior?
4. Which identity system should protect the UI?
5. Which header or query field can downstream systems reliably preserve for
   correlation?
6. May evidence contain sanitized response previews, or only hashes and
   metadata?
7. Which WAF products and rule categories need to be demonstrated first?
