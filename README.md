# EventGen

An authenticated Flask app, packaged as a container, for testing an external
website one request at a time. It is used to confirm that external
connections reach the target and are logged.

## Layout

| Path | Purpose |
| --- | --- |
| `app/` | The deployed Flask application (`web_app.py`, focused request/certificate/WAF modules, payload data, templates, and static assets). This is the only code copied into the Docker image. |
| `cli/` | A standalone test application (see below). Not part of the image. |
| `tests/` | Unit tests for both. |
| `Dockerfile`, `gunicorn.conf.py`, `requirements.txt` | Container scaffolding. |
| `docs/` | Planning documents. |

## About the CLI

`cli/` is a self-contained, standard-library-only test harness. Use it to
assess and iterate on new functionality (request handling, redirects,
User-Agent profiles, TLS behavior) before incorporating it into the Flask
app. It does not import from `app/`, and `app/` does not import from `cli/`;
the shared request logic was copied into `app/http_client.py`, so changes
proven in the CLI must be ported across deliberately.

The CLI is intended for local, authorized testing. It accepts operator-entered
URLs and does not implement the deployment-managed hostname allowlist or
SSRF controls the web service has. Do not expose it as a remotely accessible
request proxy.
## Run the CLI

Python 3.10 or later is required. No third-party packages are needed.

```powershell
python -m cli.eventgen_cli
```

If your Windows installation uses the Python launcher:

```powershell
py -m cli.eventgen_cli
```

Choose **Send a GET request**, type or paste a URL, and review the response. If
the server returns a redirect, the CLI displays its `Location` and resolved URL
and waits for **Proceed** or **Drop**. It never follows a redirect automatically.

Choose **Select User-Agent** to pick a numbered profile from 0 through 5. Edge
on Windows is option 0 and the default. The initial catalog contains Edge and
Chrome on Windows, Chrome on iPhone, a Prisma Browser profile with a configured
identification component, a `soc_testing` profile, and the `axios/1.7.9` string
observed in token-replay activity. The selected value is preserved across every
manually approved redirect and displayed with the response.

Prisma Browser's vendor default is Chrome-compatible and does not contain a
universal Prisma identifier. The included profile models Palo Alto's documented
additional-component configuration by appending `PrismaAccessBrowser/1.0`.

Choose **Show public egress IP** to make one request to an external IP-echo
service and display the public IPv4 or IPv6 address it observes after NAT. This
is the address to search for in ingress, proxy, and WAF records. The default
service is `https://api64.ipify.org?format=json`; override it when required:

```powershell
$env:EVENTGEN_IP_ECHO_URL = "https://approved.example/ip"
python -m cli.eventgen_cli
```

The IP lookup discloses the instance's public address and selected User-Agent to
the configured service. Use an organization-approved endpoint if that matters
for your environment.

TLS certificate verification is enabled by default. It can be toggled from the
main menu for a site with an invalid or privately issued certificate. The CLI
prints a prominent warning before and after every unverified request.

Every request includes an `X-Validation-ID` header. Use that value to correlate
the request with ingress, web-server, or WAF records.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The test suite uses a local HTTP fixture and does not contact the internet.

## Flask MVP

The Flask application preserves the CLI's core workflow in a browser:

- operator-entered URLs within a deployment-managed hostname scope;
- selectable User-Agent profiles and optional unverified TLS;
- response status, sanitized headers, and bounded body preview;
- display of the server-presented TLS certificate chain, including subjects,
  issuers, validity, SANs, and SHA-256 fingerprints;
- explicit Proceed or Drop decisions for redirects;
- public egress-IP lookup; and
- an authenticated, downloadable JSON session log.

The **WAF Tester** link opens a deliberately bounded Intruder-style workflow.
Enter a complete GET URL containing `[replaceme]` and optionally
`[replaceme2]` and `[replaceme3]`. Markers may appear in path segments or query
parameter values. Preview shows every encoded URL before any target request is
sent.

With multiple markers, **Isolated positions** tests one input at a time and
places a run-specific benign control in the others. **Synchronized positions**
places the same payload in all marked inputs. Different payloads are never
combined as a Cartesian product. Runs are limited to 25 sequential requests,
never follow redirects or retry automatically, and enforce 5-, 15-, or
60-second spacing on the server. The browser must remain open for automatic
progression; pause, single-step, stop, and partial log download remain
available throughout the run.

The application refuses to start unless these environment variables exist:

- `EVENTGEN_USERNAME` — HTTP Basic Auth username;
- `EVENTGEN_PASSWORD` — HTTP Basic Auth password; and
- `EVENTGEN_ALLOWED_HOSTS` — comma-separated exact or wildcard hostname
  patterns, such as `example.com,*.example.com`.

No credentials are included in source, templates, images, or defaults. Set
`EVENTGEN_SECRET_KEY` to a random value in deployed environments so a
container restart does not invalidate its signed browser session. Store the
username, password, and secret key in the deployment platform's secret manager.

### Run locally on Windows

Install dependencies into a local virtual environment:

```powershell
uv venv .venv
uv pip install --python .venv\Scripts\python.exe --requirement requirements.txt
```

Set values in the current PowerShell process. Replace every bracketed value;
do not copy real credentials into a tracked file or shell script:

```powershell
$env:EVENTGEN_USERNAME = "<temporary-analyst-username>"
$env:EVENTGEN_PASSWORD = "<temporary-strong-password>"
$env:EVENTGEN_ALLOWED_HOSTS = "<example.com,*.example.com>"
$env:EVENTGEN_SECRET_KEY = & .venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$env:EVENTGEN_SECURE_COOKIES = "false"
& .venv\Scripts\python.exe -m flask --app "app.web_app:create_app" run --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080` and enter the environment-provided Basic Auth
credentials when the browser prompts. The secure-cookie override is appropriate
only for loopback HTTP development. Leave it unset in an HTTPS deployment.

Basic Auth credentials are only protected in transit when the application is
served through HTTPS. Do not expose the Flask development server to a network.

### Run locally on Linux or macOS (bash)

Install dependencies into a local virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install --requirement requirements.txt
```

Export values in the current shell. Replace every bracketed value; do not copy
real credentials into a tracked file or shell script:

```bash
export EVENTGEN_USERNAME="<temporary-analyst-username>"
export EVENTGEN_PASSWORD="<temporary-strong-password>"
export EVENTGEN_ALLOWED_HOSTS="<example.com,*.example.com>"
export EVENTGEN_SECRET_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export EVENTGEN_SECURE_COOKIES="false"
.venv/bin/python -m flask --app "app.web_app:create_app" run --host 127.0.0.1 --port 8080
```

The same loopback-only and HTTPS notes above apply. Git Bash on Windows uses
`.venv/Scripts/` in place of `.venv/bin/`.

### Verify locally before building the container

Complete these checks with the local Flask server before attempting a Docker
build, so configuration and code problems are found without a rebuild cycle:

1. Run the unit tests from the repository root:

   ```bash
   .venv/bin/python -m unittest discover -s tests
   ```

   On Windows use `.venv\Scripts\python.exe`.

2. Start the server using the Windows or bash commands above. It exits with an
   error naming the missing variable if `EVENTGEN_USERNAME`,
   `EVENTGEN_PASSWORD` or `EVENTGEN_ALLOWED_HOSTS` is unset.

3. In a second terminal, confirm the health endpoint (no credentials needed)
   and that authentication is enforced:

   ```bash
   curl -i http://127.0.0.1:8080/healthz                  # expect 200
   curl -i http://127.0.0.1:8080/                         # expect 401
   curl -i -u "<username>:<password>" http://127.0.0.1:8080/   # expect 200
   ```

   In PowerShell use `curl.exe`, because `curl` is an alias for
   `Invoke-WebRequest`.

4. Open `http://127.0.0.1:8080` in a browser, send one request to a host in
   `EVENTGEN_ALLOWED_HOSTS`, and confirm the response, redirect prompt and
   **Download session log** work. A host outside the allowlist should be
   rejected.

5. Stop the server with `Ctrl+C`, then continue to the container build.

### Run the container

Build the image:

```powershell
docker build --tag eventgen:mvp .
```

Supply secrets using your platform's secret manager. For a local container,
create an untracked `.env` file containing the required values, a random secret
key, and `EVENTGEN_SECURE_COOKIES=false`, then run:

```powershell
docker run --rm --env-file .env --publish 127.0.0.1:8080:8080 eventgen:mvp
```

The image runs as a non-root user with one Gunicorn worker and four threads.
Keep the hosted service at one instance for this MVP because session evidence is
stored on that instance's disposable filesystem.

### Session evidence and shutdown

Use **Download session log** before stopping the container. The JSON package
contains timestamps, validation IDs, selected User-Agents, TLS state, response
summaries, redirect decisions, certificate-chain observations, public-IP
observations, and the application version. Sensitive response headers such as
`Set-Cookie` are redacted, as are query values whose names look like passwords,
tokens, secrets, or credentials.

Response previews and non-sensitive query values may still contain operational
data. Handle the downloaded report accordingly. Destroying the container before
download intentionally destroys its local session evidence.

For Cloud Run or another hosted runtime, configure zero minimum instances and a
maximum of one instance for this MVP. Deploy it only when a validation session
is required, download the evidence, and then remove or scale down the service.
