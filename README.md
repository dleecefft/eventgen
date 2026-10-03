# Event Generator

This repository contains a CLI prototype and an authenticated Flask MVP for
testing an external website one request at a time.

The CLI is intended for local, authorized testing. It accepts operator-entered
URLs and does not yet implement the deployment-managed hostname allowlist or
SSRF controls specified for the future web service. Do not expose this
prototype as a remotely accessible request proxy.

## Run the CLI

Python 3.10 or later is required. No third-party packages are needed.

```powershell
python .\event_generator_cli.py
```

If your Windows installation uses the Python launcher:

```powershell
py .\event_generator_cli.py
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
$env:EVENT_GENERATOR_IP_ECHO_URL = "https://approved.example/ip"
python .\event_generator_cli.py
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

The application refuses to start unless these environment variables exist:

- `EVENT_GENERATOR_USERNAME` — HTTP Basic Auth username;
- `EVENT_GENERATOR_PASSWORD` — HTTP Basic Auth password; and
- `EVENT_GENERATOR_ALLOWED_HOSTS` — comma-separated exact or wildcard hostname
  patterns, such as `example.com,*.example.com`.

No credentials are included in source, templates, images, or defaults. Set
`EVENT_GENERATOR_SECRET_KEY` to a random value in deployed environments so a
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
$env:EVENT_GENERATOR_USERNAME = "<temporary-analyst-username>"
$env:EVENT_GENERATOR_PASSWORD = "<temporary-strong-password>"
$env:EVENT_GENERATOR_ALLOWED_HOSTS = "<example.com,*.example.com>"
$env:EVENT_GENERATOR_SECRET_KEY = & .venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$env:EVENT_GENERATOR_SECURE_COOKIES = "false"
& .venv\Scripts\python.exe -m flask --app "web_app:create_app" run --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080` and enter the environment-provided Basic Auth
credentials when the browser prompts. The secure-cookie override is appropriate
only for loopback HTTP development. Leave it unset in an HTTPS deployment.

Basic Auth credentials are only protected in transit when the application is
served through HTTPS. Do not expose the Flask development server to a network.

### Run the container

Build the image:

```powershell
docker build --tag event-generator:mvp .
```

Supply secrets using your platform's secret manager. For a local container,
create an untracked `.env` file containing the required values, a random secret
key, and `EVENT_GENERATOR_SECURE_COOKIES=false`, then run:

```powershell
docker run --rm --env-file .env --publish 127.0.0.1:8080:8080 event-generator:mvp
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
