# EventGen — Google Cloud Run install

Scripts to deploy the container in the repo root to Cloud Run. The complete
workflow has been confirmed from a remote Linux server with `gcloud`
authenticated to Google Cloud. Execution inside Google Cloud Shell has not yet
been confirmed, although it is expected to work because the scripts use Bash
and the standard `gcloud` CLI. Git Bash, WSL and macOS are also expected to
work but are not part of that confirmed deployment result. Test the app locally
first; see the main README.

| Script | Purpose |
| --- | --- |
| `common.sh` | Shared settings; sourced, never run. |
| `provision-gcp-project.sh` | One-time: enable APIs, create the Artifact Registry repo and runtime service account, set build permissions. |
| `provision-secrets.sh` | Create the Basic Auth username, password and session signing key in Secret Manager. |
| `deploy-cloudrun.sh` | Preflight, build with Cloud Build, deploy. |
| `verify.sh` | Check `/healthz`, that auth is enforced, and optionally that your credentials work. |
| `teardown.sh` | Delete the service (and optionally secrets and images). |

## Settings

Keep them outside the repo in `~/.eventgen/deploy.env`:

```bash
mkdir -p ~/.eventgen && cat > ~/.eventgen/deploy.env <<'EOF'
GOOGLE_CLOUD_PROJECT='my-project'
CLOUD_RUN_REGION='us-central1'
EVENTGEN_ALLOWED_HOSTS='example.com,*.example.com'
EOF
```

Anything already exported in your shell overrides the file. Optional:
`CLOUD_RUN_SERVICE` (default `eventgen`), `EVENTGEN_SA_NAME`, `EVENTGEN_AR_REPO`.

Never put the username or password in this file.

## Deploy

```bash
bash cloud_install/provision-gcp-project.sh     # once per project
bash cloud_install/provision-secrets.sh         # prompts; empty password = generate
DRY_RUN=1 ALLOW_UNAUTH=1 bash cloud_install/deploy-cloudrun.sh   # preflight only
ALLOW_UNAUTH=1 bash cloud_install/deploy-cloudrun.sh
bash cloud_install/verify.sh
```

`ALLOW_UNAUTH=1` is required because the app protects itself with Basic Auth;
Cloud Run IAM would otherwise demand a Google identity token and a browser
could not reach the service. Cloud Run terminates HTTPS, so the secure-cookie
default stays on.

## Operating notes

- Scaling is fixed at min 0, max 1. Session evidence lives on the instance's
  disposable filesystem. **Download the session log before the instance scales
  to zero or you run `teardown.sh`.** An idle instance is reclaimed
  automatically, so download as soon as a test run finishes.
- Requests to your targets leave from Cloud Run's shared, dynamic egress
  addresses unless separate VPC/NAT configuration supplies static egress. Use
  the app's **Show public egress IP** feature to probe IPv4 and IPv6 separately
  for each run, and tell the owners of the target's allow/ban lists before
  testing. Existing scanner auto-banning may block either address. An address
  returned by an echo service describes that protocol path at that moment; the
  destination log remains authoritative for the address used to reach it.
- `EVENTGEN_ALLOWED_HOSTS` is the SSRF guard. Keep it to the sites you are
  authorised to test.
- Redeploy a new instance: `bash cloud_install/deploy-cloudrun.sh`. Reuse the
  existing image with `SKIP_BUILD=1`.
- Rotate the session signing key with `ROTATE_KEY=1 bash cloud_install/provision-secrets.sh`
  followed by a redeploy; Cloud Run reads `:latest` at revision start.

## Teardown

```bash
bash cloud_install/teardown.sh
DELETE_SECRETS=1 DELETE_IMAGES=1 bash cloud_install/teardown.sh
```
