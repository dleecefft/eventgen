#!/bin/bash
# =============================================================================
# EventGen — build and deploy to Cloud Run
# =============================================================================
#
# 1. Preflights the project, registry, runtime SA and secrets (no build is paid
#    for if something provisioning should have created is missing).
# 2. Builds the repo-root Dockerfile with Cloud Build, tagged with the git
#    short SHA and :latest.
# 3. Deploys one instance with secrets mounted as environment variables.
#
# Settings:
#   EVENTGEN_ALLOWED_HOSTS  required — comma-separated host patterns the tool
#                           may send requests to (set in ~/.eventgen/deploy.env)
#   ALLOW_UNAUTH=1          required to deploy. The app enforces its own Basic
#                           Auth, so Cloud Run IAM must admit the request first.
#                           Without this flag the service needs a Google
#                           identity token and a browser cannot reach it.
#   SKIP_BUILD=1            redeploy the existing :latest image
#   DRY_RUN=1               preflight only, change nothing
#
# Scaling is fixed at min 0 / max 1: session evidence lives on the instance's
# disposable filesystem, so a second instance would split a session. Download
# the session log before scaling down or tearing down.
#
# Usage:
#   ALLOW_UNAUTH=1 bash cloud_install/deploy-cloudrun.sh
#
# Caller needs: roles/cloudbuild.builds.editor, roles/serviceusage.serviceUsageConsumer,
# roles/run.admin (plus run.services.setIamPolicy for ALLOW_UNAUTH),
# and roles/iam.serviceAccountUser on the runtime and build service accounts.
# =============================================================================

set -uo pipefail

# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_project
require_region

SKIP_BUILD="${SKIP_BUILD:-0}"
DRY_RUN="${DRY_RUN:-0}"
ALLOWED_HOSTS="${EVENTGEN_ALLOWED_HOSTS:-}"

if [ -z "${ALLOWED_HOSTS}" ]; then
    echo "ERROR: EVENTGEN_ALLOWED_HOSTS is not set. The app refuses to start without it."
    echo "       Put it in ${EVENTGEN_DEPLOY_ENV}, single-quoted."
    exit 1
fi
if [ "${ALLOW_UNAUTH:-0}" != "1" ]; then
    echo "ERROR: set ALLOW_UNAUTH=1 to deploy. The service is public at the Cloud Run"
    echo "       layer and protected by the app's Basic Auth; see the header of this script."
    exit 1
fi
if [ ! -f "${REPO_ROOT}/Dockerfile" ]; then
    echo "ERROR: cannot locate the repo root (derived ${REPO_ROOT})."
    exit 1
fi

SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
TAG="${SHA:-nogit-${STAMP}}"
if [ -n "${SHA}" ] && [ -n "$(git -C "${REPO_ROOT}" status --porcelain -- app Dockerfile gunicorn.conf.py requirements.txt 2>/dev/null)" ]; then
    TAG="${SHA}-dirty-${STAMP}"
fi
[ "${SKIP_BUILD}" = "1" ] && TAG="latest"

echo ""
echo "🚀 EventGen deploy"
echo "========================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo "Image:    ${IMAGE_BASE}:${TAG}"
echo "Hosts:    ${ALLOWED_HOSTS}"
echo ""

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "🔎 Preflight"
PREFLIGHT_FAILED=0

check() { # $1 label, remaining args = command
    local label="$1" err
    shift
    if err=$("$@" 2>&1 >/dev/null); then
        echo "   ✓ ${label}"
    else
        report_error "${label}" "${err}"
        PREFLIGHT_FAILED=$((PREFLIGHT_FAILED + 1))
    fi
}

check "Runtime SA ${SA_EMAIL}" \
    gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}"
check "Artifact Registry ${AR_REPO} (${REGION})" \
    gcloud artifacts repositories describe "${AR_REPO}" --project="${PROJECT_ID}" --location="${REGION}"
for secret in "${SECRET_USER}" "${SECRET_PASS}" "${SECRET_KEY}"; do
    check "Secret ${secret}" \
        gcloud secrets describe "${secret}" --project="${PROJECT_ID}"
done

if [ "${PREFLIGHT_FAILED}" -gt 0 ]; then
    echo ""
    echo "✗ ${PREFLIGHT_FAILED} check(s) failed. Run provision-gcp-project.sh and"
    echo "  provision-secrets.sh, or fix the errors above."
    exit 1
fi

if [ "${DRY_RUN}" = "1" ]; then
    echo ""
    echo "DRY_RUN=1 — preflight passed, nothing changed."
    exit 0
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [ "${SKIP_BUILD}" != "1" ]; then
    echo ""
    echo "🔨 Building with Cloud Build..."

    BUILD_CONFIG="$(mktemp "${TMPDIR:-/tmp}/cloudbuild-eventgen.XXXXXX.yaml")"
    trap 'rm -f "${BUILD_CONFIG}"' EXIT

    cat > "${BUILD_CONFIG}" <<BUILDEOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${IMAGE_BASE}:${TAG}', '-t', '${IMAGE_BASE}:latest', '.']
images:
  - '${IMAGE_BASE}:${TAG}'
  - '${IMAGE_BASE}:latest'
options:
  logging: CLOUD_LOGGING_ONLY
BUILDEOF

    if ! gcloud builds submit \
            --project="${PROJECT_ID}" \
            --config="${BUILD_CONFIG}" \
            "${REPO_ROOT}"; then
        echo ""
        echo "ERROR: Build failed. Nothing was deployed."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
SERVICE_EXISTS=0
gcloud run services describe "${SERVICE_NAME}" --project="${PROJECT_ID}" \
    --region="${REGION}" >/dev/null 2>&1 && SERVICE_EXISTS=1

echo ""
echo "☁  Deploying ${SERVICE_NAME}..."

# "^@^" switches the list delimiter so commas inside the host list survive.
if ! gcloud run deploy "${SERVICE_NAME}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --image="${IMAGE_BASE}:${TAG}" \
        --platform=managed \
        --port=8080 \
        --memory=512Mi \
        --cpu=1 \
        --min-instances=0 \
        --max-instances=1 \
        --concurrency=10 \
        --timeout=120 \
        --session-affinity \
        --service-account="${SA_EMAIL}" \
        --set-secrets="EVENTGEN_USERNAME=${SECRET_USER}:latest,EVENTGEN_PASSWORD=${SECRET_PASS}:latest,EVENTGEN_SECRET_KEY=${SECRET_KEY}:latest" \
        --set-env-vars="^@^EVENTGEN_ALLOWED_HOSTS=${ALLOWED_HOSTS}" \
        --allow-unauthenticated; then
    echo ""
    if [ "${SERVICE_EXISTS}" = "1" ]; then
        echo "ERROR: Deploy failed. Cloud Run kept the previous revision serving."
    else
        echo "ERROR: Deploy failed. The service was never created, so nothing is serving."
    fi
    echo "       gcloud run revisions list --service=${SERVICE_NAME} --region=${REGION} --project=${PROJECT_ID}"
    exit 1
fi

URL=$(gcloud run services describe "${SERVICE_NAME}" --project="${PROJECT_ID}" \
        --region="${REGION}" --format="value(status.url)" 2>/dev/null)

echo ""
echo "✓ Deployed: ${URL}"
echo "  Verify:   bash cloud_install/verify.sh"
echo "  Download the session log before scaling down or tearing down."
