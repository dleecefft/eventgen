#!/bin/bash
# =============================================================================
# EventGen — shared configuration for the cloud_install scripts
# =============================================================================
# Sourced by the other scripts, never run directly. Anything already exported
# in the current shell wins over ~/.eventgen/deploy.env.
# =============================================================================

EVENTGEN_DEPLOY_ENV="${EVENTGEN_DEPLOY_ENV:-${HOME}/.eventgen/deploy.env}"
if [ -f "${EVENTGEN_DEPLOY_ENV}" ]; then
    _pre_project="${GOOGLE_CLOUD_PROJECT:-}"
    _pre_region="${CLOUD_RUN_REGION:-}"
    _pre_hosts="${EVENTGEN_ALLOWED_HOSTS:-}"
    # shellcheck disable=SC1090
    . "${EVENTGEN_DEPLOY_ENV}"
    [ -n "${_pre_project}" ] && GOOGLE_CLOUD_PROJECT="${_pre_project}"
    [ -n "${_pre_region}" ]  && CLOUD_RUN_REGION="${_pre_region}"
    [ -n "${_pre_hosts}" ]   && EVENTGEN_ALLOWED_HOSTS="${_pre_hosts}"
    unset _pre_project _pre_region _pre_hosts
    echo "Loaded deploy config: ${EVENTGEN_DEPLOY_ENV}"
fi

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
REGION="${CLOUD_RUN_REGION:-}"
SERVICE_NAME="${CLOUD_RUN_SERVICE:-eventgen}"
SA_NAME="${EVENTGEN_SA_NAME:-eventgen-runner}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
AR_REPO="${EVENTGEN_AR_REPO:-eventgen}"
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${SERVICE_NAME}"

SECRET_USER="${SERVICE_NAME}-username"
SECRET_PASS="${SERVICE_NAME}-password"
SECRET_KEY="${SERVICE_NAME}-secret-key"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_project() {
    if [ -z "${PROJECT_ID}" ]; then
        echo "ERROR: GOOGLE_CLOUD_PROJECT is not set (and no ${EVENTGEN_DEPLOY_ENV})."
        exit 1
    fi
}

require_region() {
    if [ -z "${REGION}" ]; then
        echo "ERROR: CLOUD_RUN_REGION is not set (for example us-central1)."
        exit 1
    fi
}

# Print what gcloud actually said instead of guessing a cause.
report_error() {
    local label="$1" err="$2"
    echo "   ✗ ${label}"
    echo "${err}" | sed 's/^/       /'
    if echo "${err}" | grep -qi "not available in your location"; then
        echo "       Google geo-blocked this client IP; try from another network."
    fi
}
