#!/bin/bash
# =============================================================================
# EventGen — teardown
# =============================================================================
# Deletes the Cloud Run service. The service's local session evidence is
# destroyed with it, so download the session log first.
#
# CONFIRM=1       skip the prompt
# DELETE_SECRETS=1  also delete the three secrets
# DELETE_IMAGES=1   also delete the Artifact Registry repository
#
# The project, APIs and runtime service account are left in place so a later
# redeploy is just provision-secrets.sh (if needed) + deploy-cloudrun.sh.
# =============================================================================

set -uo pipefail

# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_project
require_region

echo ""
echo "🧹 EventGen teardown — ${SERVICE_NAME} in ${PROJECT_ID}/${REGION}"
echo "   Session evidence on the instance will be lost."

if [ "${CONFIRM:-0}" != "1" ]; then
    read -r -p "Type the service name to confirm: " answer
    if [ "${answer}" != "${SERVICE_NAME}" ]; then
        echo "Aborted."
        exit 1
    fi
fi

FAILED=0

if err=$(gcloud run services delete "${SERVICE_NAME}" --project="${PROJECT_ID}" \
            --region="${REGION}" --quiet 2>&1 >/dev/null); then
    echo "   ✓ Cloud Run service deleted"
elif echo "${err}" | grep -qi "not found"; then
    echo "   ✓ Cloud Run service already gone"
else
    report_error "service delete" "${err}"
    FAILED=$((FAILED + 1))
fi

if [ "${DELETE_SECRETS:-0}" = "1" ]; then
    for secret in "${SECRET_USER}" "${SECRET_PASS}" "${SECRET_KEY}"; do
        if err=$(gcloud secrets delete "${secret}" --project="${PROJECT_ID}" --quiet 2>&1 >/dev/null); then
            echo "   ✓ ${secret} deleted"
        elif echo "${err}" | grep -qi "not found"; then
            echo "   ✓ ${secret} already gone"
        else
            report_error "${secret}" "${err}"
            FAILED=$((FAILED + 1))
        fi
    done
fi

if [ "${DELETE_IMAGES:-0}" = "1" ]; then
    if err=$(gcloud artifacts repositories delete "${AR_REPO}" --project="${PROJECT_ID}" \
                --location="${REGION}" --quiet 2>&1 >/dev/null); then
        echo "   ✓ Artifact Registry ${AR_REPO} deleted"
    elif echo "${err}" | grep -qi "not found"; then
        echo "   ✓ Artifact Registry ${AR_REPO} already gone"
    else
        report_error "${AR_REPO}" "${err}"
        FAILED=$((FAILED + 1))
    fi
fi

echo ""
[ "${FAILED}" -eq 0 ] && echo "✓ Teardown complete." || { echo "✗ ${FAILED} step(s) failed."; exit 1; }
