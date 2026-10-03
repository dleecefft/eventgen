#!/bin/bash
# =============================================================================
# EventGen — post-deploy check
# =============================================================================
# Confirms /healthz answers, that the app rejects unauthenticated requests,
# and (when EVENTGEN_USERNAME / EVENTGEN_PASSWORD are exported) that the
# credentials are accepted. The password is passed to curl via a config file on
# stdin so it does not appear in `ps`.
#
# Usage:
#   bash cloud_install/verify.sh
#   EVENTGEN_USERNAME=analyst EVENTGEN_PASSWORD='...' bash cloud_install/verify.sh
# =============================================================================

set -uo pipefail

# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_project
require_region

URL=$(gcloud run services describe "${SERVICE_NAME}" --project="${PROJECT_ID}" \
        --region="${REGION}" --format="value(status.url)" 2>/dev/null)
if [ -z "${URL}" ]; then
    echo "ERROR: service ${SERVICE_NAME} not found in ${REGION}."
    exit 1
fi

echo "Service: ${URL}"
FAILED=0

expect() { # $1 label, $2 expected, $3 actual
    if [ "$2" = "$3" ]; then
        echo "   ✓ $1 → $3"
    else
        echo "   ✗ $1 → $3 (expected $2)"
        FAILED=$((FAILED + 1))
    fi
}

expect "GET /healthz (no auth)" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${URL}/healthz")"
expect "GET / (no auth)" 401 "$(curl -s -o /dev/null -w '%{http_code}' "${URL}/")"

if [ -n "${EVENTGEN_USERNAME:-}" ] && [ -n "${EVENTGEN_PASSWORD:-}" ]; then
    code=$(printf 'user = "%s:%s"\n' "${EVENTGEN_USERNAME}" "${EVENTGEN_PASSWORD}" \
            | curl -s -o /dev/null -w '%{http_code}' -K - "${URL}/")
    expect "GET / (Basic Auth)" 200 "${code}"
else
    echo "   - Skipped authenticated check (export EVENTGEN_USERNAME and EVENTGEN_PASSWORD)"
fi

echo ""
[ "${FAILED}" -eq 0 ] && echo "✓ All checks passed." || { echo "✗ ${FAILED} check(s) failed."; exit 1; }
