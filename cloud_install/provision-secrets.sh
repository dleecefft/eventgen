#!/bin/bash
# =============================================================================
# EventGen — Secret Manager provisioning
# =============================================================================
#
# Creates three secrets and grants the runtime service account secretAccessor
# on each:
#
#   <service>-username    HTTP Basic Auth username     (EVENTGEN_USERNAME)
#   <service>-password    HTTP Basic Auth password     (EVENTGEN_PASSWORD)
#   <service>-secret-key  Flask session signing key    (EVENTGEN_SECRET_KEY)
#
# Values are taken from EVENTGEN_USERNAME / EVENTGEN_PASSWORD if exported,
# otherwise prompted for (password input is hidden; leave it empty to generate
# a random one, shown once). The signing key is generated randomly and is never
# rotated by a re-run unless ROTATE_KEY=1.
#
# Values go to gcloud on stdin, never on the command line.
#
# Usage:
#   bash cloud_install/provision-secrets.sh
#   ROTATE_KEY=1 bash cloud_install/provision-secrets.sh
#
# Caller needs: roles/secretmanager.admin.
# =============================================================================

set -uo pipefail

# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_project

random_token() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null \
        || openssl rand -base64 24 | tr -d '/+=\n'
}

USERNAME="${EVENTGEN_USERNAME:-}"
PASSWORD="${EVENTGEN_PASSWORD:-}"
GENERATED_PASSWORD=0

if [ -z "${USERNAME}" ]; then
    read -r -p "Basic Auth username: " USERNAME
fi
if [ -z "${USERNAME}" ]; then
    echo "ERROR: a username is required."
    exit 1
fi
if [ -z "${PASSWORD}" ]; then
    read -r -s -p "Basic Auth password (empty = generate): " PASSWORD
    echo ""
    if [ -z "${PASSWORD}" ]; then
        PASSWORD="$(random_token)"
        GENERATED_PASSWORD=1
    fi
fi

echo ""
echo "🔐 EventGen secrets — ${PROJECT_ID}"
echo "   Runtime SA: ${SA_EMAIL}"
echo ""

FAILED=0

# $1 = secret name, $2 = value, $3 = "keep" to never add a version once it exists
ensure_secret() {
    local secret="$1" value="$2" mode="${3:-update}" err current

    if gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        if [ "${mode}" = "keep" ]; then
            echo "   ✓ ${secret} — exists, kept"
        elif current=$(gcloud secrets versions access latest \
                          --secret="${secret}" --project="${PROJECT_ID}" 2>/dev/null) \
             && [ "${current}" = "${value}" ]; then
            echo "   ✓ ${secret} — exists, value current"
        elif err=$(printf '%s' "${value}" | gcloud secrets versions add "${secret}" \
                      --project="${PROJECT_ID}" --data-file=- --quiet 2>&1 >/dev/null); then
            echo "   ✓ ${secret} — new version added"
        else
            report_error "${secret} — adding version failed" "${err}"
            return 1
        fi
    elif err=$(printf '%s' "${value}" | gcloud secrets create "${secret}" \
                  --project="${PROJECT_ID}" --data-file=- \
                  --labels="app=eventgen" --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${secret} — created"
    else
        report_error "${secret} — create failed" "${err}"
        return 1
    fi

    if ! err=$(gcloud secrets add-iam-policy-binding "${secret}" \
                  --project="${PROJECT_ID}" \
                  --member="serviceAccount:${SA_EMAIL}" \
                  --role="roles/secretmanager.secretAccessor" \
                  --quiet 2>&1 >/dev/null); then
        report_error "${secret} — secretAccessor binding failed" "${err}"
        return 1
    fi
    return 0
}

KEY_MODE="keep"
[ "${ROTATE_KEY:-0}" = "1" ] && KEY_MODE="update"

ensure_secret "${SECRET_USER}" "${USERNAME}"          || FAILED=$((FAILED + 1))
ensure_secret "${SECRET_PASS}" "${PASSWORD}"          || FAILED=$((FAILED + 1))
ensure_secret "${SECRET_KEY}"  "$(random_token)${RANDOM}$(random_token)" "${KEY_MODE}" \
                                                      || FAILED=$((FAILED + 1))

echo ""
if [ "${FAILED}" -gt 0 ]; then
    echo "✗ ${FAILED} secret(s) failed. Fix the errors above and re-run."
    exit 1
fi

if [ "${GENERATED_PASSWORD}" = "1" ]; then
    echo "Generated password (shown once, not stored anywhere else):"
    echo "   ${PASSWORD}"
    echo ""
fi
echo "✓ Secrets are in place and readable by ${SA_NAME}."
echo "  Next: ALLOW_UNAUTH=1 bash cloud_install/deploy-cloudrun.sh"
