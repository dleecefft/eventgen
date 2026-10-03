#!/bin/bash
# =============================================================================
# EventGen — one-time GCP project bootstrap
# =============================================================================
#
# Enables the required APIs, creates the Artifact Registry repository and the
# runtime service account, and grants the Cloud Build identity permission to
# push images. Safe to re-run.
#
# The runtime service account gets NO project roles. Its only access is
# secretAccessor on its own three secrets, granted by provision-secrets.sh.
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="my-project"
#   export CLOUD_RUN_REGION="us-central1"
#   bash cloud_install/provision-gcp-project.sh
#
# Caller needs: roles/serviceusage.serviceUsageAdmin, roles/iam.serviceAccountAdmin,
# roles/artifactregistry.admin and roles/resourcemanager.projectIamAdmin
# (Owner on a dedicated project covers all four).
# =============================================================================

set -uo pipefail

# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_project
require_region

echo ""
echo "🏗  EventGen project bootstrap"
echo "========================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Runtime:  ${SA_EMAIL}"
echo "Registry: ${AR_REPO}"
echo ""

FAILED=0

echo "── Project"
if ! err=$(gcloud projects describe "${PROJECT_ID}" 2>&1 >/dev/null); then
    report_error "Cannot read project ${PROJECT_ID}" "${err}"
    exit 1
fi
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)" 2>/dev/null)
echo "   ✓ ${PROJECT_ID} (${PROJECT_NUMBER})"

echo ""
echo "── APIs"
for api in run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
           secretmanager.googleapis.com iam.googleapis.com; do
    if err=$(gcloud services enable "${api}" --project="${PROJECT_ID}" --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${api}"
    else
        report_error "${api}" "${err}"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "── Runtime service account"
if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "   ✓ ${SA_EMAIL} — exists"
elif err=$(gcloud iam service-accounts create "${SA_NAME}" \
              --project="${PROJECT_ID}" \
              --display-name="EventGen Cloud Run runtime" 2>&1 >/dev/null); then
    echo "   ✓ ${SA_EMAIL} — created"
else
    report_error "${SA_EMAIL}" "${err}"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "── Artifact Registry"
if gcloud artifacts repositories describe "${AR_REPO}" \
      --project="${PROJECT_ID}" --location="${REGION}" >/dev/null 2>&1; then
    echo "   ✓ ${AR_REPO} (${REGION}) — exists"
elif err=$(gcloud artifacts repositories create "${AR_REPO}" \
              --project="${PROJECT_ID}" --location="${REGION}" \
              --repository-format=docker \
              --description="EventGen container images" 2>&1 >/dev/null); then
    echo "   ✓ ${AR_REPO} (${REGION}) — created"
else
    report_error "${AR_REPO}" "${err}"
    FAILED=$((FAILED + 1))
fi

# Builds run as the Compute default service account on newer projects. It
# needs to write to the registry and logs, and to read the uploaded source.
echo ""
echo "── Cloud Build permissions"
BUILD_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for role in roles/artifactregistry.writer roles/logging.logWriter roles/storage.objectViewer; do
    if err=$(gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
                --member="serviceAccount:${BUILD_SA}" --role="${role}" \
                --condition=None --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${BUILD_SA} ← ${role}"
    else
        report_error "${role} on ${BUILD_SA}" "${err}"
        FAILED=$((FAILED + 1))
    fi
done

OPERATOR=$(gcloud config get-value account 2>/dev/null)
if [ -n "${OPERATOR}" ]; then
    case "${OPERATOR}" in
        *.iam.gserviceaccount.com) OPERATOR_MEMBER="serviceAccount:${OPERATOR}" ;;
        *)                         OPERATOR_MEMBER="user:${OPERATOR}" ;;
    esac
    # Deploying with --service-account and building both require actAs.
    for target in "${SA_EMAIL}" "${BUILD_SA}"; do
        if err=$(gcloud iam service-accounts add-iam-policy-binding "${target}" \
                    --project="${PROJECT_ID}" --member="${OPERATOR_MEMBER}" \
                    --role="roles/iam.serviceAccountUser" --quiet 2>&1 >/dev/null); then
            echo "   ✓ ${OPERATOR} may act as ${target}"
        else
            report_error "actAs on ${target}" "${err}"
            FAILED=$((FAILED + 1))
        fi
    done
fi

echo ""
if [ "${FAILED}" -gt 0 ]; then
    echo "✗ ${FAILED} step(s) failed. Fix the errors above and re-run."
    exit 1
fi

echo "✓ Project is ready. Save your settings (kept outside the repo):"
echo ""
echo "  mkdir -p ~/.eventgen && cat > ~/.eventgen/deploy.env <<'EOF'"
echo "  GOOGLE_CLOUD_PROJECT='${PROJECT_ID}'"
echo "  CLOUD_RUN_REGION='${REGION}'"
echo "  EVENTGEN_ALLOWED_HOSTS='<example.com,*.example.com>'"
echo "  EOF"
echo ""
echo "  Next: bash cloud_install/provision-secrets.sh"
