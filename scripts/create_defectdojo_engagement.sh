#!/usr/bin/env bash
set -euo pipefail

: "${DEFECTDOJO_URL:?}"
: "${DEFECTDOJO_API_KEY:?}"
: "${DEFECTDOJO_PRODUCT_ID:?}"

# ---------- REQUIREMENTS ----------
command -v jq >/dev/null 2>&1 || {
  echo "[FATAL] jq is required but not installed"
  exit 1
}

# ---------- CONTEXT ----------
PR_NUMBER="$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")"
COMMIT_SHA="${GITHUB_SHA:-}"
REPO_URL="https://github.com/${GITHUB_REPOSITORY}"

if [[ -z "$PR_NUMBER" ]]; then
  echo "[INFO] Not a PR run – skipping engagement creation"
  exit 0
fi

ENGAGEMENT_NAME="VulnBank-PR-${PR_NUMBER}"

echo "[INFO] Using engagement: $ENGAGEMENT_NAME"

# ---------- CHECK EXISTING ----------
ENGAGEMENT_ID="$(curl -fsS \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  "$DEFECTDOJO_URL/api/v2/engagements/?name=$ENGAGEMENT_NAME&product=$DEFECTDOJO_PRODUCT_ID" \
  | jq -r '.results[0].id // empty')"

if [[ -n "$ENGAGEMENT_ID" ]]; then
  echo "[INFO] Reusing engagement ID=$ENGAGEMENT_ID"
  echo "DEFECTDOJO_ENGAGEMENT_ID=$ENGAGEMENT_ID" >> "$GITHUB_ENV"
  exit 0
fi

# ---------- CREATE ENGAGEMENT ----------
ENGAGEMENT_ID="$(curl -fsS -X POST \
  "$DEFECTDOJO_URL/api/v2/engagements/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$ENGAGEMENT_NAME\",
    \"product\": $DEFECTDOJO_PRODUCT_ID,
    \"status\": \"In Progress\",
    \"engagement_type\": \"CI/CD\",
    \"source_code_management_uri\": \"$REPO_URL\",
    \"branch_tag\": \"${GITHUB_HEAD_REF:-}\",
    \"build_id\": \"${GITHUB_RUN_ID:-}\",
    \"commit_hash\": \"${COMMIT_SHA}\"
  }" | jq -r '.id')"

if [[ -z "$ENGAGEMENT_ID" ]]; then
  echo "[FATAL] Failed to create engagement"
  exit 1
fi

echo "[OK] Created engagement ID=$ENGAGEMENT_ID"
echo "DEFECTDOJO_ENGAGEMENT_ID=$ENGAGEMENT_ID" >> "$GITHUB_ENV"
