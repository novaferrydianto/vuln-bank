#!/usr/bin/env bash
set -euo pipefail

: "${DEFECTDOJO_URL:?}"
: "${DEFECTDOJO_API_KEY:?}"
: "${DEFECTDOJO_PRODUCT_ID:?}"

command -v jq >/dev/null 2>&1 || {
  echo "[FATAL] jq is required but not installed"
  exit 1
}

PR_NUMBER="$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")"

if [[ -z "$PR_NUMBER" ]]; then
  echo "[INFO] Not a PR run – skipping engagement creation"
  exit 0
fi

ENGAGEMENT_NAME="VulnBank-PR-${PR_NUMBER}"

TODAY="$(date +%Y-%m-%d)"
END_DATE="$(date -d '+7 days' +%Y-%m-%d)"

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

# ---------- CREATE ENGAGEMENT (VALID PAYLOAD ONLY) ----------
ENGAGEMENT_ID="$(curl -fsS -X POST \
  "$DEFECTDOJO_URL/api/v2/engagements/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$ENGAGEMENT_NAME\",
    \"product\": $DEFECTDOJO_PRODUCT_ID,
    \"status\": \"In Progress\",
    \"target_start\": \"$TODAY\",
    \"target_end\": \"$END_DATE\"
  }" | jq -r '.id')"

if [[ -z "$ENGAGEMENT_ID" ]]; then
  echo "[FATAL] Failed to create engagement"
  exit 1
fi

echo "[OK] Created engagement ID=$ENGAGEMENT_ID"
echo "DEFECTDOJO_ENGAGEMENT_ID=$ENGAGEMENT_ID" >> "$GITHUB_ENV"
