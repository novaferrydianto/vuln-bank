#!/usr/bin/env bash
set -euo pipefail

SCAN_TYPE="$1"
FILE="$2"
TAGS="$3"

if [ ! -f "$FILE" ]; then
  echo "[SKIP] $FILE not found"
  exit 0
fi

echo "[INFO] Importing $SCAN_TYPE to DefectDojo"

curl -sS -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -F "scan_type=$SCAN_TYPE" \
  -F "file=@$FILE" \
  -F "product=$DEFECTDOJO_PRODUCT_ID" \
  -F "engagement=$DEFECTDOJO_ENGAGEMENT_ID" \
  -F "tags=$TAGS" \
  -F "active=true" \
  -F "verified=true"
