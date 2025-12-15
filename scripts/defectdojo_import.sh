#!/usr/bin/env bash
set -euo pipefail

SCAN_TYPE="$1"
FILE="$2"
ACTIVE="$3"

curl -sS -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -F "scan_type=$SCAN_TYPE" \
  -F "file=@$FILE" \
  -F "product=$DEFECTDOJO_PRODUCT_ID" \
  -F "engagement=$DEFECTDOJO_ENGAGEMENT_ID" \
  -F "active=$ACTIVE" \
  -F "verified=true"
