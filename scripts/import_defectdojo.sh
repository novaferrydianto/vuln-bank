#!/usr/bin/env bash
set -euo pipefail

# ======================================================
# DefectDojo Import Script (CI-safe, Rocky-compatible)
# ======================================================

REQUIRED_VARS=(
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_PRODUCT_ID
  DEFECTDOJO_ENGAGEMENT_ID
)

for v in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "[FATAL] Environment variable $v is not set"
    exit 1
  fi
done

import_scan () {
  local scan_type="$1"
  local file_path="$2"
  local tags="${3:-}"

  if [[ ! -f "$file_path" ]]; then
    echo "[SKIP] $scan_type – file not found: $file_path"
    return 0
  fi

  echo "[INFO] Importing $scan_type → DefectDojo"

  curl -fsS -X POST \
    "$DEFECTDOJO_URL/api/v2/import-scan/" \
    -H "Authorization: Token $DEFECTDOJO_API_KEY" \
    -F "scan_type=$scan_type" \
    -F "file=@$file_path" \
    -F "product=$DEFECTDOJO_PRODUCT_ID" \
    -F "engagement=$DEFECTDOJO_ENGAGEMENT_ID" \
    -F "active=true" \
    -F "verified=true" \
    -F "close_old_findings=true" \
    -F "push_to_jira=false" \
    ${tags:+-F "tags=$tags"} \
    || {
      echo "[WARN] DefectDojo unreachable, skipping $scan_type import"
      return 0
    }

  echo "[OK] $scan_type imported"
}

# ======================================================
# Imports (MATCH CI OUTPUT PATHS)
# ======================================================

CI_TAGS="ci:${GITHUB_RUN_ID:-local},repo:${GITHUB_REPOSITORY:-vuln-bank}"

# ---- DAST ----
import_scan \
  "ZAP Scan" \
  "security-reports/zap/zap_alerts.json" \
  "source:zap,type:dast,${CI_TAGS}"

# ---- SCA ----
import_scan \
  "Trivy Scan" \
  "security-reports/trivy-sca.json" \
  "source:trivy,type:sca,${CI_TAGS}"

# ---- SAST (NORMALIZED) ----
import_scan \
  "Bandit Scan" \
  "security-reports/bandit_dd.json" \
  "source:bandit,type:sast,${CI_TAGS}"

echo "[DONE] DefectDojo imports completed (CI-safe)"
