# scripts/defectdojo_close_and_sla.sh
set -euo pipefail

SEVERITY="$1"   # critical/high/medium
SLA_DAYS=30

case "$SEVERITY" in
  critical) SLA_DAYS=7 ;;
  high) SLA_DAYS=14 ;;
esac

curl -sS -X PATCH \
  "$DEFECTDOJO_URL/api/v2/engagements/$DEFECTDOJO_ENGAGEMENT_ID/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\":\"Completed\",
    \"target_end\": \"$(date -u -d \"+$SLA_DAYS days\" +%F)\"
  }"
