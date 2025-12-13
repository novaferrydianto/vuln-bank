# scripts/slack_incident.py
import os, json, urllib.request

labels = os.getenv("OWASP_LABELS","").split(",")
incident = any(l in ("OWASP-A01-Broken-Access-Control",
                     "OWASP-A02-Broken-Authentication") for l in labels)

if not incident:
    print("[OK] No incident-level OWASP")
    exit(0)

payload = {
  "text": (
    "🚨 *SECURITY INCIDENT CREATED*\n"
    f"Repo: `{os.getenv('REPO')}`\n"
    f"PR: #{os.getenv('PR_NUMBER')}\n"
    f"OWASP: {', '.join(labels)}\n"
    "*Severity:* CRITICAL"
  )
}

req = urllib.request.Request(
  os.environ["SLACK_WEBHOOK_URL"],
  data=json.dumps(payload).encode(),
  headers={"Content-Type":"application/json"}
)
urllib.request.urlopen(req)
