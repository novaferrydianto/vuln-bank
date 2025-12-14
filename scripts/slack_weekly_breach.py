#!/usr/bin/env python3
import os, json, urllib.request

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]

def load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

sla = load("docs/data/defectdojo-sla-weekly.json", {})
score = load("docs/data/security-scorecard.json", {})

breaches = (sla.get("breaches") or {})
crit = int(breaches.get("Critical", 0) or 0)
high = int(breaches.get("High", 0) or 0)

per_asset = sla.get("per_asset") or {}
details = sla.get("details") or []

overall = (score.get("score") or {}).get("overall")
grade = score.get("grade")

lines = []
lines.append("*Weekly SLA Breach Report (DefectDojo Findings)*")
if overall is not None and grade:
    lines.append(f"Scorecard: *{overall}* ({grade})")

lines.append(f"Breaches: *Critical={crit}* | *High={high}*")

# Per-asset summary
if per_asset:
    lines.append("")
    lines.append("*Breaches by asset:*")
    for a in sorted(per_asset.keys()):
        c = int(((per_asset[a].get("Critical") or {}).get("breaches", 0)) or 0)
        h = int(((per_asset[a].get("High") or {}).get("breaches", 0)) or 0)
        if (c + h) > 0:
            lines.append(f"- `{a}` → Critical={c}, High={h}")

# Top offenders
top = details[:5]
if top:
    lines.append("")
    lines.append("*Top overdue findings:*")
    for it in top:
        lines.append(f"- [{it.get('severity')}] `{it.get('asset')}` age={it.get('age_days')}d (SLA {it.get('sla_days')}d) | {it.get('title')}")
        if it.get("url"):
            lines.append(f"  {it.get('url')}")

payload = {"text": "\n".join(lines)}

req = urllib.request.Request(
    SLACK_WEBHOOK_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type":"application/json"},
    method="POST"
)
urllib.request.urlopen(req, timeout=20)
print("[OK] Slack weekly breach summary sent")
