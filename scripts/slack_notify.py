import json
import urllib.request
import os
import sys

webhook = os.environ.get("SLACK_WEBHOOK_URL")
if not webhook:
    print("SLACK_WEBHOOK_URL not set")
    sys.exit(0)

status = os.environ.get("PIPELINE_STATUS", "FAILED")
env = os.environ.get("APP_ENV", "unknown")
repo = os.environ.get("GITHUB_REPOSITORY", "unknown")
commit = os.environ.get("GITHUB_SHA", "unknown")

emoji = ":white_check_mark:" if status == "SUCCESS" else ":rotating_light:"

msg = {
    "text": (
        f"{emoji} Vuln Bank Pipeline {status}\n"
        f"Env: {env}\n"
        f"Repo: {repo}\n"
        f"Commit: {commit}\n"
    )
}

req = urllib.request.Request(
    webhook,
    data=json.dumps(msg).encode(),
    headers={"Content-Type": "application/json"}
)

urllib.request.urlopen(req)
print("Slack notification sent")
