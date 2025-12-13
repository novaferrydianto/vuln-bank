#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse

REPO = os.environ["REPO"]
TOKEN = os.environ["GITHUB_TOKEN"]

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "vuln-bank-weekly-trend"
}

NOW = datetime.datetime.utcnow()
SINCE = (NOW - datetime.timedelta(days=7)).isoformat() + "Z"

OWASP_KEYS = [f"A{i:02}" for i in range(1, 11)]
counts = {k: 0 for k in OWASP_KEYS}

def fetch_issues(page: int):
    q = {
        "state": "all",
        "per_page": 100,
        "page": page,
        "since": SINCE
    }
    url = f"https://api.github.com/repos/{REPO}/issues?" + urllib.parse.urlencode(q)
    req = urllib.request.Request(url, headers=HEADERS)
    return json.load(urllib.request.urlopen(req))

# --- paginate issues ---
page = 1
while True:
    issues = fetch_issues(page)
    if not issues:
        break

    for issue in issues:
        for lbl in issue.get("labels", []):
            name = (lbl.get("name") or "").upper()
            if name.startswith("OWASP:A"):
                key = name.replace("OWASP:", "")
                if key in counts:
                    counts[key] += 1
    page += 1

# --- output object ---
result = {
    "repo": REPO,
    "window": "7d",
    "generated_at": NOW.isoformat() + "Z",
    "counts": counts
}

# --- paths ---
os.makedirs("security-metrics/weekly", exist_ok=True)
os.makedirs("docs/data", exist_ok=True)

latest_path = "docs/data/owasp-latest.json"
history_path = "docs/data/owasp-history.jsonl"

# --- write latest ---
with open(latest_path, "w") as f:
    json.dump(result, f, indent=2)

# --- append history ---
with open(history_path, "a") as f:
    f.write(json.dumps(result) + "\n")

# --- also keep raw copy ---
with open("security-metrics/weekly/owasp-latest.json", "w") as f:
    json.dump(result, f, indent=2)

print("[OK] Weekly OWASP trend generated")
