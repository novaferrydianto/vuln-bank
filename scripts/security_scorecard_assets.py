#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse

REPO = os.environ["REPO"]
TOKEN = os.environ["GITHUB_TOKEN"]

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "vuln-bank-scorecard-assets"
}

ASSETS = {
    "frontend": ["asset:frontend"],
    "backend":  ["asset:backend"],
    "db":       ["asset:db"],
}

OWASP_KEYS = [f"A{i:02}" for i in range(1, 11)]

def gh_get(url):
    req = urllib.request.Request(url, headers=HEADERS)
    return json.load(urllib.request.urlopen(req))

def list_issues(page=1):
    url = f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100&page={page}"
    return gh_get(url)

# Count OWASP labels per asset (requires issues labeled asset:*)
result = {
    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    "repo": REPO,
    "assets": {a: {"counts": {k: 0 for k in OWASP_KEYS}, "total": 0} for a in ASSETS}
}

page = 1
while True:
    issues = list_issues(page)
    if not issues:
        break

    for issue in issues:
        labels = [ (l.get("name") or "").lower() for l in issue.get("labels", []) ]
        # detect asset
        asset_hit = None
        for asset, tags in ASSETS.items():
            if any(t in labels for t in tags):
                asset_hit = asset
                break
        if not asset_hit:
            continue

        for lbl in labels:
            u = lbl.upper()
            if u.startswith("OWASP:A"):
                key = u.replace("OWASP:", "")
                if key in result["assets"][asset_hit]["counts"]:
                    result["assets"][asset_hit]["counts"][key] += 1
                    result["assets"][asset_hit]["total"] += 1

    page += 1

os.makedirs("docs/data", exist_ok=True)
with open("docs/data/security-scorecard-assets.json", "w") as f:
    json.dump(result, f, indent=2)

print("[OK] Per-asset OWASP score inputs generated")
