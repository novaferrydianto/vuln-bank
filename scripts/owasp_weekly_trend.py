import os, json, datetime, urllib.request

repo = os.environ["REPO"]
token = os.environ["GITHUB_TOKEN"]

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "vuln-bank-weekly-trend"
}

OWASP = {f"A{i:02}": 0 for i in range(1, 11)}

url = f"https://api.github.com/repos/{repo}/issues?state=all&per_page=100"
req = urllib.request.Request(url, headers=headers)
issues = json.load(urllib.request.urlopen(req))

for issue in issues:
    for lbl in issue.get("labels", []):
        name = lbl["name"].upper()
        if name.startswith("OWASP:A"):
            key = name.replace("OWASP:", "")
            if key in OWASP:
                OWASP[key] += 1

out = {
    "repo": repo,
    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    "owasp_counts": OWASP
}

os.makedirs("security-metrics", exist_ok=True)
with open("security-metrics/weekly-owasp.json", "w") as f:
    json.dump(out, f, indent=2)

print("[OK] Weekly OWASP trend generated")
