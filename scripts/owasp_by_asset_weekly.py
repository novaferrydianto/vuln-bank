#!/usr/bin/env python3
import os, json, urllib.request, urllib.parse, datetime, re

REPO = os.environ["REPO"]
TOKEN = os.environ["GITHUB_TOKEN"]

HEADERS = {
  "Authorization": f"Bearer {TOKEN}",
  "Accept": "application/vnd.github+json",
  "User-Agent": "vuln-bank-owasp-by-asset"
}

OWASP_KEYS = [f"A{i:02}" for i in range(1, 11)]
ASSETS = ["frontend", "backend", "db", "unknown"]

def guess_asset(text: str) -> str:
    t = (text or "").lower()
    if any(x in t for x in ["docs/", "/docs", "ui/", "/ui", "frontend/", "react", "next", "nuxt", "vue", ".css", ".js", ".ts", ".html"]):
        return "frontend"
    if any(x in t for x in ["k8s/db", "postgres", "postgresql", "mysql", "redis", "mongodb", "db/", "database", "5432", "3306"]):
        return "db"
    if any(x in t for x in ["containers/app", "api", "flask", "django", "fastapi", "backend", "service", ".py"]):
        return "backend"
    return "unknown"

def fetch_issues(page: int):
    # NOTE: /issues includes PRs; we will skip PR objects
    params = {"state":"all","per_page":100,"page":page}
    url = f"https://api.github.com/repos/{REPO}/issues?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def main():
    # counts[asset][Axx] = int
    counts = {a: {k: 0 for k in OWASP_KEYS} for a in ASSETS}

    page = 1
    while True:
        items = fetch_issues(page)
        if not items:
            break

        for it in items:
            # skip PR entries
            if "pull_request" in it:
                continue

            labels = [ (x.get("name") or "").strip() for x in (it.get("labels") or []) ]
            labels_l = [x.lower() for x in labels]

            # asset from label first
            asset = None
            for a in ["asset:frontend","asset:backend","asset:db"]:
                if a in labels_l:
                    asset = a.split("asset:",1)[1]
                    break

            # fallback from title/body if missing
            if not asset:
                asset = guess_asset((it.get("title") or "") + "\n" + (it.get("body") or ""))

            if asset not in counts:
                asset = "unknown"

            # owasp from labels
            for lb in labels:
                u = lb.upper()
                if u.startswith("OWASP:A"):
                    key = u.replace("OWASP:", "")
                    if key in counts[asset]:
                        counts[asset][key] += 1

        page += 1

    out = {
        "repo": REPO,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "by_asset": counts
    }

    os.makedirs("docs/data", exist_ok=True)
    with open("docs/data/owasp-by-asset.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("[OK] docs/data/owasp-by-asset.json generated")

if __name__ == "__main__":
    main()
