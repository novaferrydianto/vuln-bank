#!/usr/bin/env python3
import os
import sys
import json
import datetime
import urllib.parse
import urllib.request

SONAR_HOST_URL = os.getenv("SONAR_HOST_URL", "").rstrip("/")
SONAR_PROJECT_KEY = os.getenv("SONAR_PROJECT_KEY", "")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")

REPORT_DIR = os.getenv("REPORT_DIR", "security-reports")
OUT_FILE = os.path.join(REPORT_DIR, "sonar-hotspots.json")


def sonar_api(path: str, params: dict) -> dict:
    if not SONAR_HOST_URL or not SONAR_TOKEN:
        raise SystemExit("SONAR_HOST_URL or SONAR_TOKEN not set")

    query = urllib.parse.urlencode(params)
    url = f"{SONAR_HOST_URL}{path}?{query}"

    req = urllib.request.Request(url)
    # token-only auth (no user:pass, anti-gitleaks friendly)
    req.add_header("Authorization", f"Bearer {SONAR_TOKEN}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
        return json.loads(data.decode("utf-8"))


def main() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)

    issues_resp = sonar_api(
        "/api/issues/search",
        {
            "componentKeys": SONAR_PROJECT_KEY,
            "types": "VULNERABILITY,SECURITY_HOTSPOT",
            "ps": 500,
        },
    )

    issues = issues_resp.get("issues", [])
    components = {c["key"]: c for c in issues_resp.get("components", [])}

    summary = {
        "project": SONAR_PROJECT_KEY,
        "synced_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_issues": len(issues),
        "by_severity": {},
        "issues": [],
    }

    for issue in issues:
        sev = issue.get("severity", "UNKNOWN")
        summary["by_severity"].setdefault(sev, 0)
        summary["by_severity"][sev] += 1

        comp_key = issue.get("component")
        comp_name = components.get(comp_key, {}).get("path") or comp_key

        summary["issues"].append(
            {
                "key": issue.get("key"),
                "type": issue.get("type"),
                "severity": sev,
                "rule": issue.get("rule"),
                "component": comp_name,
                "line": issue.get("line"),
                "message": issue.get("message"),
                "creationDate": issue.get("creationDate"),
                "updateDate": issue.get("updateDate"),
            }
        )

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote Sonar hotspots summary to {OUT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover
        print(f"[ERROR] sonar_defectdojo_bridge failed: {exc}", file=sys.stderr)
        sys.exit(1)
