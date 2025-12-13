#!/usr/bin/env python3
"""
ZAP → GitHub Issues Integrator (Refactored FINAL)

Key changes (best practice):
- 1 GitHub Issue per ZAP alert title (deduped), NOT per URL.
- Aggregate affected URLs into issue body.
- Idempotent: create if missing, update body if changed, auto-close when resolved.
- Policy-as-Code ignore list (zap_ignore_alerts.json).
- SLA labels + severity labels.
- Dashboard cross-link.

Required env:
- GITHUB_TOKEN
- GITHUB_REPOSITORY (owner/repo)

Expected files:
- security-reports/zap/zap_alerts.json
- zap_ignore_alerts.json (optional)
"""

import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

import requests

# ---------------------------------------------------------
# Config
# ---------------------------------------------------------
ZAP_JSON = Path("security-reports/zap/zap_alerts.json")
IGNORE_ALERTS_FILE = Path("zap_ignore_alerts.json")

GITHUB_API = "https://api.github.com"
REPO = os.getenv("GITHUB_REPOSITORY", "").strip()
TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

# Optional: Override in workflow if you use custom pages path
# e.g. https://<owner>.github.io/<repo>
DASHBOARD_URL = (
    f"https://{REPO.split('/')[0]}.github.io/{REPO.split('/')[1]}"
    if REPO and "/" in REPO
    else ""
)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

SEVERITY_MAP = {
    "High": "CRITICAL",
    "Medium": "HIGH",
    "Low": "MEDIUM",
    "Informational": "LOW",
}

SLA_LABELS = {
    "CRITICAL": "sla-7-days",
    "HIGH": "sla-14-days",
    "MEDIUM": "sla-30-days",
    "LOW": "sla-90-days",
}

BASE_LABELS = ["security", "dast", "zap"]

# Limits to keep issues readable
MAX_URLS_IN_BODY = 40
HTTP_TIMEOUT = 30


# ---------------------------------------------------------
# Utilities
# ---------------------------------------------------------
def fatal(msg: str) -> None:
    print(f"[FATAL] {msg}")
    sys.exit(1)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Invalid JSON in {path}: {e}") from e


def load_ignored_alerts() -> Set[str]:
    if not IGNORE_ALERTS_FILE.exists():
        return set()
    try:
        data = safe_json_load(IGNORE_ALERTS_FILE)
        if isinstance(data, list):
            return {str(x).strip() for x in data if str(x).strip()}
        print("[WARN] zap_ignore_alerts.json is not a list. Ignoring file.")
        return set()
    except Exception as e:
        print(f"[WARN] Failed loading zap_ignore_alerts.json: {e}")
        return set()


def request_raise(method: str, url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    r = requests.request(method, url, headers=HEADERS, **kwargs)
    # Helpful error printing
    if r.status_code >= 400:
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        print(f"[HTTP {r.status_code}] {method} {url}")
        print(detail)
    r.raise_for_status()
    return r


# ---------------------------------------------------------
# ZAP Parsing (dedupe per alert title)
# ---------------------------------------------------------
def parse_zap_findings(zap_data: Dict[str, Any], ignored: Set[str]) -> Dict[str, Dict[str, Any]]:
    """
    Returns:
      key -> finding
      key = alert_title (1 issue per alert)

    Finding structure:
      {
        title, risk, severity, description, solution, reference,
        uris: [ ... ],
      }
    """
    findings: Dict[str, Dict[str, Any]] = {}

    for site in zap_data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            title = (alert.get("alert") or "").strip()
            if not title:
                continue

            if title in ignored:
                print(f"[IGNORE] {title}")
                continue

            risk = (alert.get("risk") or "Low").strip()
            severity = SEVERITY_MAP.get(risk, "LOW")

            if title not in findings:
                findings[title] = {
                    "title": title,
                    "risk": risk,
                    "severity": severity,
                    "description": (alert.get("description") or "").strip(),
                    "solution": (alert.get("solution") or "").strip(),
                    "reference": (alert.get("reference") or "").strip(),
                    "uris": set(),  # temp set
                }

            # aggregate URIs
            for inst in alert.get("instances", []) or []:
                uri = (inst.get("uri") or "").strip()
                if uri:
                    findings[title]["uris"].add(uri)

    # finalize: set -> sorted list
    for f in findings.values():
        f["uris"] = sorted(list(f["uris"]))

    return findings


# ---------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------
def github_get(url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    return request_raise("GET", url, params=params).json()


def github_post(url: str, payload: Dict[str, Any]) -> Any:
    return request_raise("POST", url, json=payload).json()


def github_patch(url: str, payload: Dict[str, Any]) -> Any:
    return request_raise("PATCH", url, json=payload).json()


def github_comment(issue_number: int, body: str) -> None:
    github_post(
        f"{GITHUB_API}/repos/{REPO}/issues/{issue_number}/comments",
        {"body": body},
    )


def get_open_dast_issues() -> List[Dict[str, Any]]:
    """
    Pull open issues and filter:
    - title starts with [DAST]
    - has label 'dast'
    - not labeled do-not-close / risk-accepted
    """
    issues = github_get(
        f"{GITHUB_API}/repos/{REPO}/issues",
        params={"state": "open", "per_page": 100},
    )

    result: List[Dict[str, Any]] = []
    for i in issues:
        labels = [l["name"] for l in i.get("labels", [])]
        if (
            str(i.get("title", "")).startswith("[DAST]")
            and "dast" in labels
            and "do-not-close" not in labels
            and "risk-accepted" not in labels
        ):
            result.append(i)
    return result


# ---------------------------------------------------------
# Issue keying + parsing
# ---------------------------------------------------------
def issue_key_from_title(issue_title: str) -> str:
    """
    Issue title format we create:
      [DAST] <alert title>
    Returns:
      <alert title>
    """
    if "] " in issue_title:
        return issue_title.split("] ", 1)[1].strip()
    return issue_title.strip()


def extract_issue_key(issue: Dict[str, Any]) -> str:
    return issue_key_from_title(issue.get("title", ""))


# ---------------------------------------------------------
# Body rendering
# ---------------------------------------------------------
def render_urls_section(uris: List[str]) -> str:
    if not uris:
        return "_No affected URLs reported by ZAP (unexpected)._"

    shown = uris[:MAX_URLS_IN_BODY]
    extra = len(uris) - len(shown)
    lines = "\n".join(f"- {u}" for u in shown)
    if extra > 0:
        lines += f"\n- ... and {extra} more"
    return lines


def build_issue_body(finding: Dict[str, Any]) -> str:
    urls_md = render_urls_section(finding.get("uris", []))

    # Hash to make idempotent update detection simple
    fingerprint_payload = {
        "risk": finding.get("risk"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "solution": finding.get("solution"),
        "reference": finding.get("reference"),
        "uris": finding.get("uris", [])[:MAX_URLS_IN_BODY],  # stable subset
    }
    fp = sha256(json.dumps(fingerprint_payload, sort_keys=True))

    dashboard_block = f"\n📊 **Security Dashboard:**\n{DASHBOARD_URL}\n" if DASHBOARD_URL else ""

    body = f"""### 🔍 DAST Finding (OWASP ZAP)

**Finding:** `{finding['title']}`  
**Severity:** `{finding['severity']}`  
**Risk:** `{finding['risk']}`  

---

### 🌐 Affected URLs
{urls_md}

---

### 📖 Description
{finding.get('description','')}

---

### 🛠️ Recommended Fix
{finding.get('solution','')}

---

### 🔗 References
{finding.get('reference','')}

---

{dashboard_block}
_Managed automatically by DevSecOps pipeline._  
<!-- zap_fingerprint: {fp} -->
"""
    return body.strip()


def extract_fingerprint_from_body(body: str) -> Optional[str]:
    """
    Look for:
      <!-- zap_fingerprint: <hash> -->
    """
    marker = "zap_fingerprint:"
    for line in (body or "").splitlines():
        if marker in line:
            # naive parse but robust enough
            try:
                return line.split(marker, 1)[1].replace("-->", "").strip()
            except Exception:
                return None
    return None


# ---------------------------------------------------------
# Issue management
# ---------------------------------------------------------
def desired_labels_for_finding(finding: Dict[str, Any]) -> List[str]:
    return BASE_LABELS + [
        f"severity/{finding['severity']}",
        SLA_LABELS.get(finding["severity"], "sla-30-days"),
    ]


def create_issue(finding: Dict[str, Any]) -> None:
    title = f"[DAST] {finding['title']}"
    labels = desired_labels_for_finding(finding)
    body = build_issue_body(finding)

    payload = {"title": title, "body": body, "labels": labels}
    github_post(f"{GITHUB_API}/repos/{REPO}/issues", payload)
    print(f"[CREATE] {title}")


def update_issue_if_needed(issue: Dict[str, Any], finding: Dict[str, Any]) -> None:
    """
    Update issue body/labels if content changed.
    Keeps idempotency and avoids noisy comments.
    """
    issue_number = issue["number"]
    current_body = issue.get("body", "") or ""
    current_fp = extract_fingerprint_from_body(current_body)
    desired_body = build_issue_body(finding)
    desired_fp = extract_fingerprint_from_body(desired_body)

    # update labels too (ensure SLA/severity correct)
    desired_labels = desired_labels_for_finding(finding)
    current_labels = sorted([l["name"] for l in issue.get("labels", [])])
    desired_labels_sorted = sorted(desired_labels)

    needs_body_update = (desired_fp is not None and desired_fp != current_fp)
    needs_label_update = (current_labels != sorted(set(current_labels + desired_labels_sorted)) and
                          not set(desired_labels_sorted).issubset(set(current_labels)))

    if needs_body_update or needs_label_update:
        patch_payload: Dict[str, Any] = {}
        if needs_body_update:
            patch_payload["body"] = desired_body
        if needs_label_update:
            # Preserve existing labels, but ensure required ones exist
            merged = sorted(set(current_labels).union(set(desired_labels_sorted)))
            patch_payload["labels"] = merged

        github_patch(f"{GITHUB_API}/repos/{REPO}/issues/{issue_number}", patch_payload)
        print(f"[UPDATE] Issue #{issue_number} [{finding['title']}] updated")
    else:
        print(f"[SKIP] Issue #{issue_number} [{finding['title']}] unchanged")


def close_issue(issue: Dict[str, Any], reason: str) -> None:
    issue_number = issue["number"]
    github_patch(f"{GITHUB_API}/repos/{REPO}/issues/{issue_number}", {"state": "closed"})

    comment = f"""✅ **Auto-closed by DevSecOps pipeline**

**Reason:** {reason}

The latest OWASP ZAP scan no longer reports this finding.
{f"📊 Dashboard: {DASHBOARD_URL}" if DASHBOARD_URL else ""}
"""
    github_comment(issue_number, comment.strip())
    print(f"[CLOSE] Issue #{issue_number} closed")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main() -> None:
    if not TOKEN or not REPO:
        fatal("GITHUB_TOKEN or GITHUB_REPOSITORY not set")

    if not ZAP_JSON.exists():
        print("[INFO] No ZAP results found (missing security-reports/zap/zap_alerts.json)")
        return

    ignored = load_ignored_alerts()
    if ignored:
        print(f"[INFO] Loaded {len(ignored)} ignored alerts from {IGNORE_ALERTS_FILE}")

    zap_data = safe_json_load(ZAP_JSON)
    current_findings = parse_zap_findings(zap_data, ignored)

    print(f"[INFO] Current deduped findings: {len(current_findings)}")

    # Fetch open issues
    open_issues = get_open_dast_issues()
    open_issue_by_key: Dict[str, Dict[str, Any]] = {}
    for issue in open_issues:
        k = extract_issue_key(issue)
        if k:
            open_issue_by_key[k] = issue

    # Create/update
    created = 0
    updated = 0
    for key, finding in current_findings.items():
        if key not in open_issue_by_key:
            create_issue(finding)
            created += 1
        else:
            update_issue_if_needed(open_issue_by_key[key], finding)
            updated += 1

    # Auto-close resolved
    closed = 0
    for key, issue in open_issue_by_key.items():
        if key not in current_findings:
            close_issue(issue, "Finding no longer detected by ZAP")
            closed += 1

    print(f"[OK] ZAP sync complete | created={created} updated={updated} closed={closed}")


if __name__ == "__main__":
    main()
