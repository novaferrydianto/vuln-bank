#!/usr/bin/env python3
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("security-reports")

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

def load_json(path):
    if not path.exists():
        return None
    try:
        with path.open() as f:
            return json.load(f)
    except Exception:
        return None

def canon_severity(value):
    if not value:
        return "INFO"
    return SEVERITY_MAP.get(str(value).upper(), "INFO")

def fingerprint(*parts):
    raw = "|".join(str(p) for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def normalize():
    normalized = {
        "meta": {
            "app": os.getenv("APP_NAME", "vuln-bank"),
            "image": f'{os.getenv("IMAGE_REPO","")}:{os.getenv("GITHUB_SHA","")}',
            "commit": os.getenv("GITHUB_SHA"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "findings": []
    }

    def add_finding(**f):
        f["severity"] = canon_severity(f.get("severity"))
        f["fingerprint"] = fingerprint(
            f.get("source"),
            f.get("id"),
            f.get("path"),
            f.get("pkg"),
            f.get("url"),
        )
        f.setdefault("epss", None)
        f.setdefault("asvs", None)
        normalized["findings"].append(f)

    # --- Trivy Image ---
    trivy_image = load_json(REPORT_DIR / "trivy-image.json")
    if trivy_image:
        for r in trivy_image.get("Results", []):
            for v in r.get("Vulnerabilities", []) or []:
                add_finding(
                    source="trivy-image",
                    id=v.get("VulnerabilityID"),
                    severity=v.get("Severity"),
                    title=v.get("Title"),
                    pkg=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    cve=v.get("VulnerabilityID"),
                )

    # --- Bandit ---
    bandit = load_json(REPORT_DIR / "bandit.json")
    if bandit:
        for r in bandit.get("results", []):
            add_finding(
                source="bandit",
                id=r.get("test_id"),
                severity=r.get("issue_severity"),
                title=r.get("test_name"),
                path=r.get("filename"),
                line=r.get("line_number"),
            )

    # --- Semgrep ---
    semgrep = load_json(REPORT_DIR / "semgrep.json")
    if semgrep:
        for r in semgrep.get("results", []):
            extra = r.get("extra", {})
            add_finding(
                source="semgrep",
                id=extra.get("rule_id"),
                severity=extra.get("severity"),
                title=extra.get("message"),
                path=r.get("path"),
                start=r.get("start"),
            )

    # --- Gitleaks ---
    gitleaks = load_json(REPORT_DIR / "gitleaks.json")
    if isinstance(gitleaks, list):
        for f in gitleaks:
            add_finding(
                source="gitleaks",
                id=f.get("RuleID"),
                severity="HIGH",
                title=f.get("Description"),
                path=f.get("File"),
            )

    # --- OWASP ZAP ---
    zap = load_json(REPORT_DIR / "zap/zap-report.json")
    if zap:
        for site in zap.get("site", []):
            for alert in site.get("alerts", []):
                severity = {
                    "3": "HIGH",
                    "2": "MEDIUM",
                    "1": "LOW",
                }.get(str(alert.get("riskcode")), "INFO")

                add_finding(
                    source="zap",
                    id=alert.get("alert"),
                    severity=severity,
                    title=alert.get("name"),
                    url=alert.get("url"),
                )

    out = REPORT_DIR / "normalized.json"
    out.write_text(json.dumps(normalized, indent=2))
    print(f"✅ Normalized report written to {out}")

if __name__ == "__main__":
    normalize()
