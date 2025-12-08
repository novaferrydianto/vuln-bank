#!/usr/bin/env python3
import json
import os
from pathlib import Path

REPORT_DIR = Path("security-reports")

def load_json(path):
    if not path.exists():
        return None
    try:
        with path.open() as f:
            return json.load(f)
    except Exception:
        return None

def normalize():
    normalized = {
        "metadata": {
            "app": os.getenv("APP_NAME", "vuln-bank"),
            "image": os.getenv("IMAGE_REPO", "") + ":" + os.getenv("GITHUB_SHA", ""),
        },
        "findings": []
    }

    # Trivy image
    trivy_image = load_json(REPORT_DIR / "trivy-image.json")
    if trivy_image:
        for res in trivy_image.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:
                normalized["findings"].append({
                    "source": "trivy-image",
                    "id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity"),
                    "title": v.get("Title"),
                    "pkg": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                })

    # Trivy fs
    trivy_fs = load_json(REPORT_DIR / "trivy-fs.json")
    if trivy_fs:
        for res in trivy_fs.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:
                normalized["findings"].append({
                    "source": "trivy-fs",
                    "id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity"),
                    "title": v.get("Title"),
                    "target": res.get("Target"),
                })

    # Trivy config
    trivy_cfg = load_json(REPORT_DIR / "trivy-config.json")
    if trivy_cfg:
        for res in trivy_cfg.get("Results", []):
            for mis in res.get("Misconfigurations", []) or []:
                normalized["findings"].append({
                    "source": "trivy-config",
                    "id": mis.get("ID"),
                    "severity": mis.get("Severity"),
                    "title": mis.get("Title"),
                    "description": mis.get("Description"),
                    "target": res.get("Target"),
                })

    # Bandit
    bandit = load_json(REPORT_DIR / "bandit.json")
    if bandit:
        for r in bandit.get("results", []):
            normalized["findings"].append({
                "source": "bandit",
                "id": r.get("test_id"),
                "severity": r.get("issue_severity"),
                "title": r.get("test_name"),
                "filename": r.get("filename"),
                "line_number": r.get("line_number"),
            })

    # Semgrep
    semgrep = load_json(REPORT_DIR / "semgrep.json")
    if semgrep:
        for r in semgrep.get("results", []):
            extra = r.get("extra", {})
            severity = extra.get("severity")
            normalized["findings"].append({
                "source": "semgrep",
                "id": extra.get("rule_id"),
                "severity": severity,
                "title": extra.get("message"),
                "path": r.get("path"),
                "start": r.get("start"),
            })

    # Gitleaks
    gitleaks = load_json(REPORT_DIR / "gitleaks.json")
    if gitleaks and isinstance(gitleaks, list):
        for f in gitleaks:
            normalized["findings"].append({
                "source": "gitleaks",
                "id": f.get("RuleID"),
                "severity": "HIGH",  # secrets are always high value
                "title": f.get("Description"),
                "file": f.get("File"),
            })

    # ZAP
    zap = load_json(REPORT_DIR / "zap/zap-report.json")
    if zap:
        for site in zap.get("site", []):
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskcode", "0"))
                severity = {
                    "3": "HIGH",
                    "2": "MEDIUM",
                    "1": "LOW",
                    "0": "INFO"
                }.get(risk, "INFO")
                normalized["findings"].append({
                    "source": "zap",
                    "id": alert.get("alert"),
                    "severity": severity,
                    "title": alert.get("name"),
                    "url": alert.get("url"),
                })

    out_path = REPORT_DIR / "normalized.json"
    out_path.write_text(json.dumps(normalized, indent=2))
    print(f"Normalized report written to {out_path}")

if __name__ == "__main__":
    normalize()
