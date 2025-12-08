#!/usr/bin/env python3
"""
normalize_reports.py
--------------------
Normalize all scanner outputs into ONE canonical schema.

Used by:
- Security gate (ASVS + EPSS)
- GitHub Actions pipeline
- Reporting / dashboards
"""

import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

REPORT_DIR = Path("security-reports")

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

# ----------------------------
# Helpers
# ----------------------------

def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with path.open() as f:
            return json.load(f)
    except Exception:
        return None


def canon_severity(value: Optional[str]) -> str:
    if not value:
        return "INFO"
    return SEVERITY_MAP.get(str(value).upper(), "INFO")


def fingerprint(*parts: Any) -> str:
    raw = "|".join(str(p) for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ----------------------------
# Core normalize logic
# ----------------------------

def normalize() -> None:
    normalized: Dict[str, Any] = {
        "meta": {
            "schema_version": "1.0",
            "app": os.getenv("APP_NAME", "vuln-bank"),
            "image": f'{os.getenv("IMAGE_REPO","")}:{os.getenv("GITHUB_SHA","")}',
            "commit": os.getenv("GITHUB_SHA"),
            "branch": os.getenv("GITHUB_REF_NAME"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "findings": [],
        "summary": {},
    }

    findings: List[Dict[str, Any]] = []

    def add_finding(**f: Any) -> None:
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
        f.setdefault("baseline", False)
        f.setdefault("confidence", None)
        findings.append(f)

    # ----------------------------
    # Trivy – image
    # ----------------------------
    trivy_image = load_json(REPORT_DIR / "trivy-image.json")
    if trivy_image:
        for r in trivy_image.get("Results", []):
            for v in r.get("Vulnerabilities", []) or []:
                add_finding(
                    source="trivy-image",
                    category="SCA",
                    id=v.get("VulnerabilityID"),
                    cve=v.get("VulnerabilityID"),
                    severity=v.get("Severity"),
                    title=v.get("Title"),
                    pkg=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                )

    # ----------------------------
    # Bandit
    # ----------------------------
    bandit = load_json(REPORT_DIR / "bandit.json")
    if bandit:
        for r in bandit.get("results", []):
            add_finding(
                source="bandit",
                category="SAST",
                id=r.get("test_id"),
                severity=r.get("issue_severity"),
                title=r.get("test_name"),
                path=r.get("filename"),
                line=r.get("line_number"),
                cwe=r.get("issue_cwe", {}).get("id"),
            )

    # ----------------------------
    # Semgrep
    # ----------------------------
    semgrep = load_json(REPORT_DIR / "semgrep.json")
    if semgrep:
        for r in semgrep.get("results", []):
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            add_finding(
                source="semgrep",
                category="SAST",
                id=extra.get("rule_id"),
                severity=extra.get("severity"),
                title=extra.get("message"),
                description=metadata.get("description"),
                path=r.get("path"),
                line=r.get("start", {}).get("line"),
                cwe=metadata.get("cwe"),
                asvs=metadata.get("asvs"),
                confidence=metadata.get("confidence"),
            )

    # ----------------------------
    # Gitleaks
    # ----------------------------
    gitleaks = load_json(REPORT_DIR / "gitleaks.json")
    if isinstance(gitleaks, list):
        for f in gitleaks:
            add_finding(
                source="gitleaks",
                category="SECRET",
                id=f.get("RuleID"),
                severity="HIGH",
                title=f.get("Description"),
                path=f.get("File"),
            )

    # ----------------------------
    # OWASP ZAP
    # ----------------------------
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
                    category="DAST",
                    id=alert.get("alert"),
                    severity=severity,
                    title=alert.get("name"),
                    url=alert.get("url"),
                    cwe=alert.get("cweid"),
                )

    # ----------------------------
    # Deduplicate by fingerprint
    # ----------------------------
    deduped = {}
    for f in findings:
        deduped[f["fingerprint"]] = f
    normalized["findings"] = list(deduped.values())

    # ----------------------------
    # SUMMARY (STEP-READY)
    # ----------------------------
    normalized["summary"] = {
        "total": len(normalized["findings"]),
        "critical": sum(f["severity"] == "CRITICAL" for f in normalized["findings"]),
        "high": sum(f["severity"] == "HIGH" for f in normalized["findings"]),
        "asvs_failed": any(
            f.get("asvs") and f["severity"] in ("HIGH", "CRITICAL")
            for f in normalized["findings"]
        ),
        "exploitable": False,  # activated in EPSS step
    }

    out = REPORT_DIR / "normalized.json"
    out.write_text(json.dumps(normalized, indent=2))
    print(f"✅ Normalized report written to {out}")


# ----------------------------
# Entrypoint
# ----------------------------
if __name__ == "__main__":
    normalize()
