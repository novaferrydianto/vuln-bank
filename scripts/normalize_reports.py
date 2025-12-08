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

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ============================
# Config
# ============================

REPORT_DIR = Path("security-reports")

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

# ============================
# Helpers
# ============================

def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def canon_severity(value: Optional[str]) -> str:
    if not value:
        return "INFO"
    return SEVERITY_MAP.get(str(value).upper(), "INFO")


def make_fingerprint(*parts: Any) -> str:
    raw = "|".join(str(p) for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def now_utc() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ============================
# Finding registry
# ============================

class FindingRegistry:
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def add(self, finding: Dict[str, Any]) -> None:
        fp = finding["fingerprint"]
        self._store[fp] = finding  # auto-dedup by fingerprint

    def all(self) -> List[Dict[str, Any]]:
        return list(self._store.values())


def build_finding(**data: Any) -> Dict[str, Any]:
    data["severity"] = canon_severity(data.get("severity"))
    data["fingerprint"] = make_fingerprint(
        data.get("source"),
        data.get("id"),
        data.get("path"),
        data.get("pkg"),
        data.get("url"),
    )

    # Defaults (gate-safe)
    data.setdefault("epss", None)
    data.setdefault("asvs", None)
    data.setdefault("baseline", False)
    data.setdefault("confidence", None)

    return data


# ============================
# Normalizers (per scanner)
# ============================

def normalize_trivy_image(reg: FindingRegistry) -> None:
    data = load_json(REPORT_DIR / "trivy-image.json")
    if not data:
        return

    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            reg.add(build_finding(
                source="trivy-image",
                category="SCA",
                id=v.get("VulnerabilityID"),
                cve=v.get("VulnerabilityID"),
                severity=v.get("Severity"),
                title=v.get("Title"),
                pkg=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
            ))


def normalize_bandit(reg: FindingRegistry) -> None:
    data = load_json(REPORT_DIR / "bandit.json")
    if not data:
        return

    for r in data.get("results", []):
        reg.add(build_finding(
            source="bandit",
            category="SAST",
            id=r.get("test_id"),
            severity=r.get("issue_severity"),
            title=r.get("test_name"),
            path=r.get("filename"),
            line=r.get("line_number"),
            cwe=r.get("issue_cwe", {}).get("id"),
        ))


def normalize_semgrep(reg: FindingRegistry) -> None:
    data = load_json(REPORT_DIR / "semgrep.json")
    if not data:
        return

    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})

        reg.add(build_finding(
            source="semgrep",
            category="SAST",
            id=extra.get("rule_id"),
            severity=extra.get("severity"),
            title=extra.get("message"),
            description=meta.get("description"),
            path=r.get("path"),
            line=r.get("start", {}).get("line"),
            cwe=meta.get("cwe"),
            asvs=meta.get("asvs"),
            confidence=meta.get("confidence"),
        ))


def normalize_gitleaks(reg: FindingRegistry) -> None:
    data = load_json(REPORT_DIR / "gitleaks.json")
    if not isinstance(data, list):
        return

    for f in data:
        reg.add(build_finding(
            source="gitleaks",
            category="SECRET",
            id=f.get("RuleID"),
            severity="HIGH",
            title=f.get("Description"),
            path=f.get("File"),
        ))


def normalize_zap(reg: FindingRegistry) -> None:
    data = load_json(REPORT_DIR / "zap/zap-report.json")
    if not data:
        return

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            sev = {
                "3": "HIGH",
                "2": "MEDIUM",
                "1": "LOW",
            }.get(str(alert.get("riskcode")), "INFO")

            reg.add(build_finding(
                source="zap",
                category="DAST",
                id=alert.get("alert"),
                severity=sev,
                title=alert.get("name"),
                url=alert.get("url"),
                cwe=alert.get("cweid"),
            ))


def normalize_llm_sast(reg: FindingRegistry) -> None:
    """
    Optional — non-blocking unless wired into summary gate
    """
    data = load_json(REPORT_DIR / "llm-sast.json")
    if not isinstance(data, list):
        return

    for f in data:
        reg.add(build_finding(
            source="llm-sast",
            category=f.get("category", "LOGIC"),
            id=f.get("title"),
            severity=f.get("severity"),
            title=f.get("title"),
            description=f.get("description"),
            path=f.get("file"),
            line=f.get("line"),
            cwe=f.get("cwe"),
            asvs=f.get("asvs"),
            confidence=f.get("confidence"),
            remediation=f.get("remediation"),
            raw=f,
        ))


# ============================
# Main normalize orchestration
# ============================

def normalize() -> None:
    registry = FindingRegistry()

    normalize_trivy_image(registry)
    normalize_bandit(registry)
    normalize_semgrep(registry)
    normalize_gitleaks(registry)
    normalize_zap(registry)
    normalize_llm_sast(registry)  # ✅ future-ready

    findings = registry.all()

    report: Dict[str, Any] = {
        "meta": {
            "schema_version": "1.0",
            "app": os.getenv("APP_NAME", "vuln-bank"),
            "image": f'{os.getenv("IMAGE_REPO","")}:{os.getenv("GITHUB_SHA","")}',
            "commit": os.getenv("GITHUB_SHA"),
            "branch": os.getenv("GITHUB_REF_NAME"),
            "generated_at": now_utc(),
        },
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": sum(f["severity"] == "CRITICAL" for f in findings),
            "high": sum(f["severity"] == "HIGH" for f in findings),
            "asvs_failed": any(
                f.get("asvs") and f["severity"] in ("HIGH", "CRITICAL")
                for f in findings
            ),
            "exploitable": False,  # set later by EPSS step
        }
    }

    out = REPORT_DIR / "normalized.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"✅ Normalized report written to {out}")


if __name__ == "__main__":
    normalize()
