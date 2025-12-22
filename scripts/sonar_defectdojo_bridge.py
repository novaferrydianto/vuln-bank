#!/usr/bin/env python3
"""
sonar_defectdojo_bridge.py (final)

Purpose:
- Convert SonarQube Issues + Security Hotspots into DefectDojo "Generic Findings Import".
- Create a DefectDojo Test first (DefectDojo requires 'test' for import-scan, or requires
  target_start/target_end + environment as PK when creating tests, depending on instance).

Fixes applied:
- Ruff UP007: uses X | Y instead of Optional[X]
- DefectDojo 'environment' expects PK (int), not string.
- DefectDojo test create often requires target_start/target_end.
- Robust lookups for test_type id + environment id.
- Skips import if 0 findings.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from typing import Any


SEVERITY_MAP: dict[str, str] = {
    "BLOCKER": "Critical",
    "CRITICAL": "Critical",
    "MAJOR": "High",
    "MINOR": "Medium",
    "INFO": "Low",
}


def load_json(path: str) -> dict[str, Any]:
    if not os.path.isfile(path):
        print(f"[WARN] File not found: {path}", file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalize_component(component: str) -> str:
    # "projectKey:path/to/file.py" -> "path/to/file.py"
    if ":" in component:
        return component.split(":", 1)[1]
    return component


def map_issue(issue: dict[str, Any]) -> dict[str, Any]:
    raw = (issue.get("severity") or "INFO").upper()
    sev = SEVERITY_MAP.get(raw, "Low")

    comp = normalize_component(issue.get("component", ""))
    line = issue.get("line") or (issue.get("textRange") or {}).get("startLine")

    title = f"[Sonar Issue] {issue.get('rule')} in {comp}:{line or '?'}"
    desc = "\n".join(
        [
            issue.get("message", ""),
            f"Rule: {issue.get('rule')}",
            f"Component: {comp}",
            f"Line: {line or 'N/A'}",
            f"Severity: {raw}",
            f"Key: {issue.get('key')}",
        ]
    )

    return {
        "title": title,
        "description": desc,
        "severity": sev,
        "file_path": comp,
        "line": line,
        "static_finding": True,
        "unique_id_from_tool": issue.get("key"),
    }


def map_hotspot(hs: dict[str, Any]) -> dict[str, Any]:
    comp = normalize_component(hs.get("component", ""))
    line = hs.get("line")
    prob = (hs.get("vulnerabilityProbability") or "").upper()

    prob_map = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    sev = prob_map.get(prob, "Medium")

    title = f"[Sonar Hotspot] {hs.get('securityCategory')} in {comp}:{line or '?'}"
    desc = "\n".join(
        [
            hs.get("message", ""),
            "Type: SECURITY_HOTSPOT",
            f"Category: {hs.get('securityCategory')}",
            f"Vulnerability Probability: {prob}",
            f"Component: {comp}",
            f"Line: {line or 'N/A'}",
            f"Key: {hs.get('key')}",
        ]
    )

    return {
        "title": title,
        "description": desc,
        "severity": sev,
        "file_path": comp,
        "line": line,
        "static_finding": True,
        "unique_id_from_tool": hs.get("key"),
    }


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _dd_env() -> dict[str, str]:
    required = ["DEFECTDOJO_URL", "DEFECTDOJO_API_KEY", "DEFECTDOJO_PRODUCT_ID", "DEFECTDOJO_ENGAGEMENT_ID"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return {
        "dd": os.environ["DEFECTDOJO_URL"].rstrip("/"),
        "key": os.environ["DEFECTDOJO_API_KEY"],
        "prod": os.environ["DEFECTDOJO_PRODUCT_ID"],
        "eng": os.environ["DEFECTDOJO_ENGAGEMENT_ID"],
        "env_name": os.environ.get("DEFECTDOJO_ENVIRONMENT", "Development"),
    }


def _auth_headers(key: str) -> list[str]:
    return ["-H", f"Authorization: Token {key}"]


def resolve_test_type_id(dd: str, key: str, name: str = "Generic Findings Import") -> int | None:
    # /api/v2/test_types/?name=<...>
    q = name.replace(" ", "%20")
    url = f"{dd}/api/v2/test_types/?name={q}"
    out = _run(["curl", "-sS", "-X", "GET", url, *_auth_headers(key)])
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
        results = data.get("results") or []
        if results and results[0].get("id") is not None:
            return int(results[0]["id"])
    except Exception:
        return None
    return None


def resolve_environment_id(dd: str, key: str, name: str) -> int | None:
    """
    DefectDojo expects environment as PK (int), not string.
    Endpoint: /api/v2/environments/?name=<...>
    If not found, we fallback to None and later fallback to "Development" default ID if possible.
    """
    q = name.replace(" ", "%20")
    url = f"{dd}/api/v2/environments/?name={q}"
    out = _run(["curl", "-sS", "-X", "GET", url, *_auth_headers(key)])
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
        results = data.get("results") or []
        if results and results[0].get("id") is not None:
            return int(results[0]["id"])
    except Exception:
        return None
    return None


def _iso_date(d: dt.date) -> str:
    return d.strftime("%Y-%m-%d")


def create_test(title: str) -> int:
    env = _dd_env()
    dd, key, prod, eng, env_name = env["dd"], env["key"], env["prod"], env["eng"], env["env_name"]

    test_type_id = resolve_test_type_id(dd, key) or 17  # fallback
    env_id = resolve_environment_id(dd, key, env_name) or resolve_environment_id(dd, key, "Development")

    # Some Dojo deployments require target_start/target_end; provide safe defaults (today).
    today = dt.date.today()
    payload: dict[str, Any] = {
        "title": title,
        "engagement": int(eng),
        "test_type": int(test_type_id),
        "product": int(prod),
        "target_start": _iso_date(today),
        "target_end": _iso_date(today),
    }

    # Environment: prefer PK if resolved, else omit it (some instances have default)
    if env_id is not None:
        payload["environment"] = int(env_id)

    out = _run(
        [
            "curl",
            "-sS",
            "-X",
            "POST",
            f"{dd}/api/v2/tests/",
            *_auth_headers(key),
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(payload),
        ]
    )

    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        raise RuntimeError("Failed to create DefectDojo Test (curl non-zero)")

    try:
        resp = json.loads(out.stdout)
    except json.JSONDecodeError:
        print(out.stdout, file=sys.stderr)
        raise RuntimeError("DefectDojo Test create returned non-JSON response")

    test_id = resp.get("id")
    if not test_id:
        # Print body for debugging
        print(out.stdout, file=sys.stderr)
        raise RuntimeError("DefectDojo Test did not return ID")

    print(f"[INFO] Created DefectDojo Test ID={test_id}")
    return int(test_id)


def upload_findings(json_path: str, test_id: int) -> None:
    env = _dd_env()
    dd, key, prod, eng = env["dd"], env["key"], env["prod"], env["eng"]

    if not os.path.isfile(json_path):
        raise RuntimeError(f"Generic findings file not found: {json_path}")

    out = _run(
        [
            "curl",
            "-sS",
            "-X",
            "POST",
            f"{dd}/api/v2/import-scan/",
            *_auth_headers(key),
            "-F",
            "scan_type=Generic Findings Import",
            "-F",
            f"test={test_id}",
            "-F",
            f"product={prod}",
            "-F",
            f"engagement={eng}",
            "-F",
            "active=true",
            "-F",
            "verified=true",
            "-F",
            f"file=@{json_path}",
        ]
    )

    # curl may return 0 but Dojo returns JSON error; detect it
    body = out.stdout.strip()
    if out.returncode != 0:
        print(body, file=sys.stderr)
        print(out.stderr, file=sys.stderr)
        raise RuntimeError("DefectDojo import failed (curl non-zero)")

    if body.startswith("{"):
        try:
            resp = json.loads(body)
            # Common Dojo error shapes:
            # {"detail":"..."} or {"message":"...","...":...}
            if isinstance(resp, dict) and (
                (isinstance(resp.get("detail"), str) and resp.get("detail"))
                or (isinstance(resp.get("message"), str) and resp.get("message"))
            ):
                raise RuntimeError(f"DefectDojo import error: {resp}")
        except json.JSONDecodeError:
            pass

    print("[INFO] DefectDojo import OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issues", required=True)
    parser.add_argument("--hotspots", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    issues = (load_json(args.issues).get("issues", []) or []) if args.issues else []
    hotspots = (load_json(args.hotspots).get("hotspots", []) or []) if args.hotspots else []

    findings: list[dict[str, Any]] = []
    for i in issues:
        findings.append(map_issue(i))
    for h in hotspots:
        findings.append(map_hotspot(h))

    if not findings:
        print("[INFO] No Sonar issues/hotspots found. Skipping DefectDojo test/import.")
        return

    report_dir = os.environ.get("REPORT_DIR", ".")
    os.makedirs(report_dir, exist_ok=True)
    out_path = args.out or os.path.join(report_dir, "sonar-defectdojo-generic.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f, indent=2)

    print(f"[INFO] Generic findings written: {out_path}")
    print(f"[INFO] Total findings: {len(findings)}")

    sha = os.environ.get("GITHUB_SHA", "")[:7] or "manual"
    title = f"SonarQube Bridge Import - {sha} ({os.environ.get('DEFECTDOJO_ENVIRONMENT','')})"
    test_id = create_test(title=title)
    upload_findings(out_path, test_id)


if __name__ == "__main__":
    main()