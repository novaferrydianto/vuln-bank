#!/usr/bin/env python3
"""
sonar_defectdojo_bridge.py (v4.7)

Fixes:
- DefectDojo 400 "Attribute 'test' is required" by creating a Test first
- DefectDojo expects environment as pk (int), not string -> resolves environment ID
- Ruff UP015 compliance (no explicit "r" open mode)
- Ruff UP007 compliance (use `X | Y` instead of Optional[X])
- More robust: resolves test_type ID dynamically (falls back if lookup fails)
- Skips creating empty tests/imports when there are 0 findings
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

# Severity mapping (DefectDojo expected values vary; these are commonly accepted)
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
    # Ruff UP015: omit "r"
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
    return subprocess.run(cmd, capture_output=True, text=True)


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
    }


def _curl_json(url: str, token: str) -> dict[str, Any]:
    cmd = ["curl", "-sS", "-X", "GET", url, "-H", f"Authorization: Token {token}"]
    out = _run(cmd)
    if out.returncode != 0:
        return {}
    try:
        return json.loads(out.stdout) if out.stdout.strip() else {}
    except Exception:
        return {}


def resolve_test_type_id(dd: str, key: str, name: str = "Generic Findings Import") -> int | None:
    """
    DefectDojo stores test types; IDs may differ per instance.
    We try to fetch test_type by name.
    Endpoint: /api/v2/test_types/?name=<...>
    """
    q = name.replace(" ", "%20")
    data = _curl_json(f"{dd}/api/v2/test_types/?name={q}", key)
    results = data.get("results") or []
    if results:
        tid = results[0].get("id")
        try:
            return int(tid) if tid is not None else None
        except Exception:
            return None
    return None


def resolve_environment_id(dd: str, key: str, name: str = "Development") -> int | None:
    """
    DefectDojo expects environment as pk (int), not string.

    Different Dojo versions expose different endpoints. We try a few common patterns:
    - /api/v2/environments/?name=<name>
    - /api/v2/development_environments/ (older / custom builds)
    If all fail, return None and caller may fall back (or hard fail).
    """
    q = name.replace(" ", "%20")

    # Most common (modern) endpoint
    data = _curl_json(f"{dd}/api/v2/environments/?name={q}", key)
    results = data.get("results") or []
    if results:
        eid = results[0].get("id")
        try:
            return int(eid) if eid is not None else None
        except Exception:
            return None

    # Fallback probes (best-effort)
    for endpoint in ("development_environments", "staging_environments", "production_environments"):
        data2 = _curl_json(f"{dd}/api/v2/{endpoint}/?name={q}", key)
        results2 = data2.get("results") or []
        if results2:
            eid = results2[0].get("id")
            try:
                return int(eid) if eid is not None else None
            except Exception:
                return None

    return None


def create_test(title: str, environment_name: str = "Development") -> int:
    env = _dd_env()
    dd, key, prod, eng = env["dd"], env["key"], env["prod"], env["eng"]

    test_type_id = resolve_test_type_id(dd, key)  # try dynamic
    if test_type_id is None:
        # Fallback to a common default; better than failing hard, but log it.
        test_type_id = 17
        print("[WARN] Could not resolve test_type ID dynamically; falling back to 17.", file=sys.stderr)

    environment_id = resolve_environment_id(dd, key, environment_name)
    if environment_id is None:
        # If your Dojo has envs disabled/unavailable, this may still fail.
        # You can hardcode an ID here once you confirm it from your Dojo.
        print(
            f"[WARN] Could not resolve environment ID for '{environment_name}'. "
            "DefectDojo may reject test creation without a valid environment pk.",
            file=sys.stderr,
        )

    payload: dict[str, Any] = {
        "title": title,
        "engagement": int(eng),
        # IMPORTANT: environment is pk (int). If None, we omit it and let Dojo validate.
        "test_type": int(test_type_id),
        "product": int(prod),
    }
    if environment_id is not None:
        payload["environment"] = int(environment_id)

    cmd = [
        "curl",
        "-sS",
        "-X",
        "POST",
        f"{dd}/api/v2/tests/",
        "-H",
        f"Authorization: Token {key}",
        "-H",
        "Content-Type: application/json",
        "-d",
        json.dumps(payload),
    ]

    out = _run(cmd)
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        raise RuntimeError("Failed to create DefectDojo Test")

    try:
        resp = json.loads(out.stdout)
    except json.JSONDecodeError:
        print(out.stdout, file=sys.stderr)
        raise RuntimeError("DefectDojo Test create returned non-JSON response")

    test_id = resp.get("id")
    if not test_id:
        print(out.stdout, file=sys.stderr)
        raise RuntimeError("DefectDojo Test did not return ID")

    print(f"[INFO] Created DefectDojo Test ID={test_id}")
    return int(test_id)


def upload_findings(json_path: str, test_id: int) -> None:
    env = _dd_env()
    dd, key, prod, eng = env["dd"], env["key"], env["prod"], env["eng"]

    cmd = [
        "curl",
        "-sS",
        "-X",
        "POST",
        f"{dd}/api/v2/import-scan/",
        "-H",
        f"Authorization: Token {key}",
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

    out = _run(cmd)
    if out.returncode != 0:
        print("[ERROR] DefectDojo import failed", file=sys.stderr)
        print(out.stdout, file=sys.stderr)
        print(out.stderr, file=sys.stderr)
        raise RuntimeError("DefectDojo import failed")

    # DefectDojo may still return JSON with error while curl exitcode=0; guard that too
    if out.stdout.strip().startswith("{"):
        try:
            resp = json.loads(out.stdout)
            # Common error shapes
            if "detail" in resp and isinstance(resp["detail"], str) and resp["detail"]:
                raise RuntimeError(f"DefectDojo import error: {resp['detail']}")
            if "message" in resp and isinstance(resp["message"], str) and resp["message"]:
                # If Dojo returns validation message, surface it.
                # Note: some responses contain "pro" upsell text; ignore that unless paired with errors.
                if "target_start" in resp or "target_end" in resp or "environment" in resp:
                    raise RuntimeError(f"DefectDojo import validation error: {resp['message']}")
        except json.JSONDecodeError:
            pass

    print("[INFO] DefectDojo import OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issues", required=True)
    parser.add_argument("--hotspots", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--environment", default=os.environ.get("DD_ENVIRONMENT", "Development"))
    args = parser.parse_args()

    issues = load_json(args.issues).get("issues", []) or []
    hotspots = load_json(args.hotspots).get("hotspots", []) or []

    findings: list[dict[str, Any]] = []
    findings.extend(map_issue(i) for i in issues)
    findings.extend(map_hotspot(h) for h in hotspots)

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

    sha7 = (os.environ.get("GITHUB_SHA") or "manual")[:7]
    title = f"SonarQube Bridge Import - {sha7}"
    test_id = create_test(title=title, environment_name=args.environment)
    upload_findings(out_path, test_id)


if __name__ == "__main__":
    main()
