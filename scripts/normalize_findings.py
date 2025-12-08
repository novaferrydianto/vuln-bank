output = {
    "meta": {
        "schema_version": "1.0",
        "app": "vuln-bank",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "commit": os.environ.get("GITHUB_SHA"),
        "branch": os.environ.get("GITHUB_REF_NAME")
    },
    "summary": {
        "total": len(findings),
        "critical": sum(f.severity == "CRITICAL" for f in findings),
        "high": sum(f.severity == "HIGH" for f in findings),
        "exploitable": sum(
            f.epss and f.epss >= 0.5 and not f.baseline
            for f in findings
        ),
        "asvs_failed": any(
            f.asvs and f.severity in ("HIGH", "CRITICAL")
            for f in findings
        )
    },
    "findings": [asdict(f) for f in findings_sorted]
}

with open("security-reports/normalized.json", "w") as f:
    json.dump(output, f, indent=2)
