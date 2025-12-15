import json
from pathlib import Path

hist = Path("security-reports/epss-history.jsonl")
baseline_file = Path("security-baselines/asvs-baseline.json")
out = Path("docs/data/trends/risk-trend.json")

baseline_score = 0
if baseline_file.exists():
    baseline = json.loads(baseline_file.read_text())
    baseline_score = baseline.get("overall_score", 0)

points = []

for line in hist.read_text().splitlines():
    row = json.loads(line)
    score = round(row.get("max_epss", 0.0) * 100, 2)

    points.append({
        "timestamp": row["timestamp"],
        "risk_score": score,
        "delta_vs_baseline": round(score - baseline_score, 2),
    })

out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(points, indent=2))
