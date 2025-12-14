async function loadJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error("Failed to load " + path);
  return res.json();
}

function setDonut(circle, percent) {
  const radius = 90;
  const circumference = 2 * Math.PI * radius;
  const value = Math.max(0, Math.min(percent, 100));

  const offset = circumference * (1 - value / 100);
  circle.style.strokeDasharray = `${circumference}`;
  circle.style.strokeDashoffset = offset;
}

(async () => {
  const asvs = await loadJSON("../../data/governance/asvs-coverage.json");
  const scorecard = await loadJSON("../../data/security-scorecard.json");

  // ===============================
  // KPI SUMMARY
  // ===============================
  document.getElementById("maturity-score").textContent =
    scorecard.score.overall;

  document.getElementById("coverage-percent").textContent =
    asvs.summary.coverage_percent + "%";

  document.getElementById("control-count").textContent =
    asvs.summary.total;

  // ===============================
  // STATUS COUNTS
  // ===============================
  const controls = asvs.controls || [];

  const pass = controls.filter(c => c.status === "PASS").length;
  const fail = controls.filter(c => c.status === "FAIL").length;
  const na   = controls.filter(c => c.status === "NOT_APPLICABLE").length;
  const total = pass + fail + na || 1;

  document.getElementById("pass-count").textContent = pass;
  document.getElementById("fail-count").textContent = fail;
  document.getElementById("na-count").textContent = na;

  // ===============================
  // DONUT CHART (PASS vs FAIL)
  // ===============================
  const passPct = Math.round((pass / total) * 100);
  const failPct = Math.round((fail / total) * 100);

  document.getElementById("donut-percent").textContent = `${passPct}%`;

  const donutPass = document.getElementById("donut-pass");
  const donutFail = document.getElementById("donut-fail");

  setDonut(donutPass, passPct);
  setDonut(donutFail, failPct);

  // ===============================
  // CONTROLS TABLE (Risk-First)
  // ===============================
  const tbody = document.getElementById("controls-table");

  const priority = { "FAIL": 0, "PASS": 1, "NOT_APPLICABLE": 2 };
  controls
    .sort((a, b) =>
      (priority[a.status] ?? 9) - (priority[b.status] ?? 9) ||
      a.id.localeCompare(b.id)
    )
    .forEach(c => {
      const tr = document.createElement("tr");
      tr.className = c.status.toLowerCase();

      tr.innerHTML = `
        <td>${c.id}</td>
        <td>L${c.level}</td>
        <td>${c.status}</td>
        <td>${(c.evidence || []).join(", ")}</td>
      `;
      tbody.appendChild(tr);
    });
})();
