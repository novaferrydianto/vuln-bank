/* ====================================================
   Utilities
   ==================================================== */

async function loadJSON(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to load ${path} (${res.status})`);
  }
  return res.json();
}

function byId(id) {
  return document.getElementById(id);
}

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(value, max));
}

/* ====================================================
   Donut Chart
   ==================================================== */

function renderDonut(circle, percent) {
  const radius = 90;
  const circumference = 2 * Math.PI * radius;
  const value = clamp(percent);

  const offset = circumference * (1 - value / 100);
  circle.style.strokeDasharray = `${circumference}`;
  circle.style.strokeDashoffset = offset;
}

/* ====================================================
   KPI Rendering
   ==================================================== */

function renderKpis(scorecard, asvs) {
  byId("maturity-score").textContent =
    scorecard?.score?.overall ?? "–";

  byId("coverage-percent").textContent =
    asvs?.summary?.coverage_percent != null
      ? `${asvs.summary.coverage_percent}%`
      : "–";

  byId("control-count").textContent =
    asvs?.summary?.total ?? "–";
}

/* ====================================================
   Status Breakdown + Donut
   ==================================================== */

function renderStatus(asvs) {
  const controls = Array.isArray(asvs?.controls) ? asvs.controls : [];

  const counts = {
    PASS: 0,
    FAIL: 0,
    NOT_APPLICABLE: 0
  };

  controls.forEach(c => {
    if (counts[c.status] !== undefined) {
      counts[c.status]++;
    }
  });

  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

  byId("pass-count").textContent = counts.PASS;
  byId("fail-count").textContent = counts.FAIL;
  byId("na-count").textContent   = counts.NOT_APPLICABLE;

  const passPct = Math.round((counts.PASS / total) * 100);
  const failPct = Math.round((counts.FAIL / total) * 100);

  byId("donut-percent").textContent = `${passPct}%`;

  renderDonut(byId("donut-pass"), passPct);
  renderDonut(byId("donut-fail"), failPct);

  return controls;
}

/* ====================================================
   Controls Table (Risk-First)
   ==================================================== */

function renderControlsTable(controls) {
  const tbody = byId("controls-table");
  if (!tbody) return;

  const priority = {
    FAIL: 0,
    PASS: 1,
    NOT_APPLICABLE: 2
  };

  controls
    .slice() // avoid mutating original
    .sort((a, b) =>
      (priority[a.status] ?? 9) - (priority[b.status] ?? 9) ||
      String(a.id).localeCompare(String(b.id))
    )
    .forEach(control => {
      const tr = document.createElement("tr");
      tr.className = control.status?.toLowerCase() || "";

      tr.innerHTML = `
        <td>${control.id ?? "–"}</td>
        <td>${control.level != null ? `L${control.level}` : "–"}</td>
        <td>${control.status ?? "–"}</td>
        <td>${Array.isArray(control.evidence)
          ? control.evidence.join(", ")
          : ""}</td>
      `;

      tbody.appendChild(tr);
    });
}

/* ====================================================
   Main Bootstrap
   ==================================================== */

(async function bootstrap() {
  try {
    const [asvs, scorecard] = await Promise.all([
      loadJSON("../../data/governance/asvs-coverage.json"),
      loadJSON("../../data/security-scorecard.json")
    ]);

    renderKpis(scorecard, asvs);

    const controls = renderStatus(asvs);

    renderControlsTable(controls);

  } catch (err) {
    console.error("Dashboard initialization failed:", err);

    const body = document.body;
    const error = document.createElement("div");
    error.style.padding = "2rem";
    error.style.color = "#b42318";
    error.textContent =
      "Failed to load security dashboard data. Check CI artifacts or schema compatibility.";

    body.prepend(error);
  }
})();
