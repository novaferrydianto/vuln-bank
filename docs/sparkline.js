/* ====================================================
   Executive PASS% Sparkline
   ==================================================== */

async function loadTrend() {
  const res = await fetch("./data/trends/asvs-pass-trend.json", { cache: "no-store" });
  if (!res.ok) throw new Error("Trend data not available");
  return res.json();
}

function renderSparkline(svg, values) {
  const width = 300;
  const height = 60;
  const padding = 6;

  const min = Math.min(...values, 0);
  const max = Math.max(...values, 100);
  const range = max - min || 1;

  const points = values.map((v, i) => {
    const x = padding + (i / (values.length - 1)) * (width - padding * 2);
    const y = height - padding - ((v - min) / range) * (height - padding * 2);
    return `${x},${y}`;
  });

  const delta = values.at(-1) - values.at(-2);
  const color = delta >= 0 ? "#067647" : "#b42318";

  svg.innerHTML = `
    <polyline
      fill="none"
      stroke="${color}"
      stroke-width="2"
      points="${points.join(" ")}"
    />
  `;

  return delta;
}

function renderDeltaBadge(delta) {
  const badge = document.createElement("span");
  badge.className = "meta-badge";
  badge.style.marginLeft = "0.6rem";

  if (delta >= 0) {
    badge.style.background = "#e6fffa";
    badge.style.color = "#067647";
    badge.textContent = `▲ +${delta.toFixed(1)}%`;
  } else {
    badge.style.background = "#ffeaea";
    badge.style.color = "#b42318";
    badge.textContent = `▼ ${delta.toFixed(1)}%`;
  }

  document.querySelector("h2")?.appendChild(badge);
}

(async function initSparkline() {
  try {
    const trend = await loadTrend();
    const rows = trend.data.slice(-12); // last 12 weeks
    if (rows.length < 2) return;

    const values = rows.map(r => r.pass_percent);
    const svg = document.getElementById("sparkline");

    const delta = renderSparkline(svg, values);
    renderDeltaBadge(delta);

  } catch (err) {
    console.warn("Sparkline unavailable:", err.message);
  }
})();
