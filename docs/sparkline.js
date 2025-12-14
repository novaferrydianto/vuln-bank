/* ====================================================
   Executive Sparkline – Weekly PASS% Trend
   ==================================================== */

const BASE = location.pathname.includes("/dashboards/")
  ? "../../"
  : "./";

const TREND_PATH = `${BASE}security-metrics/weekly/pass-trend.json`;

/* ----------------------------------------------------
   Utils
---------------------------------------------------- */
function clamp(v, min = 0, max = 100) {
  return Math.max(min, Math.min(max, v));
}

function pct(v) {
  return `${Math.round(v)}%`;
}

/* ----------------------------------------------------
   Load trend data
---------------------------------------------------- */
async function loadTrend() {
  const res = await fetch(TREND_PATH, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to load ${TREND_PATH}`);
  return res.json();
}

/* ----------------------------------------------------
   Render sparkline
---------------------------------------------------- */
function renderSparkline(svg, values) {
  if (!svg || values.length === 0) return;

  const width = 300;
  const height = 60;
  const padding = 6;

  const min = Math.min(...values, 0);
  const max = Math.max(...values, 100);

  const scaleX = (i) =>
    padding + (i / (values.length - 1 || 1)) * (width - padding * 2);

  const scaleY = (v) =>
    height - padding - ((v - min) / (max - min || 1)) * (height - padding * 2);

  // Line path
  const path = values
    .map((v, i) => `${i === 0 ? "M" : "L"} ${scaleX(i)} ${scaleY(v)}`)
    .join(" ");

  // Clear
  svg.innerHTML = "";

  // Polyline
  const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
  line.setAttribute("d", path);
  line.setAttribute("fill", "none");
  line.setAttribute("stroke-width", "2.5");
  line.setAttribute("stroke-linecap", "round");

  // Color by delta
  const delta = values.at(-1) - values.at(-2 || 0);
  if (delta > 0) {
    line.setAttribute("stroke", "var(--color-pass)");
  } else if (delta < 0) {
    line.setAttribute("stroke", "var(--color-fail)");
  } else {
    line.setAttribute("stroke", "#8c959f");
  }

  svg.appendChild(line);

  // Last point dot
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("cx", scaleX(values.length - 1));
  dot.setAttribute("cy", scaleY(values.at(-1)));
  dot.setAttribute("r", "3.5");
  dot.setAttribute("fill", line.getAttribute("stroke"));
  svg.appendChild(dot);
}

/* ----------------------------------------------------
   Delta badge (+4%)
---------------------------------------------------- */
function renderDeltaBadge(container, current, previous) {
  if (!container || previous == null) return;

  const delta = current - previous;
  const badge = document.createElement("span");

  badge.className = "meta-badge";
  badge.style.marginLeft = "0.6rem";

  if (delta > 0) {
    badge.style.background = "var(--color-pass-bg)";
    badge.style.color = "var(--color-pass)";
    badge.textContent = `▲ +${pct(delta)}`;
  } else if (delta < 0) {
    badge.style.background = "var(--color-fail-bg)";
    badge.style.color = "var(--color-fail)";
    badge.textContent = `▼ ${pct(delta)}`;
  } else {
    badge.textContent = "– 0%";
  }

  container.appendChild(badge);
}

/* ----------------------------------------------------
   Bootstrap
---------------------------------------------------- */
(async function init() {
  try {
    const trend = await loadTrend();

    const points = (trend.points || [])
      .slice(-12) // last 12 weeks
      .map(p => clamp(p.pass_percent));

    if (points.length === 0) return;

    const svg = document.getElementById("sparkline");
    renderSparkline(svg, points);

    // Delta badge
    const sectionTitle = document
      .querySelector("section.card h2");

    if (points.length >= 2) {
      renderDeltaBadge(
        sectionTitle,
        points.at(-1),
        points.at(-2)
      );
    }

  } catch (err) {
    console.warn("Sparkline unavailable:", err);
  }
})();
