/* ====================================================
   Executive Sparkline – Weekly PASS% Trend (Pages-safe)
   ==================================================== */

const BASE = location.pathname.includes("/vuln-bank/")
  ? "/vuln-bank/"
  : "/";

const TREND_PATH = `${BASE}docs/data/trends/asvs-pass-trend.json`;

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
  if (!svg || values.length < 2) return;

  const width = 300;
  const height = 60;
  const padding = 6;

  const min = Math.min(...values);
  const max = Math.max(...values);

  const scaleX = (i) =>
    padding + (i / (values.length - 1)) * (width - padding * 2);

  const scaleY = (v) =>
    height - padding - ((v - min) / (max - min || 1)) * (height - padding * 2);

  const path = values
    .map((v, i) => `${i === 0 ? "M" : "L"} ${scaleX(i)} ${scaleY(v)}`)
    .join(" ");

  svg.innerHTML = "";

  const delta = values[values.length - 1] - values[values.length - 2];

  const stroke =
    delta > 0 ? "var(--color-pass)" :
    delta < 0 ? "var(--color-fail)" :
    "#8c959f";

  const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
  line.setAttribute("d", path);
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", stroke);
  line.setAttribute("stroke-width", "2.5");
  line.setAttribute("stroke-linecap", "round");
  svg.appendChild(line);

  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("cx", scaleX(values.length - 1));
  dot.setAttribute("cy", scaleY(values.at(-1)));
  dot.setAttribute("r", "3.5");
  dot.setAttribute("fill", stroke);
  svg.appendChild(dot);

  return delta;
}

/* ----------------------------------------------------
   Delta badge (+4%)
---------------------------------------------------- */
function renderDeltaBadge(container, delta) {
  if (!container || delta == null) return;

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

    const points = trend
      .slice(-12)
      .map(p => clamp(p.pass_pct));

    if (points.length < 2) return;

    const svg = document.getElementById("sparkline");
    const delta = renderSparkline(svg, points);

    const title = document.querySelector("section.card h2");
    renderDeltaBadge(title, delta);

  } catch (err) {
    console.warn("Sparkline unavailable:", err);
  }
})();
