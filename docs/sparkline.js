/* ====================================================
   Executive Sparklines – PASS% & KEV (Pages-safe)
   ==================================================== */

const PASS_PATH = "./data/trends/pass-trend.json";
const KEV_PATH  = "./data/trends/kev-trend.json";

const KEV_THRESHOLD = 3; // risk appetite (policy-level)

const DEFECTDOJO_BASE =
  "https://defectdojo.vulnbank.local/finding";

/* ---------------- Utils ---------------- */
const clamp = (v, min = 0, max = 100) =>
  Math.max(min, Math.min(max, v));

async function loadJSON(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to load ${path}`);
  return res.json();
}

/* --------------- Renderer --------------- */
function renderSparkline(svg, values, threshold = null, invert = false) {
  if (!svg || values.length < 2) return;

  const w = 300, h = 60, p = 6;
  const min = Math.min(...values);
  const max = Math.max(...values);

  const x = i => p + (i / (values.length - 1)) * (w - p * 2);
  const y = v =>
    h - p - ((v - min) / (max - min || 1)) * (h - p * 2);

  const path = values
    .map((v, i) => `${i ? "L" : "M"} ${x(i)} ${y(v)}`)
    .join(" ");

  svg.innerHTML = "";

  const delta = values.at(-1) - values.at(-2);
  const good = invert ? delta < 0 : delta > 0;

  const color = good
    ? "var(--color-pass)"
    : delta === 0
    ? "#8c959f"
    : "var(--color-fail)";

  // threshold line
  if (threshold !== null) {
    const t = document.createElementNS("http://www.w3.org/2000/svg", "line");
    t.setAttribute("x1", 0);
    t.setAttribute("x2", w);
    t.setAttribute("y1", y(threshold));
    t.setAttribute("y2", y(threshold));
    t.setAttribute("stroke", "#ff9f1c");
    t.setAttribute("stroke-width", "1.5");
    t.setAttribute("stroke-dasharray", "4 4");
    svg.appendChild(t);
  }

  svg.insertAdjacentHTML("beforeend", `
    <path d="${path}" fill="none" stroke="${color}"
          stroke-width="2.5" stroke-linecap="round"/>
    <circle cx="${x(values.length - 1)}"
            cy="${y(values.at(-1))}"
            r="3.5" fill="${color}"/>
  `);

  return delta;
}

/* ---------------- Bootstrap ---------------- */
(async function init() {
  try {
    /* PASS% */
    const pass = await loadJSON(PASS_PATH);
    const passValues = pass.slice(-12).map(p => clamp(p.pass_pct));

    renderSparkline(
      document.getElementById("pass-sparkline"),
      passValues
    );

    /* Last updated badge */
    const last = pass.at(-1);
    const badge = document.getElementById("last-updated");
    if (badge && last?.week) {
      badge.innerHTML = `Updated: <b>${last.week}</b>`;
    }

    /* KEV */
    const kev = await loadJSON(KEV_PATH);
    const kevValues = kev.slice(-12).map(p => p.kev_count);

    const kevSvg = document.getElementById("kev-sparkline");
    renderSparkline(kevSvg, kevValues, KEV_THRESHOLD, true);

    /* Click → DefectDojo */
    kevSvg?.addEventListener("click", () => {
      const top = kev.at(-1)?.top_cves?.[0];
      if (top) {
        window.open(
          `${DEFECTDOJO_BASE}?search=${encodeURIComponent(top)}`,
          "_blank"
        );
      }
    });

  } catch (e) {
    console.warn("Dashboard trend unavailable:", e.message);
  }
})();
