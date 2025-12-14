/* ====================================================
   Executive Sparkline (Weekly PASS %)
   - No dependencies
   - GitHub Pages safe
   - Direction > snapshot
   ==================================================== */

(async function renderSparkline() {
  const svg = document.getElementById("sparkline");
  if (!svg) return;

  try {
    const res = await fetch("./data/trends/asvs-pass-trend.json", {
      cache: "no-store"
    });

    if (!res.ok) {
      console.warn("[sparkline] trend data not found");
      return;
    }

    const json = await res.json();
    const points = (json.data || []).slice(-8); // last 8 weeks
    if (points.length < 2) return;

    const values = points.map(p => Number(p.value) || 0);

    const width = 300;
    const height = 60;
    const pad = 6;

    const min = Math.min(...values, 0);
    const max = Math.max(...values, 100);
    const range = max - min || 1;

    const scaleX = i =>
      pad + (i / (values.length - 1)) * (width - pad * 2);

    const scaleY = v =>
      height - pad - ((v - min) / range) * (height - pad * 2);

    const path = values
      .map((v, i) => `${scaleX(i)},${scaleY(v)}`)
      .join(" ");

    const last = values[values.length - 1];
    const prev = values[values.length - 2];
    const delta = last - prev;

    const color =
      delta >= 0
        ? getComputedStyle(document.documentElement)
            .getPropertyValue("--color-pass") || "#067647"
        : getComputedStyle(document.documentElement)
            .getPropertyValue("--color-fail") || "#b42318";

    svg.innerHTML = `
      <polyline
        fill="none"
        stroke="${color.trim()}"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        points="${path}" />
      <circle
        cx="${scaleX(values.length - 1)}"
        cy="${scaleY(last)}"
        r="3"
        fill="${color.trim()}" />
    `;

  } catch (err) {
    console.error("[sparkline] render failed:", err);
  }
})();
