# Why “FAIL” ≠ Bad (Executive Explainer)

## English (EN)
- **FAIL is not blame.** It is a *risk signal* that has become visible and measurable.
- **A mature security program is not “zero findings.”** It is fast detection, clear prioritization, and consistent reduction of exposure.
- **CI failures are cheaper than production incidents.** We intentionally surface issues early so the organization pays less later.

### What “FAIL” usually means
- Evidence for a control is missing or inconsistent
- A security regression happened (something got worse compared to baseline)
- A high-risk exposure exists (e.g., exploit likelihood is high)

### What we do after a “FAIL”
- Triage by exploit probability (EPSS/KEV) and business impact
- Fix the top risks first
- Add prevention: gates + baselines + automated checks so the same risk doesn’t return

---

## Bahasa Indonesia (ID)
- **FAIL bukan menyalahkan.** FAIL adalah *sinyal risiko* yang sekarang terlihat dan bisa diukur.
- **Program keamanan yang matang bukan “nol temuan.”** Yang penting adalah deteksi cepat, prioritas jelas, dan exposure turun konsisten.
- **Gagal di CI lebih murah daripada insiden di production.** Kita sengaja munculkan isu lebih awal agar biaya dan dampaknya kecil.

### Biasanya “FAIL” artinya
- Bukti kontrol belum ada atau belum konsisten
- Ada regresi keamanan (lebih buruk dari baseline)
- Ada exposure berisiko tinggi (misal peluang exploit tinggi)

### Yang dilakukan setelah “FAIL”
- Triage berdasarkan peluang exploit (EPSS/KEV) dan dampak bisnis
- Perbaiki risiko terbesar dulu
- Tambahkan pencegahan: gate + baseline + automated checks agar tidak terulang
