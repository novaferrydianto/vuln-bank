# Security Maturity — One Pager (Vuln Bank)

## Executive Snapshot (EN)
- **Security Maturity Score:** 0–100 composite score (OWASP posture + EPSS exposure + SLA reliability)
- **What it tells you:** whether risk is *visible*, *prioritized*, and *shrinking over time*
- **How to read it:** a lower score is a signal for investment focus — not a reflection of engineering quality

## Ringkasan Eksekutif (ID)
- **Security Maturity Score:** skor komposit 0–100 (postur OWASP + exposure EPSS + reliabilitas SLA)
- **Maknanya:** apakah risiko sudah *terlihat*, *terprioritaskan*, dan *mengecil dari waktu ke waktu*
- **Cara baca:** skor rendah adalah sinyal fokus perbaikan — bukan “timnya jelek”

---

## What we measure (EN)
- **OWASP posture:** risk labels and control signals from CI
- **EPSS exposure:** count of high exploit-probability CVEs (plus KEV emphasis when available)
- **SLA reliability:** overdue remediation signals (aging and breach rate)

## Apa yang diukur (ID)
- **OWASP posture:** label risiko dan sinyal kontrol dari CI
- **EPSS exposure:** jumlah CVE dengan probabilitas exploit tinggi (plus KEV bila tersedia)
- **SLA reliability:** sinyal keterlambatan perbaikan (aging dan breach rate)

---

## Decision Guidance (EN)
- **Score 80–100:** maintain, automate more controls, reduce operational overhead
- **Score 60–79:** focus on top exploit risks (EPSS/KEV) + prevent regressions via gating
- **Score <60:** prioritize exposure reduction + remediation speed; treat as “risk stabilization phase”

## Panduan Keputusan (ID)
- **Skor 80–100:** maintain, tambah otomasi kontrol, kurangi overhead operasional
- **Skor 60–79:** fokus top exploit risks (EPSS/KEV) + cegah regresi lewat gating
- **Skor <60:** prioritaskan penurunan exposure + percepat remediasi; fase “stabilisasi risiko”

---

## This week’s priorities (EN)
- Fix top EPSS CVEs first (highest exploit likelihood)
- Enforce remediation SLAs for Critical/High findings
- Expand ASVS evidence coverage in CI (make controls measurable and repeatable)

## Prioritas minggu ini (ID)
- Perbaiki top EPSS CVE dulu (paling mungkin dieksploitasi)
- Tegakkan SLA perbaikan untuk finding Critical/High
- Perluas coverage bukti ASVS di CI (kontrol jadi terukur dan konsisten)

---

## Why this approach works (EN)
- Shifts security left: issues are found *before production*
- Makes security measurable: controls become data, not opinions
- Creates a repeatable improvement loop: detect → prioritize → remediate → prevent regression

## Kenapa pendekatan ini efektif (ID)
- Security shift-left: masalah ketemu *sebelum production*
- Keamanan jadi terukur: kontrol jadi data, bukan opini
- Ada loop perbaikan: deteksi → prioritas → perbaiki → cegah regresi
