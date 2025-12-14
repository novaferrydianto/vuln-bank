# Vuln Bank – Weekly Security Executive Summary

**Repository:** `novaferrydianto/vuln-bank`  
**Generated:** 2025-01-13T02:00:00Z  
**Overall Score:** **52/100 (Grade C)**

## Top Signals
- **OWASP exposure:** A01=3, A02=1, A05=2 (7-day window)
- **EPSS high-risk:** 4 findings; top: CVE-2024-3094 (EPSS 0.92) in xz-utils
- **SLA breaches:** Critical=1, High=2

## Interpretation (Exec-ready)
- **Active risk exists** due to high EPSS probability and SLA breaches.
- **Access control + crypto posture** remain primary engineering priorities (A01/A02).

## Required Actions (Next 7 Days)
1. **Patch/mitigate EPSS>threshold items first** (KEV/EPSS-driven sequencing).
2. **A01: access control audit** (authz checks, IDOR patterns, route policies).
3. **SLA remediation plan**: assign owners, enforce aging controls, weekly burn-down.

## Ownership & SLA
- Critical: 7 days (target), High: 14 days (target)
- Escalate when breached: auto-incident + weekly breach report.

## Appendix
Data sources: `docs/data/security-scorecard.json`, `docs/data/owasp-latest.json`, `docs/data/defectdojo-sla-weekly.json`
