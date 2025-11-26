# check_critical.py
import json
import os
import sys
import xml.etree.ElementTree as ET
import requests

# Lokasi reports yang diunduh
REPORT_DIR = "reports"
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK')

def parse_gitleaks(file_path):
    """Parses Gitleaks report. Any finding is considered Critical."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            if data:
                return True, f"🔑 {len(data)} Secret(s) found by Gitleaks."
    except Exception as e:
        print(f"Error parsing Gitleaks: {e}", file=sys.stderr)
    return False, None

def parse_semgrep_trivy(file_path, severity_key, critical_levels):
    """Parses Semgrep or Trivy JSON reports for CRITICAL/HIGH findings."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            critical_findings = []
            
            # Logika parsing Semgrep
            if 'results' in data: # Semgrep
                for result in data.get('results', []):
                    if result.get(severity_key, '').upper() in critical_levels:
                        critical_findings.append(result.get('check_id'))
            
            # Logika parsing Trivy (berdasarkan 'vulnerabilities' atau 'misconfigurations')
            elif 'Results' in data: # Trivy
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                         if vuln.get(severity_key, '').upper() in critical_levels:
                            critical_findings.append(f"{vuln.get('VulnerabilityID')} ({result.get('Target')})")
                    for misconfig in result.get('Misconfigurations', []):
                        if misconfig.get(severity_key, '').upper() in critical_levels:
                            critical_findings.append(f"MISCONFIG: {misconfig.get('ID')} ({result.get('Target')})")
            
            if critical_findings:
                unique_findings = set(critical_findings)
                tool_name = os.path.basename(file_path).split('-')[0].upper()
                return True, f"⚠️ {len(unique_findings)} {tool_name} Critical/High findings."
    except Exception as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
    return False, None

def parse_zap(file_path, critical_levels=['High', 'Critical']):
    """Parses OWASP ZAP XML report for High/Critical alerts."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        site = root.find('site')
        
        critical_alerts = []
        if site:
            for alert in site.findall('.//alertitem'):
                risk_desc = alert.find('riskdesc').text
                # ZAP menggunakan risk code 3 untuk High, 4 untuk Critical.
                # Kita bisa parse risk string atau risk code.
                if any(level in risk_desc for level in critical_levels):
                    alert_name = alert.find('alert').text
                    critical_alerts.append(alert_name)
        
        if critical_alerts:
            unique_alerts = set(critical_alerts)
            return True, f"🛑 {len(unique_alerts)} ZAP Critical/High DAST alerts."
    except Exception as e:
        print(f"Error parsing ZAP XML: {e}", file=sys.stderr)
    return False, None

def send_slack_notification(summary):
    """Sends a formatted notification to Slack."""
    if not SLACK_WEBHOOK:
        print("SLACK_WEBHOOK environment variable not set. Skipping notification.", file=sys.stderr)
        return
        
    pipeline_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"
    
    payload = {
        "text": ":alert: *CRITICAL VULNERABILITY ALERT - VULN BANK*",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Pipeline DevSecOps mendeteksi **Kerentanan Kritis/Tinggi** pada kode Vuln Bank (`{os.environ.get('GITHUB_REF_NAME')}`)."
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Daftar Temuan:\n{summary}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Lihat Hasil Scan (Artifacts)"
                        },
                        "url": pipeline_url
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK, json=payload)
        response.raise_for_status()
        print("Slack notification sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Slack notification: {e}", file=sys.stderr)

def main():
    critical_found = False
    finding_summary = []
    
    # 1. Gitleaks (Secret Scanning)
    found, summary = parse_gitleaks(os.path.join(REPORT_DIR, 'static/gitleaks-report.json'))
    if found:
        critical_found = True
        finding_summary.append(summary)

    # 2. Semgrep (SAST)
    found, summary = parse_semgrep_trivy(os.path.join(REPORT_DIR, 'static/semgrep-report.json'), 'severity', ['CRITICAL', 'ERROR']) # Semgrep menggunakan ERROR untuk tingkat tertinggi
    if found:
        critical_found = True
        finding_summary.append(summary)

    # 3. Trivy (Misconfig/Vulnerability)
    found, summary = parse_semgrep_trivy(os.path.join(REPORT_DIR, 'static/trivy-config-report.json'), 'Severity', ['CRITICAL', 'HIGH'])
    if found:
        critical_found = True
        finding_summary.append(summary)
        
    # 4. ZAP (DAST)
    found, summary = parse_zap(os.path.join(REPORT_DIR, 'dast/zap-report.xml'))
    if found:
        critical_found = True
        finding_summary.append(summary)

    # 5. Notifikasi
    if critical_found:
        print("::set-output name=critical_found::true") # Output untuk trigger GitHub Issue
        summary_text = "\n".join([f"* {s}" for s in finding_summary])
        send_slack_notification(summary_text)
    else:
        print("::set-output name=critical_found::false")

if __name__ == "__main__":
    main()