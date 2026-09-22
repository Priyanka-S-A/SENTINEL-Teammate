import os
from typing import List, Dict, Any

class SyntheticDemoDatasetBuilder:
    """
    Generates realistic multi-file synthetic attack scenario (Requirements #27, #28).
    Includes the 'Hidden Connection' challenge:
    Phishing Email (.eml) -> Malicious Link -> DNS Query (.csv) -> Firewall Outbound (.json) ->
    Auth Log (.txt) -> Endpoint Sysmon Alert (.json) -> Threat Advisory (.pdf).
    """

    def generate_demo_files(self) -> List[Dict[str, Any]]:
        files = []

        # File 1: Phishing Email (.eml)
        eml_content = (
            "From: HR Security Notice <update-portal@malicious-phish.net>\n"
            "To: user.smith@company.com\n"
            "Subject: IMPORTANT: Mandatory Corporate Password Verification\n"
            "Date: Mon, 14 Sep 2026 10:00:15 +0000\n"
            "Received: from mail.malicious-phish.net (198.51.100.45) by mail.company.com with ESMTP\n"
            "X-Mailer: Outgoing Mailer 4.1\n\n"
            "Dear Employee,\n\n"
            "Our security system detected an outdated password policy on your account. "
            "Please click the secure link below immediately to re-verify your corporate credentials:\n\n"
            "http://malicious-phish.net/login/update-password.php\n\n"
            "Failure to update within 24 hours will result in account suspension.\n\n"
            "IT Security Operations Team"
        )
        files.append({
            "filename": "phishing_email.eml",
            "content_bytes": eml_content.encode('utf-8')
        })

        # File 2: DNS Query Log (.csv)
        dns_csv_content = (
            "timestamp,client_ip,query_name,query_type,resolved_ip,status\n"
            "2026-09-14 10:02:11,10.0.0.15,malicious-phish.net,A,198.51.100.45,NOERROR\n"
            "2026-09-14 10:02:14,10.0.0.15,microsoft.com,A,52.96.10.1,NOERROR\n"
            "2026-09-14 10:05:00,10.0.0.88,github.com,A,140.82.121.4,NOERROR"
        )
        files.append({
            "filename": "dns_queries.csv",
            "content_bytes": dns_csv_content.encode('utf-8')
        })

        # File 3: Firewall Traffic Logs (.json)
        firewall_json_content = """[
  {
    "timestamp": "2026-09-14 10:02:45",
    "src_ip": "10.0.0.15",
    "src_port": 54210,
    "dst_ip": "198.51.100.45",
    "dst_port": 443,
    "protocol": "TCP",
    "action": "ALLOW",
    "bytes_sent": 4820,
    "bytes_recv": 18450
  },
  {
    "timestamp": "2026-09-14 10:04:10",
    "src_ip": "10.0.0.15",
    "src_port": 54212,
    "dst_ip": "52.96.10.1",
    "dst_port": 443,
    "protocol": "TCP",
    "action": "ALLOW",
    "bytes_sent": 1200,
    "bytes_recv": 3400
  }
]"""
        files.append({
            "filename": "firewall_syslog.json",
            "content_bytes": firewall_json_content.encode('utf-8')
        })

        # File 4: Windows Security Authentication Log (.txt)
        auth_txt_content = (
            "2026-09-14 10:00:00 - EventID 4624 - Successful Logon - User: user.smith@company.com - Workstation: WORKSTATION-FIN01 (10.0.0.15) - LogonType: 2\n"
            "2026-09-14 10:03:22 - EventID 4625 - Failed Password Attempt - User: user.smith@company.com - Source IP: 198.51.100.45 - Status: 0xC000006D\n"
            "2026-09-14 10:03:40 - EventID 4624 - Successful External Auth - User: user.smith@company.com - Source IP: 198.51.100.45 - LogonType: 3 (Network)\n"
            "2026-09-14 10:04:05 - EventID 4672 - Special Privileges Assigned to Account user.smith@company.com - SeDebugPrivilege Enabled"
        )
        files.append({
            "filename": "windows_auth_events.txt",
            "content_bytes": auth_txt_content.encode('utf-8')
        })

        # File 5: Endpoint Sysmon Process Execution (.json)
        sysmon_json_content = """[
  {
    "EventID": 1,
    "UtcTime": "2026-09-14 10:04:30.124",
    "Host": "WORKSTATION-FIN01",
    "User": "COMPANY\\\\user.smith",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand aGVsbG8gd29ybGQ=",
    "Hashes": "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    "ParentImage": "C:\\\\Windows\\\\explorer.exe"
  }
]"""
        files.append({
            "filename": "sysmon_endpoint_alerts.json",
            "content_bytes": sysmon_json_content.encode('utf-8')
        })

        # File 6: CERT Threat Advisory (.pdf mock)
        pdf_content = (
            "THREAT ADVISORY CVE-2026-9981 - COBALT STRIKE PHISHING CAMPAIGN\n"
            "Threat Actors are utilizing newly registered domain malicious-phish.net and C2 host 198.51.100.45.\n"
            "Targeting corporate users with fake credential portals and payload hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        )
        files.append({
            "filename": "cert_threat_advisory.pdf",
            "content_bytes": pdf_content.encode('utf-8')
        })

        return files

demo_dataset_builder = SyntheticDemoDatasetBuilder()
