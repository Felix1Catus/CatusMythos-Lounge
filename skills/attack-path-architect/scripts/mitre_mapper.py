# --- merged into CatusMythos-Lounge from Masriyan/Claude-Code-CyberSecurity-Skill ---
# Originally shipped alongside the (since-removed) 06-threat-hunting domain
# skill; this copy is attack-path-architect's own canonical one -- see
# MERGE_MAP.md for the full history.
#
#!/usr/bin/env python3
"""
MITRE ATT&CK Mapper
Maps threat behaviors and techniques to the MITRE ATT&CK framework.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Core MITRE ATT&CK technique database (subset for offline use)
ATTACK_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "subtechniques": {
            "T1059.001": {"name": "PowerShell", "detection": "Monitor for powershell.exe execution with unusual arguments"},
            "T1059.003": {"name": "Windows Command Shell", "detection": "Monitor for cmd.exe with encoded commands"},
            "T1059.004": {"name": "Unix Shell", "detection": "Monitor for bash/sh with base64 decoded commands"},
            "T1059.006": {"name": "Python", "detection": "Monitor for python execution from unusual paths"},
        },
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may abuse task scheduling to execute malicious code.",
        "subtechniques": {
            "T1053.005": {"name": "Scheduled Task", "detection": "Monitor schtasks.exe /create commands"},
            "T1053.003": {"name": "Cron", "detection": "Monitor modifications to crontab and /etc/cron.*"},
        },
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade process-based defenses.",
        "subtechniques": {
            "T1055.001": {"name": "DLL Injection", "detection": "Monitor for LoadLibrary calls from unusual sources"},
            "T1055.003": {"name": "Thread Execution Hijacking", "detection": "Monitor for SuspendThread/SetThreadContext"},
            "T1055.012": {"name": "Process Hollowing", "detection": "Monitor for NtUnmapViewOfSection followed by WriteProcessMemory"},
        },
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols.",
        "subtechniques": {
            "T1071.001": {"name": "Web Protocols", "detection": "Monitor HTTP/HTTPS traffic for C2 patterns"},
            "T1071.004": {"name": "DNS", "detection": "Monitor for DNS tunneling (high query volume, TXT records)"},
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        # ATT&CK v19 (28 Apr 2026) retired the "Defense Evasion" tactic and
        # split it into "Stealth" (same TA0005 ID) + a new "Defense
        # Impairment" (TA0112) -- confirmed via a direct fetch of T1078's own
        # page: this entry's tactic list changed from "Defense Evasion" to
        # "Stealth" (research_notes/Attack path architect depth techniques/
        # mitre_technique_reference_data.md). NOT a blanket rename: T1548
        # historically also carried Defense Evasion but now shows ONLY
        # Privilege Escalation, so T1055/T1027 below were deliberately left
        # unchanged -- their own Defense-Evasion tag was not independently
        # re-verified against v19 this pass, and guessing would repeat the
        # exact mistake the research explicitly warned against.
        "tactic": "Stealth, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may use valid accounts to gain access.",
        "subtechniques": {
            "T1078.001": {"name": "Default Accounts", "detection": "Monitor for logons with default/built-in accounts"},
            "T1078.002": {"name": "Domain Accounts", "detection": "Monitor for unusual domain account activity"},
            "T1078.003": {"name": "Local Accounts", "detection": "Monitor for local account creation and usage"},
            "T1078.004": {"name": "Cloud Accounts", "detection": "Monitor cloud provider sign-in logs for anomalous source IP/impossible-travel/new-device sign-ins on cloud-scoped accounts"},
        },
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "subtechniques": {
            "T1110.001": {"name": "Password Guessing", "detection": "Monitor for multiple failed logon attempts"},
            "T1110.003": {"name": "Password Spraying", "detection": "Monitor for single password against many accounts"},
        },
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or networks to interrupt availability.",
        "subtechniques": {},
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate files or information to hinder detection.",
        "subtechniques": {
            "T1027.001": {"name": "Binary Padding", "detection": "Monitor for unusually large binaries"},
            "T1027.002": {"name": "Software Packing", "detection": "Detect known packer signatures"},
        },
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system.",
        "subtechniques": {},
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services to move laterally.",
        "subtechniques": {
            "T1021.001": {"name": "Remote Desktop Protocol", "detection": "Monitor for unusual RDP connections"},
            "T1021.002": {"name": "SMB/Windows Admin Shares", "detection": "Monitor for C$/ADMIN$ share access"},
            "T1021.004": {"name": "SSH", "detection": "Monitor for SSH connections from unusual sources"},
            "T1021.006": {"name": "Windows Remote Management", "detection": "Monitor for WinRM connections"},
        },
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute at startup.",
        "subtechniques": {
            "T1547.001": {"name": "Registry Run Keys", "detection": "Monitor HKLM/HKCU Run key modifications"},
            "T1547.004": {"name": "Winlogon Helper DLL", "detection": "Monitor Winlogon registry changes"},
        },
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the OS.",
        "subtechniques": {
            "T1003.001": {"name": "LSASS Memory", "detection": "Monitor for LSASS process access"},
            "T1003.002": {"name": "Security Account Manager", "detection": "Monitor for SAM database access"},
            "T1003.003": {"name": "NTDS", "detection": "Monitor for ntdsutil or volume shadow copy access"},
        },
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in internet-facing applications.",
        "subtechniques": {},
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access.",
        "subtechniques": {
            "T1566.001": {"name": "Spearphishing Attachment", "detection": "Monitor for suspicious email attachments"},
            "T1566.002": {"name": "Spearphishing Link", "detection": "Monitor for email links to known bad domains"},
        },
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating over alternative protocols.",
        "subtechniques": {
            "T1048.001": {"name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "detection": "Monitor for unusual encrypted outbound traffic"},
            "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "detection": "Monitor for large DNS/ICMP transfers"},
        },
    },
    # --- Added for the web/API/cloud-pentest pipeline's own attack-tree
    # generator (generate_attack_tree.py), whose inline MITRE_TTPS table
    # needed 15 IDs this table didn't have -- see
    # research_notes/Attack path architect depth techniques/
    # mitre_technique_reference_data.md for full per-ID sourcing (all
    # fetched directly from attack.mitre.org). Adding them here lets
    # generate_attack_tree.py call this module's own lookup_technique()
    # (which already correctly resolves both flat and dotted/nested IDs)
    # instead of maintaining a second, smaller, duplicate table.
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Persistence, Initial Access",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
        "subtechniques": {},
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code.",
        "subtechniques": {},
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.",
        "subtechniques": {
            "T1098.001": {"name": "Additional Cloud Credentials", "detection": "Monitor cloud audit logs for new access-key/credential creation on an existing identity"},
            "T1098.002": {"name": "Additional Email Delegate Permissions", "detection": "Monitor mailbox-permission changes (delegate/send-as/full-access grants)"},
            "T1098.003": {"name": "Additional Cloud Roles", "detection": "Monitor cloud IAM audit logs for role/policy attachment to an identity"},
            "T1098.004": {"name": "SSH Authorized Keys", "detection": "Monitor for new entries in ~/.ssh/authorized_keys"},
            "T1098.005": {"name": "Device Registration", "detection": "Monitor identity-provider logs for new device registrations on an existing account"},
            "T1098.006": {"name": "Additional Container Cluster Roles", "detection": "Monitor Kubernetes/cluster audit logs for RoleBinding/ClusterRoleBinding creation"},
            "T1098.007": {"name": "Additional Local or Domain Groups", "detection": "Monitor for account additions to privileged local/domain groups"},
        },
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        # Confirmed via a direct fetch of T1548's own page that it does NOT
        # carry a Stealth/Defense-Impairment tag post-v19, unlike T1078 above
        # -- the counter-example the research used to show the restructuring
        # can't be assumed via blanket find/replace.
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.",
        "subtechniques": {
            "T1548.001": {"name": "Setuid and Setgid", "detection": "Monitor for execution of binaries with the setuid/setgid bit set from unusual paths"},
            "T1548.002": {"name": "Bypass User Account Control", "detection": "Monitor for UAC bypass indicators (auto-elevating binaries launched with unexpected parent processes)"},
            "T1548.003": {"name": "Sudo and Sudo Caching", "detection": "Monitor /etc/sudoers modifications and sudo usage outside normal patterns"},
            "T1548.004": {"name": "Elevated Execution with Prompt", "detection": "Monitor for unexpected authorization/credential prompts (e.g. macOS AuthorizationExecuteWithPrivileges)"},
            "T1548.005": {"name": "Temporary Elevated Cloud Access", "detection": "Monitor cloud audit logs for temporary privilege-elevation grants (e.g. AWS sts:AssumeRole, GCP IAM temporary bindings)"},
            "T1548.006": {"name": "TCC Manipulation", "detection": "Monitor macOS TCC.db modifications outside the System Preferences UI"},
        },
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
        "subtechniques": {},
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, to move laterally and bypass normal system access controls.",
        "subtechniques": {
            "T1550.001": {"name": "Application Access Token", "detection": "Monitor for OAuth/API token usage from unexpected source IPs or in unusual API-call sequences"},
            "T1550.002": {"name": "Pass the Hash", "detection": "Monitor for NTLM authentication using a hash with no corresponding interactive logon"},
            "T1550.003": {"name": "Pass the Ticket", "detection": "Monitor for Kerberos ticket reuse across hosts without a corresponding TGT request"},
            "T1550.004": {"name": "Web Session Cookie", "detection": "Monitor for session-cookie reuse from a new IP/user-agent inconsistent with the original session"},
        },
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
        "subtechniques": {},
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "subtechniques": {
            "T1552.001": {"name": "Credentials In Files", "detection": "Scan for credential-shaped strings in accessible files (config, .env, source)"},
            "T1552.002": {"name": "Credentials in Registry", "detection": "Monitor/scan Windows Registry for plaintext credential values"},
            "T1552.003": {"name": "Shell History", "detection": "Monitor access to .bash_history/.zsh_history and similar shell history files"},
            "T1552.004": {"name": "Private Keys", "detection": "Scan for private-key-shaped files (id_rsa, .pem, .pfx) outside expected locations"},
            "T1552.005": {"name": "Cloud Instance Metadata API", "detection": "Monitor for requests to the cloud metadata service (169.254.169.254, 169.254.170.2, metadata.google.internal) from an unexpected process/context"},
            "T1552.006": {"name": "Group Policy Preferences", "detection": "Scan SYSVOL for Group Policy Preference XML files containing cpassword"},
            "T1552.007": {"name": "Container API", "detection": "Monitor for unauthenticated/anomalous queries to a container orchestrator's local API (e.g. Docker socket, kubelet API)"},
            "T1552.008": {"name": "Chat Messages", "detection": "Monitor for credential-shaped strings retrieved from chat/collaboration-tool message history via an API or export"},
        },
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "description": "Adversaries may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials.",
        "subtechniques": {},
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries may access data from improperly secured cloud storage.",
        "subtechniques": {},
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Adversaries may leverage information repositories to mine valuable information.",
        "subtechniques": {
            "T1213.001": {"name": "Confluence", "detection": "Monitor Confluence audit logs for bulk page export or anomalous access patterns"},
            "T1213.002": {"name": "Sharepoint", "detection": "Monitor SharePoint/M365 audit logs for bulk download or anomalous access patterns"},
            "T1213.003": {"name": "Code Repositories", "detection": "Monitor source-control audit logs for bulk clone/export of private repositories"},
            "T1213.004": {"name": "Customer Relationship Management Software", "detection": "Monitor CRM audit logs for bulk record export"},
            "T1213.005": {"name": "Messaging Applications", "detection": "Monitor chat-platform audit logs for bulk channel/message export"},
            "T1213.006": {"name": "Databases", "detection": "Monitor for large or unusual SELECT/export queries against production databases, including cloud-hosted ones"},
        },
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system sources, such as file systems and configuration files, to find files of interest and sensitive data prior to Exfiltration.",
        "subtechniques": {},
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use an existing, legitimate external web service to exfiltrate data rather than their primary command-and-control channel.",
        "subtechniques": {
            "T1567.001": {"name": "Exfiltration to Code Repository", "detection": "Monitor for outbound pushes to external/personal code-repository accounts from a corporate egress point"},
            "T1567.002": {"name": "Exfiltration to Cloud Storage", "detection": "Monitor for large uploads to consumer/external cloud-storage endpoints"},
            "T1567.003": {"name": "Exfiltration to Text Storage Sites", "detection": "Monitor for outbound POST requests to paste-site domains carrying large payloads"},
            "T1567.004": {"name": "Exfiltration Over Webhook", "detection": "Monitor for outbound webhook calls to unexpected/newly-registered endpoints carrying sensitive data"},
        },
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources to users.",
        "subtechniques": {
            "T1498.001": {"name": "Direct Network Flood", "detection": "Monitor for a sharp, sustained volume increase on a targeted endpoint from many sources"},
            "T1498.002": {"name": "Reflection Amplification", "detection": "Monitor for inbound traffic from reflection-amplification-prone protocols (DNS/NTP/memcached) at anomalous volume"},
        },
    },
    # Three further IDs the pipeline's own chain-to-TTP classification work
    # needed (not part of the original 15-ID gap, but referenced by the new
    # ATTACK_PATTERNS this pass adds to generate_attack_tree.py) -- standard,
    # long-stable ATT&CK entries never tagged Defense Evasion, so the v19
    # restructuring above doesn't apply to them; not independently re-fetched
    # this pass, unlike the 15 IDs above.
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic": "Credential Access",
        "description": "Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources, scoped to Containers and IaaS platforms among others.",
        "subtechniques": {},
    },
    "T1606": {
        "name": "Forge Web Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may forge credential materials that can be used to gain access to web applications or Internet services.",
        "subtechniques": {
            "T1606.001": {"name": "Web Cookies", "detection": "Monitor for session cookies with inconsistent signing/issuance metadata"},
            "T1606.002": {"name": "SAML Tokens", "detection": "Monitor for SAML assertions signed by an unexpected certificate or with anomalous claims"},
        },
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        # Added as the approximate, explicitly-flagged-imperfect tag for
        # GraphQL field-suggestion/binary-oracle schema reconstruction
        # (research_notes/Attack path architect depth techniques/
        # chain_to_ttp_mapping.md: no ATT&CK technique precisely covers
        # iterative error-oracle schema inference against an already-
        # reachable API; this is the nearest Reconnaissance-tactic fit, not
        # a confirmed exact match).
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "subtechniques": {
            "T1595.001": {"name": "Scanning IP Blocks", "detection": "Monitor for broad sequential/sweeping connection attempts across an IP range"},
            "T1595.002": {"name": "Vulnerability Scanning", "detection": "Monitor for high-volume probing/error-triggering requests against a single endpoint"},
            "T1595.003": {"name": "Wordlist Scanning", "detection": "Monitor for high-volume enumeration requests using common wordlists against an endpoint"},
        },
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity.",
        "subtechniques": {
            "T1565.001": {"name": "Stored Data Manipulation", "detection": "Monitor for unexpected writes to configuration/data files by a process that doesn't normally write them"},
            "T1565.002": {"name": "Transmitted Data Manipulation", "detection": "Monitor for integrity mismatches between sent and received data in transit"},
            "T1565.003": {"name": "Runtime Data Manipulation", "detection": "Monitor for in-memory modification of application data structures by an unexpected process"},
        },
    },
}

# SIEM query templates
SIEM_TEMPLATES = {
    "splunk": {
        "T1059.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell*" | table _time, Computer, Account_Name, NewProcessName, Process_Command_Line',
        "T1053.005": 'index=windows sourcetype=WinEventLog:Security EventCode=4698 OR (EventCode=4688 NewProcessName="*schtasks*") | table _time, Computer, Account_Name, Task_Name',
        "T1110.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, Account_Name | where count > 5',
        "T1021.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10 | table _time, Source_Network_Address, Account_Name, Computer',
        "T1003.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4663 ObjectName="*lsass*" | table _time, Computer, Account_Name, Process_Name',
    },
    "elastic": {
        "T1059.001": 'event.code:4688 AND process.name:powershell.exe',
        "T1053.005": 'event.code:(4698 OR 4688) AND process.name:schtasks.exe',
        "T1110.001": 'event.code:4625 | stats count by source.ip, user.name | where count > 5',
        "T1021.001": 'event.code:4624 AND winlog.event_data.LogonType:10',
        "T1003.001": 'event.code:4663 AND file.path:*lsass*',
    },
}


class MITREMapper:
    """MITRE ATT&CK technique mapping and query generation engine."""

    def __init__(self):
        self.techniques = ATTACK_TECHNIQUES
        self.siem_templates = SIEM_TEMPLATES

    def lookup_technique(self, technique_id: str) -> Optional[Dict]:
        """Look up a technique by ID."""
        # Check top-level
        if technique_id in self.techniques:
            return {"id": technique_id, **self.techniques[technique_id]}

        # Check sub-techniques
        parent_id = technique_id.split(".")[0]
        if parent_id in self.techniques:
            subtechniques = self.techniques[parent_id].get("subtechniques", {})
            if technique_id in subtechniques:
                return {
                    "id": technique_id,
                    "parent": parent_id,
                    "parent_name": self.techniques[parent_id]["name"],
                    "tactic": self.techniques[parent_id]["tactic"],
                    **subtechniques[technique_id],
                }
        return None

    def map_techniques(self, technique_ids: List[str]) -> Dict[str, Any]:
        """Map multiple technique IDs to ATT&CK details."""
        mapped = []
        unmapped = []

        for tid in technique_ids:
            result = self.lookup_technique(tid.strip())
            if result:
                mapped.append(result)
            else:
                unmapped.append(tid)

        # Group by tactic
        by_tactic = {}
        for tech in mapped:
            tactics = tech.get("tactic", "Unknown")
            for tactic in tactics.split(", "):
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append(tech)

        return {
            "total_mapped": len(mapped),
            "total_unmapped": len(unmapped),
            "techniques": mapped,
            "unmapped": unmapped,
            "by_tactic": {k: [t["id"] for t in v] for k, v in by_tactic.items()},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def generate_detection_query(self, technique_id: str, siem: str = "splunk") -> Optional[str]:
        """Generate a SIEM detection query for a technique."""
        templates = self.siem_templates.get(siem, {})
        return templates.get(technique_id)

    def generate_navigator_layer(self, technique_ids: List[str], name: str = "Threat Map",
                                 attack_version: str = "14") -> Dict:
        """Generate an ATT&CK Navigator layer JSON."""
        techniques = []
        for tid in technique_ids:
            tech = self.lookup_technique(tid)
            if tech:
                techniques.append({
                    "techniqueID": tid,
                    "color": "#e60d0d",
                    "comment": tech.get("name", ""),
                    "enabled": True,
                })

        return {
            "name": name,
            "versions": {"attack": attack_version, "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Generated by CyberSkill MITRE Mapper — {time.strftime('%Y-%m-%d')}",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 1,
            },
        }


def _run_demo() -> int:
    """Offline self-test of technique lookup, tactic grouping, Navigator, and SIEM queries."""
    m = MITREMapper()
    sub = m.lookup_technique("T1059.001")
    mapped = m.map_techniques(["T1059.001", "T1486", "T9999"])
    layer = m.generate_navigator_layer(["T1059.001", "T1003.001"])
    query = m.generate_detection_query("T1059.001", "splunk")
    checks = [
        ("sub-technique resolves to parent tactic", sub and sub.get("tactic") == "Execution"),
        ("sub-technique name correct", sub and sub.get("name") == "PowerShell"),
        ("valid IDs mapped, bogus unmapped", mapped["total_mapped"] == 2 and mapped["unmapped"] == ["T9999"]),
        ("grouped by tactic", "Execution" in mapped["by_tactic"] and "Impact" in mapped["by_tactic"]),
        ("navigator layer has 2 techniques", len(layer["techniques"]) == 2),
        ("splunk query generated", bool(query) and "4688" in query),
    ]
    ok = all(bool(p) for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Mapper",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--input", "-i", help="File with technique IDs (one per line)")
    parser.add_argument("--technique", "-t", help="Single technique ID to look up")
    parser.add_argument("--detection-query", choices=["splunk", "elastic"], help="Generate SIEM query")
    parser.add_argument("--navigator", action="store_true", help="Export ATT&CK Navigator layer")
    parser.add_argument("--attack-version", default="14", help="Target ATT&CK release; bundled subset is legacy v14")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())

    mapper = MITREMapper()

    if args.technique:
        technique_ids = [args.technique]
    elif args.input:
        with open(args.input, "r") as f:
            technique_ids = [line.strip() for line in f if line.strip()]
    else:
        parser.error("Either --technique or --input is required")

    if args.detection_query:
        for tid in technique_ids:
            query = mapper.generate_detection_query(tid, args.detection_query)
            if query:
                print(f"\n# {tid} — {args.detection_query.upper()} Query:")
                print(query)
            else:
                print(f"\n# {tid} — No query template available")
        return

    if args.navigator:
        result = mapper.generate_navigator_layer(technique_ids, attack_version=args.attack_version)
    else:
        result = mapper.map_techniques(technique_ids)

    output_data = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_data)
        logger.info("Results saved to %s", args.output)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
