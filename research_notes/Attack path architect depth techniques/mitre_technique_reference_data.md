# MITRE ATT&CK Enterprise Technique Reference Data (for technique-reference table)

## IMPORTANT VERSION FLAG — read before using any entry below

### Takeaway
MITRE ATT&CK v19 (released 28 April 2026) **retired/split the "Defense Evasion" tactic (TA0005)**. TA0005 was renamed **"Stealth"** (covering techniques where adversaries hide malicious activity within otherwise-legitimate behavior) and a **new tactic "Defense Impairment" (TA0112)** was created to cover techniques that disable or undermine security controls. Some former Defense-Evasion techniques now map to Stealth, some to Defense Impairment, and some to both. All data below was pulled live from attack.mitre.org on 2026-11-14 and reflects this post-v19 structure; any ID or secondary source still saying "Defense Evasion" is stale.

### Cited Findings
- "MITRE retired Defense Evasion in ATT&CK v19 and split it into two tactics... Stealth... inherits the TA0005 tactic ID" and "Defense Impairment: This new tactic has ID TA0112" — [D3 Security blog via search](https://d3security.com/blog/rip-defense-evasion-ta0005/), corroborated by live page fetch of TA0005.
- Direct fetch of attack.mitre.org/tactics/TA0005/ confirms: page title "Stealth, Tactic TA0005 - Enterprise | MITRE ATT&CK®", description "The adversary is trying to hide and conceal their actions, appearing as normal behavior." — [Source](https://attack.mitre.org/tactics/TA0005/)
- Live fetch confirms T1078 (Valid Accounts) and T1078.004 (Cloud Accounts) both now list tactics as **Stealth, Persistence, Privilege Escalation, Initial Access** (not "Defense Evasion") — [T1078](https://attack.mitre.org/techniques/T1078/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/).
- By contrast, T1548 (Abuse Elevation Control Mechanism), which historically also carried a Defense Evasion tag, now shows **only Privilege Escalation** in its tactic info box per live fetch — it did NOT retain a Stealth or Defense Impairment mapping as of this check — [T1548](https://attack.mitre.org/techniques/T1548/).
- Version conflict noted in secondary sources: one source states current version is v20 (released 13 Oct 2026), another describes v19.1; attack.mitre.org pages fetched directly here show individual technique "Version" numbers (not the overall matrix version) — treat attack.mitre.org as authoritative per-page.

### Inferences
- Any tool/table that still labels T1078, T1078.004, or similar techniques with "Defense Evasion" is out of date post-v19; the reference table should use "Stealth" (and check for "Defense Impairment" co-mapping) going forward.
- Not every technique that used to map to Defense Evasion automatically maps to Stealth — T1548 is a confirmed counter-example — so each technique's tactic list must be checked individually rather than assumed via a global find/replace.

### Gaps
- Did not exhaustively check every technique below for a secondary "Defense Impairment (TA0112)" mapping beyond T1078/T1078.004/T1548 — only tactic info boxes as directly fetched were used. If the tool's table needs full Defense-Impairment coverage auditing, that would require checking each ID individually.

---

## T1133 — External Remote Services

### Takeaway
T1133 remains a parentless technique (no sub-techniques) spanning Persistence and Initial Access; no rename/deprecation.

### Cited Findings
- Name: **External Remote Services**, ID T1133 — [Source](https://attack.mitre.org/techniques/T1133/)
- Tactics: **Persistence (TA0003)** and **Initial Access (TA0001)** — [Source](https://attack.mitre.org/techniques/T1133/)
- Description (MITRE wording): "Adversaries may leverage external-facing remote services to initially access and/or persist within a network." — [Source](https://attack.mitre.org/techniques/T1133/)
- Sub-techniques: **None** ("No sub-techniques" shown on page) — [Source](https://attack.mitre.org/techniques/T1133/)
- Page shows Version 2.5, last modified 12 May 2026 — [Source](https://attack.mitre.org/techniques/T1133/)

### Inferences
- No structural change needed for this entry beyond confirming current wording.

### Gaps
- None identified.

---

## T1078 — Valid Accounts (parent) and T1078.004 — Cloud Accounts (sub-technique)

### Takeaway
T1078 "Valid Accounts" currently has exactly 4 sub-techniques (.001–.004) and spans four tactics: Stealth (renamed from Defense Evasion, TA0005), Persistence, Privilege Escalation, and Initial Access. T1078.004 "Cloud Accounts" inherits the same four-tactic mapping.

### Cited Findings
- Parent name: **Valid Accounts**, ID T1078 — [Source](https://attack.mitre.org/techniques/T1078/)
- Tactics (verbatim from page info box): **Stealth, Persistence, Privilege Escalation, Initial Access** — [Source](https://attack.mitre.org/techniques/T1078/)
- Description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion" (the description text itself still uses the phrase "Defense Evasion" even though the tactic field now reads "Stealth" — likely unupdated prose vs. the renamed tactic taxonomy) — [Source](https://attack.mitre.org/techniques/T1078/)
- Full current sub-technique list (4):
  - T1078.001 — Default Accounts
  - T1078.002 — Domain Accounts
  - T1078.003 — Local Accounts
  - T1078.004 — Cloud Accounts
  — [Source](https://attack.mitre.org/techniques/T1078/)
- Page Version 3.0, last modified 12 May 2026 — [Source](https://attack.mitre.org/techniques/T1078/)
- T1078.004 sub-technique name: **Cloud Accounts** — [Source](https://attack.mitre.org/techniques/T1078/004/)
- T1078.004 tactics (verbatim): **Stealth, Persistence, Privilege Escalation, Initial Access** — [Source](https://attack.mitre.org/techniques/T1078/004/)
- T1078.004 description: "Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access" (full sentence continues with Persistence, Privilege Escalation, Defense Evasion in the prose, same stale-wording pattern as parent) — [Source](https://attack.mitre.org/techniques/T1078/004/)
- T1078.004 page Version 2.0, last modified 12 May 2026 — [Source](https://attack.mitre.org/techniques/T1078/004/)

### Inferences
- The reference table should record T1078/T1078.004's 4th tactic as "Stealth (TA0005)" rather than "Defense Evasion," since that is the current tactic taxonomy name, even though MITRE's own prose description hasn't been fully updated to match.

### Gaps
- Not confirmed whether T1078/T1078.004 also carry a secondary "Defense Impairment (TA0112)" tag — only the tactic info box (Stealth, Persistence, Privilege Escalation, Initial Access) was observed, no Defense Impairment listed.

---

## T1203 — Exploitation for Client Execution

### Takeaway
Single-tactic (Execution) technique with no sub-techniques; no rename/deprecation detected.

### Cited Findings
- Name: **Exploitation for Client Execution**, ID T1203 — [Source](https://attack.mitre.org/techniques/T1203/)
- Tactic: **Execution (TA0002)** — [Source](https://attack.mitre.org/techniques/T1203/)
- Description: "Adversaries may exploit software vulnerabilities in client applications to execute code." — [Source](https://attack.mitre.org/techniques/T1203/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1203/)

### Inferences
- None beyond the base facts.

### Gaps
- None identified.

---

## T1098 — Account Manipulation

### Takeaway
T1098 currently has **7 sub-techniques** (.001–.007), a significant expansion from the historical 3-4 sub-technique set; it spans Persistence and Privilege Escalation tactics.

### Cited Findings
- Name: **Account Manipulation**, ID T1098 — [Source](https://attack.mitre.org/techniques/T1098/)
- Tactics: **Persistence (TA0003), Privilege Escalation (TA0004)** — [Source](https://attack.mitre.org/techniques/T1098/)
- Description: "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems." — [Source](https://attack.mitre.org/techniques/T1098/)
- Full current sub-technique list (7):
  - T1098.001 — Additional Cloud Credentials
  - T1098.002 — Additional Email Delegate Permissions
  - T1098.003 — Additional Cloud Roles
  - T1098.004 — SSH Authorized Keys
  - T1098.005 — Device Registration
  - T1098.006 — Additional Container Cluster Roles
  - T1098.007 — Additional Local or Domain Groups
  — [Source](https://attack.mitre.org/techniques/T1098/)
- Page shows Version 2.8, last modified 12 May 2026 — [Source](https://attack.mitre.org/techniques/T1098/)

### Inferences
- The user's prompt anticipated T1098.001 as "Additional Cloud Credentials" — confirmed correct and current. Note the numbering has shifted/expanded over ATT&CK's history (older references with only 3-4 sub-techniques, e.g. just Additional Cloud Credentials/Email Delegate/SSH Keys, are outdated); current numbering above is the authoritative 7-item set.

### Gaps
- None identified; full current list confirmed directly from the live page.

---

## T1548 — Abuse Elevation Control Mechanism

### Takeaway
T1548 has **6 sub-techniques**, including a newer **Temporary Elevated Cloud Access (.005)** and **TCC Manipulation (.006)**; tactic is Privilege Escalation only (did not retain a Stealth/Defense Impairment mapping despite the tactic restructuring noted above).

### Cited Findings
- Name: **Abuse Elevation Control Mechanism**, ID T1548 — [Source](https://attack.mitre.org/techniques/T1548/)
- Tactic: **Privilege Escalation (TA0004)** only — explicitly confirmed the info box does NOT list Stealth or Defense Impairment — [Source](https://attack.mitre.org/techniques/T1548/)
- Description: "Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions." — [Source](https://attack.mitre.org/techniques/T1548/)
- Full current sub-technique list (6):
  - T1548.001 — Setuid and Setgid
  - T1548.002 — Bypass User Account Control
  - T1548.003 — Sudo and Sudo Caching
  - T1548.004 — Elevated Execution with Prompt
  - T1548.005 — Temporary Elevated Cloud Access
  - T1548.006 — TCC Manipulation
  — [Source](https://attack.mitre.org/techniques/T1548/)
- Page Version 2.0, last modified 12 May 2026 — [Source](https://attack.mitre.org/techniques/T1548/)

### Inferences
- T1548.005 "Temporary Elevated Cloud Access" is a relatively recent, cloud-specific addition relevant to this tool's attack-path focus.

### Gaps
- None identified.

---

## T1068 — Exploitation for Privilege Escalation

### Takeaway
Single-tactic (Privilege Escalation) technique, no sub-techniques, no rename/deprecation detected.

### Cited Findings
- Name: **Exploitation for Privilege Escalation**, ID T1068 — [Source](https://attack.mitre.org/techniques/T1068/)
- Tactic: **Privilege Escalation (TA0004)** — [Source](https://attack.mitre.org/techniques/T1068/)
- Description: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges." — [Source](https://attack.mitre.org/techniques/T1068/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1068/)

### Inferences
- None beyond base facts.

### Gaps
- None identified.

---

## T1550 — Use Alternate Authentication Material

### Takeaway
T1550 has 4 sub-techniques (.001–.004, including Web Session Cookie at .004) and maps to the Lateral Movement tactic.

### Cited Findings
- Name: **Use Alternate Authentication Material**, ID T1550 — [Source](https://attack.mitre.org/techniques/T1550/)
- Tactic: **Lateral Movement (TA0008)** — [Source](https://attack.mitre.org/techniques/T1550/)
- Description: Adversaries may use alternate authentication material "such as password hashes, Kerberos tickets," and similar credentials to move laterally and bypass normal access controls — [Source](https://attack.mitre.org/techniques/T1550/)
- Full current sub-technique list (4):
  - T1550.001 — Application Access Token
  - T1550.002 — Pass the Hash
  - T1550.003 — Pass the Ticket
  - T1550.004 — Web Session Cookie
  — [Source](https://attack.mitre.org/techniques/T1550/)

### Inferences
- T1550.004 Web Session Cookie confirmed as current and correctly numbered, matching the prompt's expectation.

### Gaps
- None identified.

---

## T1210 — Exploitation of Remote Services

### Takeaway
Single-tactic (Lateral Movement) technique, no sub-techniques, no rename/deprecation detected.

### Cited Findings
- Name: **Exploitation of Remote Services**, ID T1210 — [Source](https://attack.mitre.org/techniques/T1210/)
- Tactic: **Lateral Movement (TA0008)** — [Source](https://attack.mitre.org/techniques/T1210/)
- Description: "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network." — [Source](https://attack.mitre.org/techniques/T1210/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1210/)

### Inferences
- None beyond base facts.

### Gaps
- None identified.

---

## T1552 — Unsecured Credentials (and T1552.005 — Cloud Instance Metadata API)

### Takeaway
T1552 currently has **8 sub-techniques** (.001–.008), a larger set than older references (which typically listed ~6); T1552.005 "Cloud Instance Metadata API" is confirmed current and correctly numbered. Tactic is Credential Access.

### Cited Findings
- Parent name: **Unsecured Credentials**, ID T1552 — [Source](https://attack.mitre.org/techniques/T1552/)
- Tactic: **Credential Access (TA0006)** — [Source](https://attack.mitre.org/techniques/T1552/)
- Description: "Adversaries may search compromised systems to find and obtain insecurely stored credentials." — [Source](https://attack.mitre.org/techniques/T1552/)
- Full current sub-technique list (8):
  - T1552.001 — Credentials In Files
  - T1552.002 — Credentials in Registry
  - T1552.003 — Shell History
  - T1552.004 — Private Keys
  - T1552.005 — Cloud Instance Metadata API
  - T1552.006 — Group Policy Preferences
  - T1552.007 — Container API
  - T1552.008 — Chat Messages
  — [Source](https://attack.mitre.org/techniques/T1552/)
- T1552.005 name: **Cloud Instance Metadata API** — [Source](https://attack.mitre.org/techniques/T1552/005/)
- T1552.005 tactic: **Credential Access (TA0006)** — [Source](https://attack.mitre.org/techniques/T1552/005/)
- T1552.005 description: "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data." — [Source](https://attack.mitre.org/techniques/T1552/005/)

### Inferences
- T1552.006 (Group Policy Preferences), .007 (Container API), and .008 (Chat Messages) are additions beyond the historically commonly-cited 5-sub-technique set — worth flagging to the tool's table maintainer as newer entries that may not be in an older reference table.

### Gaps
- None identified for the specific IDs requested.

---

## T1539 — Steal Web Session Cookie

### Takeaway
T1539 is current, not deprecated or merged into T1550.004 — the two are related-but-distinct techniques (T1539 = stealing the cookie via Credential Access; T1550.004 = using an already-obtained cookie for Lateral Movement). No sub-techniques under T1539.

### Cited Findings
- Name: **Steal Web Session Cookie**, ID T1539 — [Source](https://attack.mitre.org/techniques/T1539/)
- Tactic: **Credential Access (TA0006)** — [Source](https://attack.mitre.org/techniques/T1539/)
- Description (MITRE wording): an adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials — [Source](https://attack.mitre.org/techniques/T1539/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1539/)
- No deprecation/merge/rename notice on the page; current page Version 1.5 — [Source](https://attack.mitre.org/techniques/T1539/)
- The page cross-references T1550.004 (Web Session Cookie) as the follow-on lateral-movement step after a cookie is stolen, confirming the two remain separate, complementary techniques rather than one replacing the other — [Source](https://attack.mitre.org/techniques/T1539/)

### Inferences
- The tool's reference table should keep both T1539 (Credential Access: theft) and T1550.004 (Lateral Movement: reuse) as distinct entries since they represent different stages/tactics of the same tradecraft.

### Gaps
- None identified.

---

## T1530 — Data from Cloud Storage

### Takeaway
Single-tactic (Collection) technique, no sub-techniques, no rename/deprecation detected.

### Cited Findings
- Name: **Data from Cloud Storage**, ID T1530 — [Source](https://attack.mitre.org/techniques/T1530/)
- Tactic: **Collection (TA0009)** — [Source](https://attack.mitre.org/techniques/T1530/)
- Description: "Adversaries may access data from cloud storage." — [Source](https://attack.mitre.org/techniques/T1530/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1530/)

### Inferences
- None beyond base facts.

### Gaps
- None identified.

---

## T1213 — Data from Information Repositories

### Takeaway
T1213 currently has **6 sub-techniques** (.001–.006): Confluence, SharePoint, Code Repositories, Customer Relationship Management Software, Messaging Applications, and Databases. There is **no standalone "Cloud" sub-technique** — cloud-hosted repositories (e.g., cloud databases) are covered within the Databases (.006) sub-technique's description rather than as a separate ID. Tactic is Collection.

### Cited Findings
- Name: **Data from Information Repositories**, ID T1213 — [Source](https://attack.mitre.org/techniques/T1213/)
- Tactic: **Collection (TA0009)** — [Source](https://attack.mitre.org/techniques/T1213/)
- Description: "Adversaries may leverage information repositories to mine valuable information." — [Source](https://attack.mitre.org/techniques/T1213/)
- Full current sub-technique list (6):
  - T1213.001 — Confluence
  - T1213.002 — Sharepoint
  - T1213.003 — Code Repositories
  - T1213.004 — Customer Relationship Management Software
  - T1213.005 — Messaging Applications
  - T1213.006 — Databases
  — [Source](https://attack.mitre.org/techniques/T1213/)
- Cross-check search confirmed T1213.006 "Databases" explicitly covers both on-premises and cloud-hosted databases (PaaS and SaaS), including a cited 2025 campaign referencing use of an AI coding tool to query internal databases — [Source](https://attack.mitre.org/techniques/T1213/006/) (per search summary; direct page not separately fetched in full)
- An older Center for Threat-Informed Defense mapping (ATT&CK v8.2) lists only T1213.001/.002 (Confluence/Sharepoint), confirming this is a legacy/stale snapshot and NOT the current structure — [Source](https://center-for-threat-informed-defense.github.io/mappings-explorer/attack/attack-8.2/domain-enterprise/techniques/T1213)

### Inferences
- If the tool's table currently only lists 2-3 sub-techniques for T1213 (Confluence/SharePoint/Code Repositories, as in older ATT&CK versions), it needs to be updated to the current 6-item set above.
- No dedicated "Cloud" sub-technique ID exists for T1213 as of this check — contrary to the task's suggestion that one might exist; cloud repository access is folded into Databases (.006) and other sub-techniques' descriptions rather than broken out separately.

### Gaps
- Full page text of T1213.006 (Databases) was confirmed only via search-result summary, not a full direct WebFetch of that sub-page — the sub-technique's existence, name, and general scope are confirmed, but its exact one-line MITRE description text was not independently verified word-for-word from a direct fetch.

---

## T1005 — Data from Local System

### Takeaway
Single-tactic (Collection) technique, no sub-techniques, no rename/deprecation detected.

### Cited Findings
- Name: **Data from Local System**, ID T1005 — [Source](https://attack.mitre.org/techniques/T1005/)
- Tactic: **Collection (TA0009)** — [Source](https://attack.mitre.org/techniques/T1005/)
- Description (MITRE wording, paraphrased from a truncated fetch): adversaries may search local system sources, such as file systems, configuration files, and local databases, to find files of interest and sensitive data prior to Exfiltration — [Source](https://attack.mitre.org/techniques/T1005/)
- Sub-techniques: **None** — [Source](https://attack.mitre.org/techniques/T1005/)

### Inferences
- None beyond base facts.

### Gaps
- The full page text (138,039 characters) was only partially read (first 100,000 characters) due to length; the core name/tactic/description/sub-technique facts were confirmed within that portion, so no further read was pursued, but exhaustive procedure-example detail beyond the summary line was not reviewed (not needed for a one-line reference-table description).

---

## T1567 — Exfiltration Over Web Service

### Takeaway
T1567 has 4 sub-techniques (.001–.004), including Exfiltration to Cloud Storage (.002), and maps to the Exfiltration tactic.

### Cited Findings
- Name: **Exfiltration Over Web Service**, ID T1567 — [Source](https://attack.mitre.org/techniques/T1567/)
- Tactic: **Exfiltration (TA0010)** — [Source](https://attack.mitre.org/techniques/T1567/)
- Description: adversaries using "an existing, legitimate external Web service to exfiltrate data" instead of their primary command and control channel — [Source](https://attack.mitre.org/techniques/T1567/)
- Full current sub-technique list (4):
  - T1567.001 — Exfiltration to Code Repository
  - T1567.002 — Exfiltration to Cloud Storage
  - T1567.003 — Exfiltration to Text Storage Sites
  - T1567.004 — Exfiltration Over Webhook
  — [Source](https://attack.mitre.org/techniques/T1567/)

### Inferences
- T1567.004 "Exfiltration Over Webhook" is a newer addition beyond the classic 3-sub-technique set (Code Repository/Cloud Storage/Text Storage Sites) — worth flagging if the tool's existing table predates it.

### Gaps
- None identified.

---

## T1498 — Network Denial of Service

### Takeaway
T1498 has 2 sub-techniques (.001–.002) and maps to the Impact tactic.

### Cited Findings
- Name: **Network Denial of Service**, ID T1498 — [Source](https://attack.mitre.org/techniques/T1498/)
- Tactic: **Impact (TA0040)** — [Source](https://attack.mitre.org/techniques/T1498/)
- Description: adversaries "degrade or block the availability of targeted resources to users" — [Source](https://attack.mitre.org/techniques/T1498/)
- Full current sub-technique list (2):
  - T1498.001 — Direct Network Flood
  - T1498.002 — Reflection Amplification
  — [Source](https://attack.mitre.org/techniques/T1498/)

### Inferences
- None beyond base facts; this is a stable, small sub-technique set.

### Gaps
- None identified.
