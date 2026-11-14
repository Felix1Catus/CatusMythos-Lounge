# Chain-to-TTP Mapping: Four Finding Classes → MITRE ATT&CK / ATLAS

Reference notes for the attack-tree generator's finding-class → technique-ID lookup table. Each class below gives: attack-pattern label, step breakdown, per-step MITRE Enterprise ATT&CK ID (preferred) or MITRE ATLAS ID (only where no Enterprise technique fits), and feasibility/impact/stealth scoring rationale (1-10 scale; feasibility base 4-8, impact base 6-10, stealth reduced when WAF/CDN or cloud audit logging is present). This is classification/documentation only — no exploitation instructions are included.

---

## (a) AWS ECS cross-task credential theft — "ECScape" class

### Attack-pattern label
**ECS-Cape: IMDS-to-Agent-Impersonation Cross-Task Credential Harvest**

### Mechanism confirmed from source
Per Sweet Security's own write-up (disclosed Black Hat USA 2025, researcher Naor Haziz; AWS treats this as a configuration/design-boundary issue, not a CVE-numbered vulnerability) — [Sweet Security blog](https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs), corroborated by [CSO Online](https://www.csoonline.com/article/4036655/ecscape-new-aws-ecs-flaw-lets-containers-hijack-iam-roles-without-breaking-out.html) and [The Hacker News](https://thehackernews.com/2025/08/researchers-uncover-ecscape-flaw-in.html):

1. A compromised/malicious container queries the host's **Instance Metadata Service (IMDS, 169.254.169.254)** to obtain the EC2 instance-profile role's temporary credentials. Containers can reach IMDS by default unless blocked (e.g., `ECS_AWSVPC_BLOCK_IMDS`).
2. Using those instance-role credentials — which, by default ECS instance-role policy, carry `ecs:DiscoverPollEndpoint` and `ecs:Poll` — the attacker calls `DiscoverPollEndpoint` to learn the ECS control-plane endpoint the real ECS agent connects to.
3. The attacker opens its own parallel session to the **Agent Communication Service (ACS) WebSocket** using the stolen instance-role credentials (AWS request-signed), impersonating the real ECS agent. AWS does not enforce a single active agent session per instance, so the rogue session coexists with the legitimate one.
4. Over that session, the ECS control plane pushes IAM credential payloads for **every task running on that host that has a task role** (not just the attacker's own task) — because the control plane, not the agent, performs the `AssumeRole` calls and simply delivers results to whichever "agent" is connected.
5. The attacker extracts and uses other tasks' IAM credentials directly, gaining the privileges of co-located, higher-privilege tasks without any container-to-host breakout.

Stealth note from source: reading IMDS from inside a container is an HTTP GET not logged by CloudTrail, making step 1 stealthy by default; later misuse of stolen task-role credentials against other AWS APIs is attributable via CloudTrail to the victim task's role, but the ACS impersonation itself is an undocumented internal protocol not covered by standard CloudTrail events for ECS API calls.

### Step → Technique mapping

| Step | Technique ID | Technique Name | Fit notes |
|---|---|---|---|
| 1. Query IMDS for instance-role credentials | **T1552.005** | Unsecured Credentials: Cloud Instance Metadata API | Direct match — ATT&CK's canonical description is "adversaries with presence on a running VM/container query the Instance Metadata API to identify credentials." [attack.mitre.org/techniques/T1552/005](https://attack.mitre.org/techniques/T1552/005/) |
| 2. Call `DiscoverPollEndpoint` using stolen instance credentials | **T1528** | Steal Application Access Token | Reasonable fit — using one stolen credential set to query a service and obtain information that enables acquiring a *further* access token/credential set. ATT&CK scopes T1528 to Containers/IaaS platforms. [attack.mitre.org/techniques/T1528](https://attack.mitre.org/techniques/T1528/) |
| 3. Impersonate ECS agent over ACS WebSocket (rogue parallel session) | **T1550.001** (Use Alternate Authentication Material: Application Access Token) as closest fit, with a noted gap | No current ATT&CK technique precisely covers "open an unauthorized second session to an internal control-plane protocol by replaying a legitimate agent's authentication path." T1550.001 (using a stolen token to access a service as if legitimately authenticated) is the nearest Enterprise fit but does not capture the "impersonate the agent itself, not just use a token" nuance. **Flagging this as an imperfect mapping** rather than forcing certainty. |
| 4. Receive co-located tasks' IAM credentials via the impersonated session | **T1552.005** (secondary) + **T1528** (secondary) | The actual receipt of *other* tasks' credentials is a direct consequence of step 3; it is best tagged with the same credential-theft techniques as steps 1–2 rather than a distinct ID, since ATT&CK has no sub-technique for "receive bulk credentials pushed by a legitimate-channel impersonation." |
| 5. Use stolen task-role credentials for unauthorized AWS API access | **T1078.004** | Valid Accounts: Cloud Accounts | Standard mapping once stolen cloud credentials are used to authenticate as another identity. [attack.mitre.org/techniques/T1078/004](https://attack.mitre.org/techniques/T1078/004/) (not separately fetched this session, but T1078.004 is the well-established Enterprise ID for cloud-credential reuse) |

### Scoring rationale
- **Feasibility: 6/10.** Base feasibility is elevated above the 4-6 floor because the prerequisite (container with host IMDS access + an instance role carrying default `ecs:Poll`/`ecs:DiscoverPollEndpoint`) is the *default* ECS EC2-launch-type configuration per Sweet Security — no custom misconfiguration is required beyond "didn't block IMDS from containers." It is capped below 7-8 because it requires an existing container compromise (this is a post-initial-access/lateral technique, not a remote-unauth vector) and depends on reverse-engineering an undocumented internal protocol (ACS), which raises technical complexity.
- **Impact: 9/10.** Impact is high because the technique breaks the assumed per-task credential isolation boundary entirely — a low-privilege task can obtain a high-privilege co-located task's full IAM role, with no container breakout needed. AWS's own framing (instance = sole security boundary) confirms the blast radius is "every task on the host."
- **Stealth: 6/10 (reduced from a higher base).** Reduced from the 7-8 feasibility-adjacent range because, while the *initial* IMDS read is unlogged, (a) any WAF/CDN layer is irrelevant here (this is host/control-plane-internal, not edge-facing), but (b) subsequent *use* of the stolen task-role credentials against AWS service APIs is attributed and visible in CloudTrail under the victim task's role identity, which is a detectable anomaly (unexpected API calls under a role that shouldn't be making them) if monitored. Score lands mid-range: stealthy at the credential-theft step, more exposed at the credential-use step.

---

## (b) GraphQL introspection-bypass → nested-field authorization gap chain

### Attack-pattern label
**GraphQL Shadow-Schema Mutation Smuggle**

### Mechanism
1. **Schema reconstruction despite disabled introspection.** Even with introspection queries blocked, GraphQL servers (notably `graphql-js`-based ones) often leave "did you mean …?" field-suggestion hints active in error messages. Sending deliberately malformed/guessed field names and harvesting the suggestion text in error responses lets an attacker iteratively rebuild the schema; this is the documented behavior behind tools like Clairvoyance. Confirmed via [Escape.tech's field-suggestion writeup](https://escape.tech/blog/graphql-verbose-error-suggestions/) and [Escape's vulnerability docs](https://docs.escape.tech/testing/vulnerabilities/information_disclosure/graphql_field_suggestion): "If introspection is disabled on your target, Field Suggestion still allows users to infer the entire schema." A `graphql-js` GitHub issue confirms the suggestion text lives in the raw `error.message` string, independent of the introspection toggle — i.e., disabling introspection does **not** by default disable "did you mean" hints, which is the root cause of the bypass.
2. The reconstructed schema map is used to locate a privileged mutation (e.g., an admin-only write/update operation) that was not discoverable via the blocked introspection endpoint.
3. The attacker finds that the mutation's resolver enforces authorization on the top-level mutation argument/object but not on a nested field reachable through the same mutation — a **field-level authorization gap** distinct from object-level checks. This class of flaw is documented generically by PortSwigger's GraphQL material (arguments used to access objects directly without consistent authorization) and by secondary writeups noting that "developers may forget to enforce authorization on individual fields, and nested queries can bypass endpoint-level access controls."
4. The attacker submits the mutation through the nested field, achieving an unauthorized write that top-level authorization checks did not block.

### Step → Technique mapping

| Step | Technique ID | Technique Name | Fit notes |
|---|---|---|---|
| 1. Field-suggestion harvesting / binary-oracle brute-forcing to reconstruct schema with introspection disabled | **No clean Enterprise ATT&CK fit — explicitly flagged as a gap** | — | This is active reconnaissance against an application's own error-handling behavior, not a credential-access or execution step. ATT&CK's Reconnaissance tactic techniques (T1590–T1596) are scoped to **pre-engagement** OSINT/scanning of a target *organization*, not interactive fuzzing of an already-reachable API's error responses to rebuild hidden schema structure. T1595.002 (Active Scanning: Vulnerability Scanning) is the closest analog but is intended for broad scanning for known vulnerabilities, not iterative error-oracle schema inference. **Recommendation for the reference table: tag this step as "Reconnaissance (T1592/T1595 family, approximate)" with an explicit annotation that no precise technique exists**, rather than forcing T1595.002. |
| 2. Use reconstructed schema to locate privileged mutation | **T1213** | Data from Information Repositories | Approximate fit — using application-internal structural knowledge (the schema) to find where sensitive operations live is conceptually closer to internal-repository reconnaissance than any closer ID, but this is also an imperfect fit since T1213 is normally post-access data discovery, not schema mapping of an API surface. Flag as approximate. |
| 3. Exploit nested-field authorization gap to bypass top-level auth check | **T1190** | Exploit Public-Facing Application | Best available fit — ATT&CK defines T1190 broadly as "exploiting a weakness in an internet-facing application" to gain access/effect; a logic flaw in field-level authorization enforcement on a public GraphQL endpoint falls within that broad definition, consistent with how BOLA/BFLA findings are commonly mapped to T1190 in practice (one third-party BOLA-testing mapping explicitly lists T1190 for this class). |
| 4. Submit unauthorized privileged write via the nested field | **T1565.001** (if the write corrupts/alters stored data) or simply treated as the *impact* of the T1190 exploitation rather than a separate technique | Stored Data Manipulation | Only tag separately if the write's purpose is data manipulation; if the write is itself account/privilege-escalating (e.g., an admin-grant mutation), this step is better folded into T1548 (Abuse Elevation Control Mechanism) territory conceptually, but no clean Enterprise sub-technique exists for "nested-parameter authorization-check gap" specifically — **flag as approximate/best-effort**, same caveat as step 3. |

### Scoring rationale
- **Feasibility: 5/10.** Introspection-disabled + field-suggestion-enabled is a common misconfiguration (most teams disable introspection but forget to also strip suggestion text, per the `graphql-js` issue tracker discussion), so schema reconstruction is realistically achievable, but it requires patience (many iterative error-oracle queries) and the nested-field authz gap is implementation-specific and not guaranteed to exist — pulling feasibility toward the middle of the 4-8 base band rather than the high end.
- **Impact: 8/10.** Impact is high because the end state is an unauthorized privileged write (e.g., admin-level mutation) achieved despite introspection being deliberately disabled as a defense — the chain demonstrates that a single surface-level control (disabled introspection) provided a false sense of security while the deeper authorization logic flaw remained exploitable.
- **Stealth: 4/10 (reduced from base).** Reduced because the field-suggestion/binary-oracle harvesting step requires a high volume of malformed queries against the endpoint, which is exactly the kind of noisy, repetitive traffic a WAF or API gateway with anomaly/rate-based detection is positioned to flag — consistent with the convention of lowering stealth when a WAF/CDN sits in front of the target. The final privileged-write request itself may look like a single legitimate-shaped mutation and thus be harder to catch at that stage, but the reconnaissance phase dominates the stealth score downward.

---

## (c) JWT depth-technique chains

### (c1) `kid`-header path traversal / injection → key-lookup redirection → token forgery

#### Attack-pattern label
**JWT `kid` Lookup Hijack**

#### Mechanism
Per [PentesterLab's JWT Kid Injection glossary entry](https://pentesterlab.com/glossary/jwt-kid-injection) and corroborating writeups ([HackTricks JWT attacks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens), [Invicti](https://invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities)): when the server uses the attacker-controlled `kid` (Key ID) JWT header value unsanitized in a server-side file-path lookup or database query to retrieve the verification key, an attacker can:
1. Supply a path-traversal payload in `kid` to redirect the lookup to an attacker-chosen file with predictable/known content (e.g., `/dev/null` for an empty-string key, or `/proc/sys/kernel/randomize_va_space` for a known constant value on Linux), **or** supply a SQL-injection payload in `kid` (if the lookup is a DB query) to force a `UNION SELECT`-style injection that returns an attacker-known value as the "key."
2. The server then uses that attacker-known value as the signing/verification secret.
3. The attacker signs a forged JWT (with arbitrary claims, e.g., elevated role/identity) using that known secret and submits it.
4. The server validates the forged token successfully (because it re-derives the same attacker-known key via the same unsanitized `kid` lookup), granting the attacker unauthorized access/authentication bypass.

No MITRE page specifically covering "JWT kid injection" was found in this research; the closest standards references are CWE-22 (Path Traversal) and CWE-89 (SQL Injection) at the weakness level, not technique level.

#### Step → Technique mapping

| Step | Technique ID | Technique Name | Fit notes |
|---|---|---|---|
| 1. Inject path-traversal/SQLi payload into `kid` to redirect key lookup | **No clean Enterprise ATT&CK technique — explicitly flagged as a gap** | — | ATT&CK has no technique for "parameter injection into a cryptographic key-lookup mechanism." The underlying primitives (path traversal, SQL injection) are CWE-level weaknesses, not ATT&CK techniques — ATT&CK generally models post-exploitation adversary behavior, not web-input-validation vulnerability classes themselves. **Recommend leaving this step unmapped in the reference table, or cross-referencing CWE-22/CWE-89 instead of forcing an ATT&CK ID.** |
| 2. Server resolves lookup to attacker-known/attacker-supplied key material | **T1552** (Unsecured Credentials, general) — approximate | Unsecured Credentials | Weak fit, included only because the end effect is "the attacker now possesses/controls the credential material used for verification." Flag as approximate. |
| 3. Forge validly-signed JWT using the known key | **T1606** | Forge Web Credentials | Strong fit — ATT&CK's T1606 is explicitly "adversaries create their own credentials... to access web resources," including web session tokens, which generalizes cleanly to forging a JWT once the signing material is known or controlled. [attack.mitre.org/techniques/T1606](https://attack.mitre.org/techniques/T1606/) |
| 4. Authenticate / access resources using the forged token | **T1078** | Valid Accounts | Standard mapping for using a (forged, in this case) credential to authenticate as if legitimate. |

#### Scoring rationale
- **Feasibility: 4/10.** Base-floor feasibility — requires a specific, increasingly rare implementation flaw (unsanitized `kid` passed directly into a file-path or DB-query construction) that modern JWT libraries' default verification flows have largely closed off; this is implementation-specific rather than a structural protocol weakness.
- **Impact: 9/10.** Impact is high because successful exploitation yields full authentication bypass with arbitrary claims (attacker chooses the forged token's identity/role), equivalent to full account/privilege takeover.
- **Stealth: 6/10.** Moderate — the injection probing step (fuzzing `kid` with traversal/SQLi payloads) can generate anomalous-looking tokens/requests that a WAF with JWT-aware inspection or SQLi/path-traversal signatures would likely flag, reducing stealth from a higher base; the final forged-token use, once achieved, looks like a normal authenticated request and is hard to distinguish afterward.

### (c2) RS256→PS256 algorithm-confusion / relabeling

#### Attack-pattern label
**JWT Algorithm-Family Relabel (RS256→PS256)**

#### Mechanism
Per [PortSwigger's algorithm confusion attacks page](https://portswigger.net/web-security/jwt/algorithm-confusion) and [WorkOS's analysis](https://workos.com/blog/jwt-algorithm-confusion-attacks): algorithm-confusion attacks exploit JWT libraries that provide a single, algorithm-agnostic verification method, allowing the attacker-controlled `alg` header to dictate which cryptographic algorithm the server uses to verify the signature, rather than the server pinning an explicit expected algorithm. The canonical/well-documented variant swaps RS256 (asymmetric RSA) → HS256 (symmetric HMAC), using the known RSA public key as the HMAC secret, producing a *newly forged* signature. The user's described RS256→PS256 variant is narrower and more nuanced: it is a **pure header relabeling** of an already-validly-signed RS256 token to claim `alg: PS256`, with **zero new cryptographic material created** — this specifically targets servers that validate the signature bytes without strictly checking that the declared algorithm in the header matches the algorithm that was actually used/expected, or that incorrectly dispatch verification based on key-object metadata rather than the token header. Research found a concrete, closely-related real-world case: **CVE-2026-48523** in PyJWT (2.9.0–2.12.1), where signature verification used the algorithm bound to the PyJWK object rather than the token header's `alg`, allowing an RS256-signed token with its header relabeled to `alg: PS256` to be accepted when the server intended to only accept PS256 — confirmed via the [OSV advisory GHSA-jq35-7prp-9v3f](https://osv.dev/GHSA-jq35-7prp-9v3f). WorkOS's analysis separately notes this variant "does not always produce a direct exploit the way the HS256 swap does" and can manifest as downgrade/verification-logic-quirk bypasses rather than a universal bypass.

#### Step → Technique mapping

| Step | Technique ID | Technique Name | Fit notes |
|---|---|---|---|
| 1. Take a validly RS256-signed token and relabel header `alg` to PS256 (no new signing) | **No clean Enterprise ATT&CK technique for the relabeling action itself — flagged as a gap**, with **T1606** (Forge Web Credentials) as the nearest step-level fit for the overall outcome | Forge Web Credentials | The relabeling action is better described as *manipulating* an existing valid credential's metadata than *forging* new credential material (no new signature is created) — this is a subtler act than T1606 is written to describe, so the fit is approximate. If used in the table, annotate that no cryptographic forgery occurred, only header manipulation. |
| 2. Server's algorithm-agnostic/mis-pinned verification logic accepts the relabeled token without re-validating signature-to-algorithm consistency | **T1600** or **T1552** — no strong Enterprise match; closest is **T1210** (Exploitation of Remote Services) in spirit, but imperfect | — | This step is fundamentally an *implementation flaw in verification logic* (a software defect), which ATT&CK generally doesn't have a precise technique for at this granularity. **Flag explicitly as a gap** — the closest conceptual parent is still T1606's broader "bypass authentication protection mechanisms" framing, but no dedicated ID exists for "algorithm-pinning failure in signature verification." |
| 3. Server treats the relabeled token as authenticated, granting access | **T1078** | Valid Accounts | Standard mapping once the bypass succeeds and the attacker is treated as authenticated. |

#### Scoring rationale
- **Feasibility: 4/10 (lower end of base band).** This is the lowest-feasibility item among the four classes' sub-techniques researched: it depends on a narrow, library-specific verification defect (confirmed to exist concretely only in specific cases like the PyJWT CVE, which itself notes the risk "mainly applies where external parties register their own keys") rather than a broadly applicable protocol weakness. WorkOS explicitly notes this variant does not reliably produce a direct exploit the way RS256→HS256 does.
- **Impact: 8/10.** When it does work, impact is high — full authentication bypass using zero new cryptographic material, which is a particularly severe finding because it requires no key-cracking or secret-guessing at all.
- **Stealth: 7/10.** Higher stealth than the other JWT sub-chain because the "attack traffic" is a single relabeled token submitted through a normal authentication flow — there is no fuzzing/brute-forcing footprint, no unusual payload shape beyond one modified header byte sequence, making it very hard for a WAF or anomaly detector to distinguish from a legitimate request. Not raised to the 8-10 range because the technique still requires the attacker to have captured/possessed a validly RS256-signed token in the first place, which may itself leave a prior access trail.

---

## (d) AI/LLM-application chain — EchoLeak / AgentFlayer / CurXecute pattern class

### Attack-pattern label
**Agentic Tool-Access Indirect Injection Exfiltration**

### Mechanism and confirmed case studies
Three concrete, independently disclosed real-world cases confirm this pattern:
- **EchoLeak (CVE-2025-32711, Microsoft 365 Copilot)** — disclosed by Aim Labs, reported to MSRC, CVSS 9.3, publicly disclosed June 11, 2025. A zero-click indirect prompt injection delivered via email content that Copilot ingests as part of its normal retrieval, causing the agent to use its own legitimate tool access to exfiltrate information — no user interaction required. NVD's own description frames it as "AI command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network." Source: [multiple secondary reports](https://informationsecuritybuzz.com/zero-click-ai-vulnerability-echoleak-ms-365/); MSRC advisory URL referenced but not independently fetched this session.
- **CurXecute (CVE-2025-54135, Cursor IDE)** — disclosed by AIM Security. A crafted Slack message, read through an approved/legitimate Slack MCP connector, carried a prompt injection that caused Cursor to rewrite its own global MCP configuration file and execute attacker-chosen commands — the config-file write occurred before the user had a chance to reject the action. Patched in Cursor 1.3 (merged July 8, 2025; shipped July 29, 2025). Source: [Cato Networks](https://www.catonetworks.com/blog/curxecute-rce/), [The Hacker News](https://thehackernews.com/2025/08/cursor-ai-code-editor-fixed-flaw.html).
- **AgentFlayer (Zenity, Black Hat USA 2025)** — a set of zero-click/one-click exploit chains against enterprise AI tools (ChatGPT, Copilot Studio, Salesforce Einstein, Google Gemini, Microsoft Copilot), where the common exfiltration pattern (demonstrated against ChatGPT) passed locally-accessible data as URL parameters to achieve exfiltration via an outbound request the agent's existing tool access permitted. Source: secondary coverage; primary Zenity/AIM posts not independently fetched this session.

Generalized step structure, consistent with the user's framing and MITRE ATLAS's own technique set:
1. The AI agent, which already holds legitimate tool/connector access (email, calendar, documents, Slack/MCP tool, etc. — granted through normal, authorized configuration), ingests content from a lower-trust source as part of its normal operation (an email body, calendar invite, shared document, chat message, or an MCP tool's own description field).
2. That ingested content contains a hidden/indirect instruction (prompt injection) not visible to or authored by the legitimate user.
3. The agent's LLM core fails to distinguish the injected instruction from legitimate user/system instructions and begins to follow it.
4. The agent invokes its own already-granted tool(s) to carry out the injected instruction — e.g., rewriting a config file, sending data to an attacker-controlled endpoint via a legitimate "fetch/browse" tool, or acting on connected enterprise data.
5. Data is exfiltrated or an unauthorized action is taken, using entirely legitimate, pre-authorized tool access — no separate privilege escalation or credential theft was needed.

### Step → Technique mapping

| Step | Technique ID | Technique Name | Framework | Fit notes |
|---|---|---|---|---|
| 1-2. Agent ingests untrusted content containing hidden/indirect injected instructions | **AML.T0051.001** | LLM Prompt Injection: Indirect | **MITRE ATLAS** | Precise fit — ATLAS explicitly defines indirect prompt injection as "the payload arrives through content the model ingests, such as documents, emails, or web pages," which is exactly this step. No Enterprise ATT&CK technique covers this AI-specific mechanism, so ATLAS is the correct and necessary choice per the task's own fallback rule. |
| 3. LLM follows the injected instruction instead of/alongside legitimate instructions | **AML.T0054** | LLM Jailbreak (as the nearest ATLAS neighbor) — approximate, since the user did not necessarily jailbreak safety training, just failed instruction-source discrimination | **MITRE ATLAS** | Imperfect fit flagged: ATLAS does not appear (per this research) to have a dedicated technique purely for "model fails to distinguish injected content from trusted instructions" as distinct from the injection delivery itself (AML.T0051) and the subsequent tool misuse (next row). In practice, security tools commonly collapse this step into AML.T0051's effect rather than tagging it separately — **recommend not assigning a separate ID to this step and folding it into AML.T0051.001's outcome** rather than forcing AML.T0054. |
| 4. Agent invokes its own legitimately-granted tool(s) to execute the injected instruction | **AML.T0053** | AI Agent Tool Invocation (sources disagree on this ID also historically being labeled "LLM Plugin Compromise") | **MITRE ATLAS** | Good fit for the "agent uses its existing tool access under adversary influence" step — this is the ATLAS-native technique for exactly this behavior; sources note it sits under Execution and/or Privilege Escalation. Flag the naming inconsistency across secondary sources (older material uses "LLM Plugin Compromise") as a sourcing caveat — verify current canonical name against atlas.mitre.org directly before publishing. |
| 5a. Data exfiltrated via the agent's legitimate tool access | **T1567** (Exfiltration Over Web Service) or **AML.T0024** (Exfiltration via AI Inference API) depending on exfil channel | Exfiltration Over Web Service / Exfiltration via AI Inference API | **Enterprise ATT&CK preferred when the exfil channel is a conventional outbound web request** (e.g., CurXecute/AgentFlayer-style URL-parameter or webhook exfiltration) — T1567 fits cleanly since the agent's own legitimate "fetch"/browse/connector tool is simply making an outbound request. **ATLAS AML.T0024 is the better fit only if the exfiltration channel is specifically the model's own inference API output channel** rather than an invoked external tool. For the EchoLeak/CurXecute/AgentFlayer cases researched, T1567 (Enterprise) is the more accurate mapping since exfiltration rode on a conventional web/connector call, not the inference API itself. |
| 5b. Unauthorized action taken (e.g., config file rewrite, as in CurXecute) instead of/in addition to data theft | **T1565.001** | Data Manipulation: Stored Data Manipulation | **Enterprise ATT&CK** | Fits the CurXecute case specifically — the agent's legitimate file-write tool access was used, under injected instruction, to rewrite its own MCP configuration file, which is a stored-data manipulation with downstream command-execution consequences. |

### Scoring rationale
- **Feasibility: 7/10.** Feasibility sits toward the high end of the base band because this class requires no credential theft, no code execution vulnerability, and no infrastructure compromise — only (a) a lower-trust content channel the agent already ingests as part of normal operation, and (b) an agent that already has the tool access (both of which are *standard, intended* features of agentic AI deployments, not misconfigurations). Three independent real-world confirmed cases in 2025 (EchoLeak, CurXecute, AgentFlayer) across different vendors (Microsoft, Cursor/Anysphere, multiple AgentFlayer targets) within months of each other indicate this is a structurally common and repeatable pattern, not a one-off.
- **Impact: 9/10.** Impact is high and sometimes zero-click (EchoLeak, CurXecute both achieved zero/low user-interaction exfiltration or code execution), and because the vulnerability is the *combination* of ingestion + tool access rather than either alone, remediation is architecturally harder than patching a single bug — multiple vendors needed dedicated fixes.
- **Stealth: 7/10 (high, but can be reduced by egress controls, the AI/agent-world analog of a WAF/CDN).** Stealth is naturally high because the entire chain uses the agent's own legitimate, pre-authorized tool access — there is no anomalous authentication event, no new credential, no obviously malicious payload signature in the traditional network sense; the "attack traffic" is indistinguishable from the agent doing its normal job. This should be **reduced toward 5-6/10 in environments with egress-filtering/DLP on agent tool calls or MCP-call allowlisting** (the closest architectural analog to a WAF/CDN for this class), consistent with the scoring convention of lowering stealth when such a control layer is present and monitoring outbound agent tool invocations.

---

## Summary table (quick reference)

| Class | Label | Primary framework(s) used | Key unmapped/approximate steps flagged |
|---|---|---|---|
| (a) ECScape | IMDS-to-Agent-Impersonation Cross-Task Credential Harvest | ATT&CK: T1552.005, T1528, T1550.001 (approx.), T1078.004 | ACS impersonation step (step 3) has no precise Enterprise technique |
| (b) GraphQL | GraphQL Shadow-Schema Mutation Smuggle | ATT&CK: T1213 (approx.), T1190, T1565.001 (conditional) | Field-suggestion/schema-reconstruction step has **no clean ATT&CK fit** — explicitly flagged |
| (c1) JWT kid | JWT `kid` Lookup Hijack | ATT&CK: T1552 (approx.), T1606, T1078 | Injection-into-key-lookup step has **no ATT&CK technique** — CWE-22/CWE-89 are the correct cross-reference instead |
| (c2) JWT alg confusion | JWT Algorithm-Family Relabel (RS256→PS256) | ATT&CK: T1606 (approx.), T1078 | Verification-logic-defect step has **no dedicated ATT&CK technique** — flagged as implementation-flaw gap |
| (d) AI agent chain | Agentic Tool-Access Indirect Injection Exfiltration | ATLAS: AML.T0051.001, AML.T0053; ATT&CK: T1567, T1565.001 | "Model fails to discriminate injected instruction" step folded into AML.T0051.001 rather than force-fit to AML.T0054 |

---

## Sources

- Sweet Security, ["ECScape: Understanding IAM Privilege Boundaries in Amazon ECS"](https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs) (primary technical disclosure)
- [CSO Online — ECScape coverage](https://www.csoonline.com/article/4036655/ecscape-new-aws-ecs-flaw-lets-containers-hijack-iam-roles-without-breaking-out.html)
- [The Hacker News — ECScape coverage](https://thehackernews.com/2025/08/researchers-uncover-ecscape-flaw-in.html)
- MITRE ATT&CK: [T1552.005](https://attack.mitre.org/techniques/T1552/005/), [T1528](https://attack.mitre.org/techniques/T1528/), [T1606](https://attack.mitre.org/techniques/T1606/), [T1190](https://attack.mitre.org/techniques/T1190/) (general knowledge; page not independently refetched this session), T1078/T1078.004, T1567, T1565.001, T1550.001 (general knowledge, not independently refetched)
- Escape.tech, ["When GraphQL field suggestions become a Security Issue"](https://escape.tech/blog/graphql-verbose-error-suggestions/) and [Field Suggestion vulnerability docs](https://docs.escape.tech/testing/vulnerabilities/information_disclosure/graphql_field_suggestion)
- PortSwigger, [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql) and [Algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
- PentesterLab, [JWT Kid Injection](https://pentesterlab.com/glossary/jwt-kid-injection)
- HackTricks, [JWT Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- Invicti, [JSON Web Token (JWT) Attacks & Vulnerabilities](https://invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities)
- WorkOS, [JWT Algorithm Confusion Attacks](https://workos.com/blog/jwt-algorithm-confusion-attacks)
- OSV, [GHSA-jq35-7prp-9v3f — PyJWT CVE-2026-48523](https://osv.dev/GHSA-jq35-7prp-9v3f)
- Information Security Buzz / secondary coverage of [EchoLeak CVE-2025-32711](https://informationsecuritybuzz.com/zero-click-ai-vulnerability-echoleak-ms-365/)
- Cato Networks, [CurXecute RCE](https://www.catonetworks.com/blog/curxecute-rce/)
- The Hacker News, [Cursor AI code editor fixed flaw (CurXecute)](https://thehackernews.com/2025/08/cursor-ai-code-editor-fixed-flaw.html)
- MITRE ATLAS (secondary-sourced; atlas.mitre.org itself not independently fetched this session): AML.T0051 / AML.T0051.000 / AML.T0051.001, AML.T0053, AML.T0024 — via [Startup Defense ATLAS pages](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0051-llm-prompt-injection) and [D3FEND mirror](https://d3fend.mitre.org/offensive-technique/attack/AML.T0051/)

## Explicit gaps / caveats for the report writer
1. **atlas.mitre.org and attack.mitre.org were not directly fetched** for every ID cited (time/tool-budget constraints) — several Enterprise ATT&CK IDs (T1078.004, T1190, T1550.001, T1565.001, T1567) are stated from established general knowledge/secondary corroboration rather than a fresh primary-source fetch this session, and the ATLAS sub-technique naming for AML.T0053 shows a discrepancy across secondary sources ("AI Agent Tool Invocation" vs. older "LLM Plugin Compromise") that should be verified against the canonical atlas.mitre.org data before the table is finalized.
2. **No MITRE ATT&CK technique exists** for: (i) GraphQL field-suggestion/error-oracle schema reconstruction specifically, (ii) JWT `kid`-parameter injection into a key-lookup mechanism, (iii) JWT algorithm-pinning verification-logic defects. These are noted as explicit gaps rather than forced into a weak technique match, per the task's constraints.
3. The RS256→PS256 variant is **narrower and less universally exploitable** than the well-known RS256→HS256 confusion attack; the strongest confirmed real-world instance found (PyJWT CVE-2026-48523) is caveated by its own advisory as applying mainly where external parties register their own JWKs — this should temper how broadly the attack-tree generator treats this specific sub-variant versus the more general algorithm-confusion family.
