---
name: web-protocol-auditor
description: Research-guided assessment of HTTP request parsing, proxy protocol transitions, request desynchronization indicators, and WebSocket security. Use when a web target uses reverse proxies, HTTP/2 or HTTP/3, protocol upgrades, or WebSocket endpoints. Authorized testing only.
license: MIT
compatibility: Claude Code; Burp Suite is optional for interactive protocol analysis
metadata:
  version: 1.0.0
  tags: web-security, http, request-smuggling, desync, websocket, protocol
---

# Web Protocol Auditor

Assess the boundaries where browsers, edge services, reverse proxies, WAFs,
application servers, and persistent WebSocket connections interpret the same
traffic. Use this skill alongside `webapp-exploit-hunter`, `web-cache-auditor`,
and `api-breaker` when the target's protocol path makes those tests relevant.

## Scope and safety

Confirm the exact hostnames, listener ports, test accounts, authorized protocol
tests, and request budget before sending active probes. HTTP desynchronization
tests can affect a shared connection pool and other users. Run exploit
confirmation only against an isolated staging stack or a lab that the operator
controls. On shared production infrastructure, keep work to architecture
review, passive observations, and non-desynchronizing checks expressly allowed
by the engagement rules. Do not send requests intended to poison another
user's response queue, steal credentials, or alter another user's request.

Record the test mode (`offline`, `passive`, `authorized-active`, or `simulation`)
and the scope evidence. If the approved rules do not clearly permit desync
probes, stop at the protocol inventory and request an explicit scope decision.

## Workflow

### 1. Map the protocol path

Use normal browser or proxy traffic and available configuration evidence to
record:

- Client-facing protocol and TLS ALPN result (HTTP/1.1, HTTP/2, or HTTP/3).
- Every known edge, CDN, WAF, load balancer, reverse proxy, service mesh, and
  origin hop, including protocol on each hop where the owner can confirm it.
- Whether any hop downgrades HTTP/2 or HTTP/3 to HTTP/1.1, and whether upstream
  connections are reused or multiplexed.
- WebSocket routes, handshake authentication, accepted origins, selected
  subprotocols/extensions, and whether HTTP/2 extended CONNECT (RFC 8441) is
  enabled.

Do not infer upstream HTTP/2 from a browser's HTTP/2 connection. Check the
upstream configuration or owner-provided telemetry. A protocol version observed
at one hop does not establish the protocol used by later hops.

### 2. Review HTTP message boundaries

Use PortSwigger's HTTP Request Smuggler in its detection mode for authorized
targets, or review the request path and parser configuration with the service
owner. Prefer its parser-discrepancy approach over a brittle payload checklist.
Keep the Burp history item, exact request, response sequence, tool version, and
relevant connection settings with each lead. HTTP/2 at the edge is not proof of
HTTP/2 end-to-end: a downgrade can expose a second framing interpretation.

Review the following boundary classes as applicable to the actual proxy chain:

- Conflicting or repeated message-length metadata and transfer coding.
- HTTP/2-to-HTTP/1 downgrade framing, including content-length disagreement.
- Requests whose body handling differs by method, missing or invalid lengths,
  header-name/whitespace normalization, and parser treatment of malformed
  lines.
- Optimistic protocol transitions such as `Upgrade` and `CONNECT`, including
  data sent before the transition is accepted (RFC 9931 updates RFC 9112 on
  this case).
- Connection reuse, early responses, interim `1xx` responses, and response
  parsing tied to the preceding request.

Do not hand-build a production exploit from a scanner lead. Use this evidence
ladder:

1. **Observation:** one response differs. Record it without calling it a bug.
2. **Parser-discrepancy lead:** repeated control and variant requests produce
   a stable, request-specific difference that supports two interpretations.
3. **Desync validated in a lab:** an isolated, owner-controlled backend shows a
   request-boundary shift using harmless marker routes and synthetic accounts.
4. **Impact validated:** only in that isolated lab, the shifted request reaches
   a controlled route and demonstrates the security consequence without
   involving a real user or real secret.

Compare like-for-like controls, keep each probe's connection behavior explicit,
and distinguish ordinary HTTP keep-alive/pipelining from cross-request
contamination. A status-code or latency change by itself is not confirmation.
When scanner output is noisy, compare stable response properties across a
control set (status, headers, body shape, and connection behavior); treat
anomaly ranking as triage, not a vulnerability verdict.

### 3. Review WebSocket security

For each `ws:`/`wss:` or HTTP/2 extended-CONNECT endpoint, review the handshake
and the message protocol separately:

- **Handshake and origin:** test an expected origin, an unrelated origin, and
  the `null` origin where applicable. Confirm an explicit allowlist. The
  `Origin` header is meaningful for browsers; a direct client can forge it, so
  origin checks do not replace authentication.
- **Authentication and lifecycle:** confirm unauthenticated connections fail;
  credentials expire and logout/revocation take effect on an already-open
  connection; reconnects cannot restore revoked privilege; and session
  cookies are not the only protection for browser-originated state-changing
  messages.
- **Cross-site WebSocket hijacking:** assess only in an owner-controlled
  browser/session. The risk requires a browser to attach ambient credentials,
  the server to accept an untrusted origin, and useful authenticated messages
  to be readable or actionable. Document all three conditions.
- **Per-message authorization:** replay representative read and write message
  types with two test users/tenants. Change object IDs, tenant IDs, roles,
  subscriptions, and operation names. Verify the server checks authorization
  for every message, not only at connection setup.
- **Input and resource limits:** check message schema/type validation,
  oversized text and binary frames, malformed JSON/protobuf-like messages,
  compression negotiation, connection limits, idle timeouts, message rates,
  and close/error handling. Use low-volume boundary cases; stress and
  concurrency testing belongs in an isolated environment with an agreed cap.
- **State and races:** in a lab, test duplicate/replayed messages, reconnects,
  simultaneous operations, and out-of-order updates against disposable test
  records. Keep concurrent connections low and bounded.
- **Logging and privacy:** verify connection, authz, validation, throttling, and
  termination events are observable while tokens and full sensitive message
  bodies are redacted.

Use Burp's WebSocket history/editor for manual inspection. Use WebSocket Turbo
Intruder or another message-fuzzing client only when the scope and environment
allow it; its high-concurrency modes and malformed-frame capabilities can
exhaust memory or destabilize a server. Do not use these modes on shared
production infrastructure.

### 4. Report and recommend

For every result, include the client-to-origin protocol map, endpoint, test
mode, sanitized request/response references, tool/version, control comparison,
reproducibility, confidence level, and impact that was actually validated.
Keep parser discrepancy, desynchronization, and security impact as separate
claims. A banner or HTTP/2 frontend alone is architecture evidence, not a
vulnerability.

For remediation, recommend strict and consistent message parsing across every
hop, supported software, rejection of ambiguous requests, explicit method/body
allow-lists, and HTTP/2 or later for proxy-to-origin connections where
supported. For WebSockets, recommend explicit Origin allowlists, message-level
authorization, bounded payloads/rates/connections, session-revocation handling,
and structured logs that redact credentials.

Use `research_notes/HTTP protocol auditor depth techniques/` for source notes,
false-positive handling, and the evidence model.
