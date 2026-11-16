# HTTP protocol auditor — research notes

These notes translate primary researcher and standards sources into a bounded
assessment workflow. They are methodology references, not a claim that every
implementation-specific variant has been tested or can be safely tested on a
shared live target.

## HTTP desynchronization

- James Kettle's [HTTP/1.1 must die: the desync endgame](https://portswigger.net/research/http1-must-die)
  documents parser-discrepancy detection, HTTP/2 downgrade risk, and many
  framing variants. The operational lesson is to identify disagreement across
  the actual proxy path and separate detection from impact validation.
- PortSwigger's [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
  is a maintained Burp extension for HTTP/1.1, HTTP/2 downgrade, and parser
  discrepancy analysis. Its attack features can alter shared connection state;
  use detection mode first and exploit confirmation only in an isolated lab.
- Kettle's [pipelining versus smuggling analysis](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling)
  explains a common false positive: ordinary keep-alive or pipelining can look
  like cross-request contamination. A result needs controls that separate
  these behaviors.
- Kettle's [HTTP Anomaly Rank](https://portswigger.net/research/introducing-http-anomaly-rank)
  describes ranking responses by stable attribute differences. Use anomaly
  scores to prioritize manual review; response uniqueness alone is not proof.
- RFC [9112](https://www.rfc-editor.org/rfc/rfc9112.html) defines HTTP/1.1
  message framing and parsing. RFC [9931](https://www.rfc-editor.org/rfc/rfc9931.html)
  (March 2026) updates RFC 9112 on security considerations for optimistic
  protocol transitions, including data sent before an upgrade is confirmed.
  These standards define parsing requirements; they do not establish that a
  particular proxy chain follows them consistently.
- Kettle's 2026 [HTTP Terminator research](https://portswigger.net/research/can-ai-do-novel-security-research)
  describes a broad research factory that generated novel desync vectors and
  also surfaced unrelated memory-leak behavior. The article stresses the need
  for a human discovery cascade and identifies HTTP Request Smuggler as the
  practical target-assessment tool. This skill does not direct an autonomous
  high-volume research harness at live websites.

## WebSocket security

- PortSwigger's [WebSocket Turbo Intruder research](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)
  shows that WebSocket messages expose authorization, race, parsing, and
  resource-exhaustion cases that ordinary HTTP request testing may miss. It
  also demonstrates why malformed frames and high concurrency need a lab.
- PortSwigger's [cross-site WebSocket hijacking guide](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)
  describes the cookie-authenticated handshake risk and two-way channel impact.
- [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) specifies the
  browser origin-based security model. Its security considerations warn that
  non-browser clients can forge `Origin`, so origin validation is not an
  authentication substitute.
- The [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
  covers origin allowlists, message validation, rate/size limits, session
  handling, and sensitive-data-safe logging.

## Evidence discipline

The workflow grades results as observation, stable parser-discrepancy lead,
lab-validated desynchronization, or lab-validated impact. It does not convert
unusual response codes, latency, or a scanner label into a confirmed finding.
The exact client/edge/origin protocol sequence and connection reuse context are
part of the evidence because a browser-visible HTTP version alone cannot prove
the upstream path.
