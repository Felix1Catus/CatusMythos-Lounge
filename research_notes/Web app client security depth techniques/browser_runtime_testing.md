# Browser runtime testing for client-side web security

Research snapshot: 2026-11-15. This note feeds
`skills/webapp-exploit-hunter/scripts/browser_security_auditor.py` and its
`SKILL.md` workflow. It uses public researcher material and official browser
testing guidance; the script remains a bounded assistant to manual review.

## Public sources

- PortSwigger, [Testing for DOM XSS using DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-xss), updated 2026-11-11. DOM Invader uses a canary to follow input into runtime sinks, then asks the tester to examine context and transformations. The browser auditor follows the same evidence order: insert a unique harmless execution marker, verify it ran in the browser, and preserve the source context for review. A reflection match alone is never reported as execution.
- PortSwigger, [Testing for DOM XSS using web messages](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages), updated 2026-11-11, and [Web message settings](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/settings/web-messages). These emphasize message `origin`, `source`, and `data`, testing origin validation, and checking whether message data reaches a sink. The auditor inventories observed inbound origins and outbound target origins without retaining message bodies; this is triage evidence, not proof of a vulnerable receiver.
- OWASP, [WSTG client-side testing](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/README/) covers DOM XSS, browser storage, WebSockets, and web messaging as distinct test areas. [Browser storage testing](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage/) calls out sensitive data stored client-side and the importance of reviewing how storage values are consumed.
- Microsoft Playwright, [Browser contexts](https://playwright.dev/python/docs/browser-contexts) documents isolated contexts for cookies and storage. [BrowserContext routing](https://playwright.dev/python/docs/api/class-browsercontext) warns that service-worker traffic can bypass ordinary routing and recommends blocking service workers for intercepted tests. [WebSocket routing](https://playwright.dev/python/docs/api/class-browsercontext) allows the auditor to close the browser socket without connecting upstream or forwarding frames.
- Playwright's [browser installation guide](https://playwright.dev/python/docs/browsers) notes that the package and browser binaries are installed separately and that browser downloads consume substantial disk space. The plugin bootstrap therefore installs the Python package, while Chromium installation is a one-time explicit command in the skill instructions.

## Testing implications

1. Static source-to-sink review and server-response reflection checks do not prove browser execution. Use a distinct marker and observe an execution side effect in a real browser context.
2. Test more than server-visible query inputs. Fragments and browser-side form values can reach runtime sources without appearing in the initial HTTP request.
3. Keep dynamic checks bounded: unique marker only; no `alert`, external callback, or data collection; no forms in passive mode; an explicit flag for forms; cap pages, requests, and submissions.
4. Treat form submission as potentially state-changing. Skip password forms and fields that look like credentials, tokens, or personal/payment data; require an explicit submission option; permit only the declared same-scope GET/POST action; never forward non-read methods or off-scope requests.
5. A browser context is a security boundary for session data. Load only storage-state entries that match the declared origin set, block service workers so request routing stays effective, omit values and full query strings from reports, and isolate cookies from the user's normal profile.
6. WebSocket endpoint presence and observed message origins/targets are context, not findings. This audit closes sockets before upstream connection and forwards no frames; use the manual protocol workflow for authorized handshake, authorization, and message-shape assessment.
7. Missing headers or cookie attributes and suspicious storage key names are informational observations. Verify whether a cookie is a session credential and inspect storage values locally in the browser before assigning impact; the report intentionally omits those values.

## Scope and known limits

The auditor does not click arbitrary controls, upload files, test password flows, forge cross-origin messages, or mutate arbitrary APIs. Active query/fragment probes test only the current page's existing non-sensitive parameters, or a short common-name set when none exist. Form probes test eligible text fields only. Client-side frameworks can require a user action or application state not reached by the bounded page load; absence of a finding is not evidence of safety. Use browser developer tools/DOM Invader for message replay, complex framework sources, stateful flows, and payload-context tailoring.
