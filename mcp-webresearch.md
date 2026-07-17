https://github.com/mzxrai/mcp-webresearch - "This repository was archived by the owner on Feb 13, 2025. It is now read-only."

## Finding: SSRF via visit_page: only the URL protocol is validated, no internal-IP filtering

Package: @mzxrai/mcp-webresearch (npm)

Affected Versions: confirmed on 0.1.7 (latest)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N

CWE: CWE-918 Server-Side Request Forgery

### Summary
The visit_page tool loads a caller-supplied URL in a Playwright browser and returns the page content. The only validation is a protocol check (http/https); there is no filtering of loopback, link-local/cloud-metadata, or private addresses, and Playwright follows redirects. An attacker who can influence the URL (the tool argument is LLM-produced and steerable via prompt injection) can make the server navigate to internal services and the cloud metadata endpoint and return their content. Confirmed on 0.1.7: visit_page navigated to a local internal sentinel and returned its body (including a planted secret).

### Details
dist/index.js: visit_page (handler around lines 769-786) calls safePageNavigation, which does page.goto(url, ...) (around line 315). The URL gate isValidUrl (around lines 646-651) only checks url.protocol === 'http:' || 'https:'. There is no internal-IP / loopback / metadata filtering, and no re-validation of redirect targets (Playwright follows the 302). safePageNavigation additionally requires the loaded page to have sufficient content, but a normal internal page (an admin panel, a metadata JSON document, etc.) easily passes that check.

### PoC
validated on @mzxrai/mcp-webresearch 0.1.7 by driving the server over MCP stdio (raw JSON-RPC) against a local server standing in for an internal metadata service:
```
=== webresearch visit_page SSRF (substantial internal page) ===
server fetched internal: true | content readback leaked secret: true
returned (excerpt): { "url": "http://127.0.0.1:<port>/latest/meta-data/iam/",
  "title": "Internal Metadata Service", "content": "# EC2 Instance Metadata ... WR_INTERNAL_IMDS_SECRET_iam-creds=AKIA9XEXFIL ..." }
```
visit_page({ url: "http://127.0.0.1:<port>/latest/meta-data/iam/" }) caused the server's browser to load the internal page (the sentinel logged the loopback hit) and returned its content, including the planted secret, to the caller. The same reaches http://169.254.169.254/latest/meta-data/... on cloud hosts. (The browser was launched with --no-sandbox / a pinned chromium path to run in the test container; the navigation logic is unchanged.)

### Impact
A host running mcp-webresearch can be used to read internal-only HTTP services and the cloud metadata endpoint, returning their contents (page text) into the model context, from where they can be exfiltrated. The URL is attacker-controllable via prompt injection (search results or a page the agent visits can instruct it to visit an internal URL), so this is reachable without direct authenticated access.

### Remediation
Add SSRF protection to isValidUrl / before navigation: resolve the host and reject loopback, link-local/metadata (169.254.0.0/16), 0.0.0.0/8, and private/reserved ranges, applied to visit_page and to every redirect hop (re-check the post-redirect host, or pin navigation to the validated IP). Apply the same to take_screenshot and to the URLs followed from search_google results.
