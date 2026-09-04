https://github.com/simstudioai/sim

## Finding: Internal Route Confused Deputy Bypasses SSRF Guard and Internal Auth via HTTP Block URL

Affected Versions: v0.6.103

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N (Score 5.0)

CWE: CWE-441 — Unintended Proxy or Intermediary ('Confused Deputy')


### Summary

An authenticated workflow author can supply an HTTP block URL beginning with /api/ that Sim classifies as an internal route based only on a string prefix match. This classification skips the SSRF/DNS validation applied to external URLs and attaches a server minted internal authentication token to the outgoing request, letting the request reach internal only API endpoints on the same origin without the checks the internal API surface is meant to enforce.

### Details

In apps/sim/tools/index.ts (~line 1538), route classification is:

isInternalRoute = endpointUrl.startsWith('/api/')

The internal branch does not call validateUrlWithDNS, which only runs on the external branch (~line 1690). Instead, the internal branch calls addInternalAuthIfNeeded (~line 1581), which mints a fresh JWT via generateInternalToken(userId) with type set to internal.

The HTTP block URL that reaches this classification is user controlled. It originates from processUrl in tools/http/utils.ts (~line 50) and is passed through verbatim, with no scheme or path normalization before the isInternalRoute check.

The minted internal JWT is accepted by checkInternalAuth in lib/auth/hybrid.ts (~line 70), which gates the executor only internal API surface, including /api/function/execute (route.ts ~line 1267), the Function block code execution backend.

Internal route resolution uses new URL(path, internalApiBaseUrl), so a leading slash path cannot change the host. This means the bypass is confined to the application's own origin: an absolute URL such as http://169.254.169.254/... does not match the /api/ prefix, is routed through the validated external branch, and is blocked there. The internal token is minted with the calling workflow author's own userId, and every endpoint gated by checkInternalAuth resolves the token back to that same identity, so no other user's identity or a higher privileged identity is reachable through this path.

The issue is that classification of a request as internal is driven by string matching a user supplied value, not by a trusted flag on the tool definition. This lets a user controlled HTTP block cross into the internal API surface and receive a server minted credential meant only for internal service to service calls, bypassing both the SSRF guard and the intended boundary between the tool execution surface and the internal only API.

### Disclosure
 - 12 June 2026 - reported via email
 - 13 June 2026 - accepted
 - 30 June 2026 - followed up - fixed

<img width="536" height="314" alt="image" src="https://github.com/user-attachments/assets/50241634-4020-43ed-9f12-220489f69f3a" />
