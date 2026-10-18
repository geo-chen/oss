## Linksys EA8100 Router

**firmware 1.0.3.216940**

<img width="497" height="275" alt="image" src="https://github.com/user-attachments/assets/d654081c-22b3-4b7a-ad78-3d5a337a29c0" />

## Finding 1: Unauthenticated network reconnaissance via GetWANStatus/GetWANStatus3/IsAdminPasswordDefault, exploitable cross-origin via DNS rebinding

### Disclosure: 
 - 28 Sep 2026 reported via bugcrowd: https://bugcrowd.com/submissions/4d8a25a8-4778-498f-b90b-c68235353d4b#activity-3346a4ad-100a-4df4-979f-173362166690
 - 17 Oct 2026 - model end of life (but many customers, including me, am still using it!):
   <img width="739" height="147" alt="image" src="https://github.com/user-attachments/assets/044b22f6-28cc-4482-81c6-9e6d5419accd" />

### CVSS 3.1: 4.3 (Medium)
`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | The vulnerable JNAP endpoint is only reachable over the LAN. DNS rebinding lets a remote attacker's webpage initiate the attack, but the TCP connection that actually reaches the router always originates from a device physically on (or already routed into) the local network, per Linksys's own CVSSv3 scoring guidance for LAN-only attacks. |
| AC | Low (L) | DNS rebinding against LAN-local HTTP services is a well-established, reliable technique; no race condition or unusual victim behavior required beyond visiting a page and staying on the network briefly. |
| PR | None (N) | No authentication of any kind is required to call the vulnerable actions. |
| UI | None (N) | The primarily demonstrated path is a LAN-positioned attacker sending the request directly, with no victim interaction required. DNS rebinding (requiring a victim to load a page) is an additional, secondary delivery path for a non-LAN-positioned attacker, described below. |
| S | Unchanged (U) | Impact is confined to the JNAP API's own data; no privilege escalation into another security scope. |
| C | Low (L) | Discloses WAN-facing network identifiers (see Details) but not credentials, PII, or full device control. |
| I | None (N) | The vulnerable actions are read-only `Get*` calls; nothing can be modified through them. |
| A | None (N) | No availability impact. |

### CWE
- CWE-306: Missing Authentication for Critical Function (primary, all three actions have no auth gate at all)
- CWE-346: Origin Validation Error (secondary, no Host-header/origin validation, which is what turns "an attacker on your LAN" into "any website you visit while on this LAN")

### Vulnerability description

The EA8100's local management API (JNAP, reached via `POST /JNAP/` with
an `X-JNAP-Action` header identifying the action) requires no
authentication for three actions:

- `http://linksys.com/jnap/router/GetWANStatus`
- `http://linksys.com/jnap/router/GetWANStatus3`
- `http://linksys.com/jnap/core/IsAdminPasswordDefault`

The two `GetWANStatus*` actions return, without any credential or
session token:

- the router's WAN-side MAC address
- the WAN IPv4 address, gateway, and DNS server
- the WAN IPv6 address (SLAAC-derived, which embeds the same MAC)
- WAN connection type and status

`IsAdminPasswordDefault` returns a single boolean stating whether the
admin password is still set to the factory default. On this device
(admin/admin, the documented EA8100 factory default) it correctly
returned `true`. This turns "try the known default credentials and see"
into a single unauthenticated request that tells an attacker, in
advance and with certainty, whether that attempt is worth making at
all, without generating a failed-login attempt against the device.

This is the residue of a broader, previously disclosed issue: a 2019-era
public writeup documented roughly 28 JNAP `Get*`/status actions callable
without authentication across a range of Linksys Smart Wi-Fi routers,
EA8100 included (`IsAdminPasswordDefault` and `GetWANStatus` were both
named in that original list), up through firmware 1.0.2.193233. Testing
the same list against the currently shipping 1.0.3.216940 build shows
25 of the ~28 actions correctly return `_ErrorUnauthorized`. These three
do not. `GetWANStatus3` is a newer action version that did not exist in
the original disclosure, added later without an authentication check
either, meaning the same class of oversight was reintroduced in a newer
action rather than fully closed out for that one.

Separately, the JNAP endpoint performs no validation of the HTTP `Host`
header. A request with an arbitrary, attacker-chosen `Host` value
(simulating what a browser sends after DNS rebinding) is processed
identically to a request with the router's real address as `Host`. This
matters because it is what makes the disclosure remotely triggerable
rather than requiring the attacker to already be on the LAN: a malicious
or compromised webpage, loaded by any device on the network, can rebind
its own domain's DNS record to the router's LAN address after the page
loads, then issue a `fetch()` that the browser now treats as same-origin
(because, from the browser's perspective at request time, it is talking
to the same hostname it loaded from, only the underlying IP changed).
No CORS header is needed for the attacker to read the response in this
scenario, because DNS rebinding sidesteps the Same-Origin Policy check
entirely rather than needing to defeat it.

### Attack scenario

1. Victim's laptop or phone is connected to a network served by this
   router (any network, home, guest, or office).
2. Victim visits any webpage that serves attacker-controlled
   JavaScript (a malicious site, a compromised ad, a compromised page on
   an otherwise legitimate site).
3. That page's JavaScript begins polling its own origin. The attacker's
   DNS server, authoritative for that origin, initially resolves to an
   attacker-controlled IP (to pass the page's own load), then switches
   the DNS answer to the router's LAN IP address (a low, attacker-chosen
   TTL makes this switch happen quickly, typically within seconds).
4. Once the victim's browser re-resolves the domain (browsers re-resolve
   per the DNS TTL, not per page load) and picks up the new IP, further
   `fetch()` calls from that same page to that same origin now land on
   the router instead of the attacker's server, but the browser still
   considers them same-origin.
5. The page issues `fetch('https://<rebound-domain>/JNAP/', {method:
   'POST', headers: {'X-JNAP-Action':
   'http://linksys.com/jnap/router/GetWANStatus', 'Content-Type':
   'text/plain'}, body: '{}'})` (the router's self-signed certificate
   would need to be accepted, or the attack run over the router's HTTP
   listener if present; this was tested over HTTPS with certificate
   verification disabled, matching how a real browser would only be
   blocked by a cert warning, not by any router-side control).
6. The router replies 200 OK with the full WAN status JSON. Because this
   is now a same-origin request from the browser's perspective, the
   page's own JavaScript can read the response body directly and exfiltrate
   it to the attacker.

### Step-by-step PoC (as validated, LAN-local form)

This reproduces the missing-authentication and missing-Host-validation
primitives directly; the DNS-rebinding delivery mechanism in the attack
scenario above is the standard, previously published technique for
turning this kind of LAN-only bug into a remotely triggerable one and
was not separately re-implemented end-to-end for this report.

1. From any device on the same network as the router, with no prior
   authentication:

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/router/GetWANStatus" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response (redacted values shown as placeholders; the live response
included the real WAN MAC address, WAN IPv4/gateway/DNS, and WAN IPv6
address):

```json
{
  "result": "OK",
  "output": {
    "wanStatus": "Connected",
    "wanConnection": {
      "wanType": "DHCP",
      "ipAddress": "<WAN IPv4>",
      "gateway": "<gateway>",
      "dnsServer1": "<DNS server>"
    },
    "wanIPv6Connection": {
      "networkInfo": { "ipAddress": "<WAN IPv6>" }
    },
    "macAddress": "<WAN MAC address>"
  }
}
```

2. Confirm the same succeeds for the newer action variant:

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/router/GetWANStatus3" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Same result, plus additional supported-configuration metadata.

3. Confirm the default-credential oracle, also with no prior authentication:

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/core/IsAdminPasswordDefault" \
  -H "Content-Type: application/json" \
  -d '{}'
```

```json
{ "result": "OK", "output": { "isAdminPasswordDefault": true } }
```

4. Confirm no Host-header binding (the piece that enables DNS-rebinding
   delivery): repeat step 1 while resolving an arbitrary hostname to the
   router's IP and sending that hostname as the `Host` header.

```
curl -k -X POST "https://<router-ip>/JNAP/" \
  --resolve attacker-controlled.example:443:<router-ip> \
  -H "Host: attacker-controlled.example" \
  -H "X-JNAP-Action: http://linksys.com/jnap/router/GetWANStatus" \
  -H "Content-Type: text/plain" \
  -d '{}'
```

Identical 200 OK response (confirmed for `GetWANStatus`; the same
Host-header behavior applies to `IsAdminPasswordDefault`, also tested).
The router does not reject or otherwise treat this request differently
based on the `Host` header, confirming the request would be processed
the same way if it arrived via a DNS-rebound browser connection.

### Impact

An attacker who can get a device on this network to load a page under
their control (via ads, a compromised site, a malicious link, or a
captive-portal-adjacent scenario on a guest network) can, without any
router credentials, remotely determine the router's public-facing WAN
IP address, WAN MAC address, WAN IPv6 address, gateway, and DNS server,
and separately determine with certainty whether the admin password is
still the factory default. The WAN MAC address in particular is a
stable, globally unique identifier for the specific physical device
that survives IP changes (dynamic WAN IP, ISP reassignment, VPN use)
and can be used to track or re-identify the same router/network across
time, or as reconnaissance feeding into further attacks (for example
targeting known MAC-OUI-specific firmware exploits, or correlating this
device against other data sources that also record its MAC). The
default-credential oracle removes the need to ever attempt a failed
login against the device before knowing default credentials will
succeed, which is meaningful for any deployment monitoring failed-login
attempts as a compromise indicator, since a real attacker using this
oracle first would go straight to a successful login. This is
disclosure of stable network identifiers and account-security state,
not itself a path to credentials or device control, hence the Low
severity.

### Recommendation

1. Apply the same authorization check already enforced on every other
   formerly-unauthenticated JNAP `Get*` action (per the 2019 disclosure
   remediation) to `GetWANStatus`, `GetWANStatus3`, and
   `IsAdminPasswordDefault` specifically.
2. When adding new JNAP action versions (the `*2`, `*3`, etc. suffix
   pattern visible throughout this device's service list), include
   authentication-requirement review as an explicit step, since this is
   the second time in this device's history that a superset/successor
   action has been introduced without carrying forward an
   authentication requirement present on comparable actions.
3. Validate the `Host` header against the router's own configured
   hostname/IP set on the JNAP listener, independent of fixing the
   specific actions above. This closes the DNS-rebinding delivery
   mechanism for this class of bug generally, not just for these two
   actions, and is standard practice for embedded device management
   APIs that are reachable from a browser context.




## Finding 2: No rate limiting or lockout on admin authentication (JNAP CheckAdminPassword)

### Disclosure: 
 - 28 Sep 2026 reported via bugcrowd: https://bugcrowd.com/submissions/1719249f-9394-4039-9f41-383fffda1281
 - 17 Oct 2026 - model end of life:
   <img width="739" height="147" alt="image" src="https://github.com/user-attachments/assets/044b22f6-28cc-4482-81c6-9e6d5419accd" />

 ### CVSS 3.1: 5.3 (Medium)
`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` (as a standalone
weakness). Scored per Linksys's own CVSSv3 guidance for LAN-only
attacks (AV:A, not AV:N). This is a "requires exploiting another
weakness to have direct impact" enabler class (CWE-307): it does not
have a confidentiality/integrity/availability impact on its own beyond
what a successful credential guess would grant, but the CVSS Base
metrics here are scored for the vulnerability itself (unrestricted
authentication attempts against a LAN-reachable admin login), matching
how this class of weakness is conventionally scored when reported
independently of a specific downstream credential.

### CWE
- CWE-307: Improper Restriction of Excessive Authentication Attempts

### Vulnerability description

The JNAP action `http://linksys.com/jnap/core/CheckAdminPassword`
(reached via `POST /JNAP/` with an `X-JNAP-Authorization: Basic
<base64(admin:password)>` header, the router's authentication scheme)
has no rate limiting, exponential backoff, CAPTCHA, or account lockout
of any kind. 15 consecutive failed attempts were sent with no increase
in response latency and no change in the error response. A further 60
attempts at moderate concurrency (10 simultaneous connections) all
completed successfully at a sustained rate of approximately 4 attempts
per second, roughly 14,400 attempts per hour, with the device showing
no sign of throttling the requests, only ordinary response-time
variance under load.

This means the admin password is protected only by its own strength
against online guessing, since the well-known "admin"/"admin" default
alone was in-place on this unit before I applied any protection, there
is no secondary control (delay, lockout, or CAPTCHA) that would slow or
stop an attacker methodically working through a password list.

### Step-by-step PoC (as validated)

From any device on the same network as the router, with no prior
authentication and no valid credentials:

```
for i in $(seq 1 15); do
  curl -k -X POST https://<router-ip>/JNAP/ \
    -H "X-JNAP-Action: http://linksys.com/jnap/core/CheckAdminPassword" \
    -H "X-JNAP-Authorization: Basic $(echo -n "admin:wrongpass$i" | base64)" \
    -H "Content-Type: application/json" \
    -d '{}'
done
```

All 15 attempts return the same `_ErrorUnauthorized` response with
sub-second, non-increasing latency (approximately 0.39-0.54s per
request in serial testing), confirming no delay penalty is applied
after repeated failures. A concurrent run of 60 further attempts (10 at
a time) completed at approximately 4 attempts/second sustained, with no
attempts blocked, delayed, or rejected for any reason other than the
wrong password.

### Impact

An attacker with LAN access (or, per findings 001/002, potentially a
remote attacker who can get a LAN device to load a malicious page,
since the same missing-Host-validation issue applies to this endpoint
too) can run an unthrottled online dictionary or brute-force attack
against the admin password. At roughly 14,000+ attempts/hour with no
lockout, a common-password or small-to-medium dictionary attack is
practical within hours, and combined with finding 002's
`IsAdminPasswordDefault` check, an attacker can first triage which
devices are still on factory defaults (no brute-forcing needed at all)
before spending brute-force effort on the remainder.

### Recommendation

Add rate limiting to `CheckAdminPassword` (and any other
authentication-bearing action), for example: a short, increasing delay
after each failed attempt from the same source, a temporary lockout
after a small number of consecutive failures (with a safe local-console
or physical-reset recovery path, so this cannot itself become a
remote-DoS-of-legitimate-admin vector), and/or a CAPTCHA after a
threshold of failures. As with findings 001 and 002, adding Host-header
validation to the JNAP listener would also reduce this endpoint's
exposure to non-LAN-local attackers specifically.




## Finding 3: Unauthenticated write access to remote-management pairing state and unsecured-WiFi-warning flag

### Disclosure: 
 - 28 Sep 2026 reported via bugcrowd: https://bugcrowd.com/submissions/c82da4c8-0576-4538-a917-e312e3947f56
 - 17 Oct 2026 - model end of life


### CVSS 3.1: 5.3 (Medium)
`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | Same LAN-only reasoning as 001/002/003; also reachable via DNS rebinding since the JNAP listener validates no Host header, see 001. |
| AC | Low (L) | No special conditions; a single well-formed POST executes the change. |
| PR | None (N) | No authentication of any kind is required or checked for either action. |
| UI | None (N) | The primary demonstrated path is a LAN-positioned attacker sending the request directly; no victim interaction is required for that path. |
| S | Unchanged (U) | Impact stays within this device's own configuration state. |
| C | None (N) | Neither action returns data; this is a write-only issue. |
| I | Low (L) | An unauthenticated party can modify a security-relevant state flag (remote-management pairing status) and a UI-warning flag. Scored Low rather than High because the directly demonstrated impact is limited to flipping these two flags; full downstream consequence (whether the pairing flag is trusted elsewhere) was not verified, see Private notes. |
| A | None (N) | No availability impact. |

### CWE
- CWE-306: Missing Authentication for Critical Function

### Vulnerability description

Two JNAP `Set*` actions execute without any authentication check,
unlike the rest of this device's write actions (every other `Set*`
action tested, out of 140 real action names extracted directly from
the admin UI's own JavaScript, correctly returns `_ErrorUnauthorized`
when called without credentials):

- `http://linksys.com/jnap/ui/SetRemoteSetting`, which accepts a body
  of `{"isEnabled": <bool>}` and, per its call sites in the client
  code, tracks whether this router is currently paired with a Linksys
  cloud account for remote app-based management.
- `http://linksys.com/jnap/core/SetUnsecuredWiFiWarning`, which accepts
  `{"enabled": <bool>}` and, per its call sites, controls a local
  UI-warning flag that is reset on logout.

Both were confirmed, with valid request bodies and no
`X-JNAP-Authorization` header, to execute successfully (`{"result":
"OK"}`) and to produce a real, persistent state change, verified by
reading the state back through the corresponding unauthenticated
`Get*` action before and after each write.

### Step-by-step PoC (as validated)

From any device on the same network as the router, with no prior
authentication:

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/ui/GetRemoteSetting" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Returns the current state, for example `{"isEnabled":false}`.

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/ui/SetRemoteSetting" \
  -H "Content-Type: application/json" \
  -d '{"isEnabled":true}'
```

Returns `{"result":"OK"}`.

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/ui/GetRemoteSetting" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Now returns `{"isEnabled":true}`, confirming the unauthenticated write
took effect. The same pattern (unauthenticated `Set`, confirmed via
unauthenticated `Get`) applies to `SetUnsecuredWiFiWarning`.

### Root cause (confirmed via firmware analysis)

After the live findings above, I pulled the official firmware image for
this exact build (`FW_EA8100_1.0.3.216940_prod.img`, downloaded directly
from Linksys's own support site) and extracted its JFFS2 partition. The
JNAP backend's Lua source is present in full at
`/JNAP/modules/*_server.lua`, unobfuscated. Both vulnerable handlers'
full source:

```lua
-- JNAP/modules/ui_server.lua
local function SetRemoteSetting(ctx, input)
    local device = require('device')
    local sc = ctx:sysctx()

    local error = device.setRemoteUIEnabled(sc, input.isEnabled)
    return error or 'OK'
end
```

```lua
-- JNAP/modules/core_server.lua
local function SetUnsecuredWiFiWarning(ctx, input)
    local device = require('device')

    local sc = ctx:sysctx()
    local error = device.setUnsecuredWiFiWarningEnabled(sc, input.enabled)
    return error or 'OK'
end
```

Neither function contains any authentication or authorization check.
This is not, on its own, unusual: none of the individual action handlers
in either file carry inline auth logic (the check is evidently applied
by a layer outside this Lua source, most likely the native dispatcher
binary these modules are loaded into, `/usr/sbin/jnap`, or a permission
table compiled into one of its supporting shared libraries, neither of
which yielded readable strings identifying the exact mechanism from
static analysis alone). What is unusual, and directly relevant, is that
one action in the same file, `FactoryReset`, does carry its own manual,
inline guard:

```lua
local function FactoryReset(ctx)
    if ctx:isremotecall() then
        return "ErrorDisallowedRemoteCall"
    end
    ...
```

This confirms that per-action custom access logic is a pattern this
codebase actually uses when a developer wants behavior different from
whatever the default enforcement layer provides, and that no such guard
exists on either `SetRemoteSetting` or `SetUnsecuredWiFiWarning`. It is
also worth noting that `GetRemoteSetting` and `GetCloudServerStatus`
(the other two actions in `ui_server.lua`, both already confirmed
unauthenticated, and both plausibly intended to be reachable pre-login)
share the same file as `SetRemoteSetting` with no per-action distinction
visible in source; this is consistent with the whole `ui_server.lua`
module being treated as exempt from the default authentication
requirement at a coarser (module-level, not action-level) granularity,
which would explain why the write action `SetRemoteSetting` ended up
exempted alongside its sibling read actions, rather than this being a
deliberate, action-specific decision. `SetUnsecuredWiFiWarning`, by
contrast, lives in `core_server.lua` alongside numerous other actions
(`SetAdminPassword`, `Reboot`, `FactoryReset`) that are correctly
gated, so its exemption is not explained by a module-wide policy and
looks instead like a per-action registration gap specific to that one
entry.

`core_server.lua`'s source also confirms, at the source level, the
mechanism behind finding 002: `GetAdminPasswordHint` and
`IsAdminPasswordDefault` are defined in the exact same file, with the
same absence of any inline check, as `SetUnsecuredWiFiWarning`. All
three appear to be instances of the same underlying gap (whatever the
platform's default-authentication layer is, it is not catching every
registered action in this file), just manifesting as a read (info
disclosure, finding 002) in two cases and a write (this finding) in the
third.

### Follow-up: what `SetRemoteSetting` actually does under the hood

The firmware source resolves the "unverified" question raised above.
`device.setRemoteUIEnabled` (called by the `SetRemoteSetting` handler)
is:

```lua
function _M.setRemoteUIEnabled(sc, isEnabled)
    sc:writelock()
    sc:set_remote_ui_enabled(isEnabled)
end
```

This is a direct write to a local system-config flag via the native
`sysctx` binding (`set_remote_ui_enabled`), with no cloud API call, no
token exchange, and no other side effect triggered from this code path.
This confirms the impact framing above was accurate rather than
conservative: the directly reachable consequence of this bug really is
limited to unauthorized modification of this one local flag, not an
unverified "could be worse" scenario. Whether anything else in the
device (or the cloud/app side, which this JNAP source does not cover)
separately reads and trusts this flag was not determined from this
firmware alone.

### Impact

An unauthenticated party with LAN access, or a remote attacker able to
deliver the request via the same DNS-rebinding path described in
finding 001, can modify this router's remote-management pairing-state
flag and its unsecured-WiFi-warning flag without any credentials. At
minimum, this allows silently corrupting the device's own record of its
remote-management pairing status (for example, an attacker could
repeatedly reset it to `false` to disrupt a legitimate owner's remote
app access, or set it to `true` to plant a false signal that the device
is cloud-paired when it is not). Whether this can be chained into an
actual unauthorized remote-access grant depends on how the cloud
backend or mobile app consumes this flag, which is outside the scope of
what was tested here and should be evaluated by the vendor directly,
since it involves infrastructure this engagement did not have access
to.

### Recommendation

Apply the same authentication check already enforced on every other
`Set*` action in this API to `SetRemoteSetting` and
`SetUnsecuredWiFiWarning`. Given both appear to be intended only for
use immediately after a successful login or during logout (per their
call sites in the client code), consider whether they need to be
reachable at all outside an authenticated session, rather than relying
on the client to only call them at the "right" time. Separately,
audit whether any server-side or cloud-side logic treats
`SetRemoteSetting`'s flag as an indicator of legitimate account pairing
without independently re-verifying that pairing, since that is the
scenario that would escalate this from "unauthorized state
modification" to "unauthorized remote-access grant."



## Finding 4: Admin credential stored in a non-HttpOnly cookie (admin-auth)

### Disclosure: 
 - 29 Sep 2026 reported via bugcrowd: https://bugcrowd.com/submissions/4fbda8bd-08ba-4426-ad54-f0f5e5cb861d
 - 17 Oct 2026 - model end of life

### CVSS 3.1: 4.6 (Medium)
`CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`

| Metric | Value | Why |
|---|---|---|
| AV | Local (L) | Reading this cookie requires script execution in the browser that holds the session (via XSS on this origin, or local access to that browser's storage); it is not directly network-reachable the way findings 001/002/004 are. |
| AC | High (H) | No live exploitation chain (such as an XSS bug) was found during this engagement to actually reach and read the cookie; realizing this weakness requires such a bug to exist, which is a real but unconfirmed precondition. |
| PR | None (N) | No authentication is needed to read a cookie once a code-execution or storage-access precondition is met. |
| UI | Required (R) | Requires the victim (the logged-in administrator) to have an active session and, in the XSS scenario, to load or already be on a page where injected script runs. |
| S | Unchanged (U) | |
| C | High (H) | The cookie's value decodes directly to the plaintext admin username and password (`Basic base64(username:password)`), not a revocable session token. Reading it is equivalent to full credential theft. |
| I | None (N) | Reading the cookie has no direct integrity impact by itself (a subsequent login using the stolen credential would, but that is a separate action). |
| A | None (N) | No availability impact. |

### CWE
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-522: Insufficiently Protected Credentials

### Vulnerability description

After a successful admin login through the router's web UI, the client
sets a cookie named `admin-auth` with the value
`Basic%20<base64(username:password)>`, URL-encoded, the exact contents
of the HTTP Basic authorization header the UI subsequently attaches to
its own JNAP calls. This cookie is set with `Secure: true` but
`HttpOnly: false`, meaning any JavaScript running on the router's admin
origin can read it via `document.cookie`, and the value, once read, is
a single `base64.decode()` away from the literal admin username and
password.

This is architecturally different from (and more sensitive than) a
typical session cookie: a normal session-ID cookie, even if readable by
script, discloses only an opaque, server-revocable token; this cookie
discloses the actual, reusable, non-expiring credential. Anyone who can
read it can authenticate as the admin indefinitely (until the password
is changed), not just for the lifetime of one session.

Storing the credential this way, and specifically without `HttpOnly`,
removes a standard, cheap defense-in-depth control at exactly the point
where it matters most: it is the one piece of client-side state on this
entire application whose disclosure is equivalent to full credential
compromise, rather than session compromise.

### Step-by-step PoC (as validated)

Logging into the admin UI normally (username field, if any, plus the
`admin` password used throughout this engagement) and then, from the
browser's own developer console or any script running on the router's
origin:

```javascript
document.cookie
// "...; admin-auth=Basic%20YWRtaW46YWRtaW4%3D"

decodeURIComponent("Basic%20YWRtaW46YWRtaW4%3D")
// "Basic YWRtaW46YWRtaW4="

atob("YWRtaW46YWRtaW4=")
// "admin:admin"
```

This was run against a live login session on the test device and
correctly recovered the literal credential in use.

### Impact

If an XSS vulnerability is ever found anywhere on this admin UI's
origin (now or in a future firmware version), it would translate
directly into full, standing admin credential theft, rather than
theft of a revocable session token, because of how this cookie is
structured. This also means any local software on the administrator's
own machine capable of reading a browser's cookie storage for this
origin (a browser extension, local malware, or a misconfigured
same-machine application) obtains the router's actual admin password,
not just a session.

### Recommendation

Do not store the reusable credential client-side at all; use a
server-issued, opaque, revocable session token instead (a standard
session cookie or equivalent), which is what nearly every other web
application login flow uses instead of retaining the raw credential.
At minimum, set the `HttpOnly` flag on this cookie so it cannot be read
by JavaScript under any circumstance, though replacing the credential
with a proper session token is the more complete fix, since HttpOnly
alone does not address the cookie's `Secure`-only-if-conditionally-set
design or its use as a de facto standing bearer credential rather than
an expiring session identifier.


## Finding 5: SMB anonymous access mapped to the admin account when "Anonymous access" is enabled

### Disclosure: 
 - 28 Sep 2026 reported via bugcrowd: https://bugcrowd.com/submissions/2a807024-24fa-4388-a45b-c2a3856e730a
 - 17 Oct 2026 - model end of life

### CVSS 3.1: 6.5 (Medium)
`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | SMB (139/445) is a LAN-only service on this device; no remote-delivery mechanism (such as the DNS rebinding used for findings 001/002/004) applies to a raw TCP protocol like SMB. |
| AC | Low (L) | Standard SMB anonymous/guest connection; no special conditions once the (documented, user-facing) anonymous-access feature is turned on. |
| PR | None (N) | The entire point of the anonymous-access feature is that no credentials are required. |
| UI | None (N) | No victim interaction needed; an attacker on the LAN connects directly. |
| S | Unchanged (U) | |
| C | High (H) | Depends on what is actually shared, but the feature exists specifically to expose USB-attached storage, and the guest session is mapped to the admin account rather than a scoped, limited identity. |
| I | High (H) | Same reasoning; `permissions = everyone:full, anonymous:full` is written into the per-share config alongside the admin mapping when this feature is enabled, meaning full write access, not just read. |
| A | None (N) | No availability impact from this specific issue. |

Scored against the feature as designed (an administrator who enables
"anonymous access" gets full read/write for anyone on the network,
which might be considered by-design for that specific toggle). What
elevates this beyond "working as intended" is the `guest account =
admin` mapping specifically, a limited, dedicated anonymous account
(as correctly implemented for the equivalent FTP feature on this same
device) would achieve the same documented "shared folder available
without a password" functionality without tying guest sessions to the
router's actual administrative account identity.

### CWE
- CWE-1188: Insecure Default Initialization of Resource
- CWE-269: Improper Privilege Management

### Vulnerability description

`etc/init.d/service_smbd.sh` generates this device's live `smb.conf`
from its JNAP-exposed storage settings every time the SMB service is
(re)configured. When anonymous access is enabled (the
`SharedFolderAnonEna` `syscfg` flag, exposed via JNAP as
`storage/GetSMBServerSettings`'s `isAnonymousWriteEnabled`, itself set
via the authenticated `storage/SetSMBServerSettings` action), the
script writes:

```sh
if [ $ANON_ACCESS -gt 0 ] ; then
  echo "  security = share" >> $SAMBA_CONF_FILE
  echo "  guest account = admin" >> $SAMBA_CONF_FILE
else
  echo "  security = user" >> $SAMBA_CONF_FILE
  echo "  guest account = guest" >> $SAMBA_CONF_FILE
fi
```

into the `[global]` section, and, for each individual share created
while this setting is on:

```sh
if [ $ANON_ACCESS -gt 0 ] ; then
  echo "  permissions = everyone:full, anonymous:full" >> $SAMBA_CONF_FILE
```

`security = share` is Samba's legacy share-level security mode, where
clients are not required to authenticate as a real user; unauthenticated
and mismatched-credential connections fall back to the configured
`guest account` for filesystem-permission purposes. Setting that guest
account to `admin`, rather than a dedicated, unprivileged identity,
means any anonymous SMB session on this configuration is evaluated
against the router's actual administrative account for anything not
explicitly covered by the per-share `everyone:full, anonymous:full`
override, rather than against a limited, purpose-built guest identity.

This is the router's own documented, user-facing "Anonymous Access"
toggle for USB storage sharing (confirmed present and reachable via
the authenticated JNAP action `storage/SetSMBServerSettings`); it is
not a hidden or undocumented setting. The issue is not that enabling
this feature grants broad access, that is its stated purpose, it is
specifically that the implementation ties the resulting guest identity
to the admin account rather than to a scoped one, which is avoidable
(the equivalent FTP feature on this exact device does exactly that
correctly, see Private notes).

### Step-by-step PoC (as validated)

1. Confirm the precondition via the authenticated JNAP API:

```
curl -k -X POST https://<router-ip>/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/storage/GetSMBServerSettings" \
  -H "X-JNAP-Authorization: Basic <base64 admin:password>" \
  -H "Content-Type: application/json" -d '{}'
```

Confirmed on this device: `{"isAnonymousWriteEnabled": true, ...}`.

2. Confirm SMB anonymous negotiation succeeds:

```
smbclient -L //<router-ip>/ -N
```

Succeeds without credentials on this device (`account_used: guest`,
confirmed separately via `nmap --script smb-security-mode,smb-enum-shares`
in this engagement's earlier port-scan pass).

3. (Not performed in this engagement, requires physical USB storage
   attached to the router) With a USB drive attached and shared through
   this feature, connect anonymously and confirm files are readable
   and writable, and that this occurs under the `admin`-mapped guest
   identity per the `smb.conf` logic shown above, by reading back the
   live generated config or by testing filesystem-permission edge
   cases that would only succeed under the admin identity specifically
   (for example, a share or path not covered by the per-share
   `everyone:full` override, where the fallback `guest account`
   mapping would be the deciding factor).

### Scope boundary (what was ruled out / not claimed)

- File-level read/write impact was not demonstrated end-to-end in this
  engagement; no USB storage was attached to the test device. The
  finding is reported at the configuration/root-cause level (confirmed
  from firmware source, tied to a setting confirmed live-enabled on the
  device), not as a completed file-exfiltration or file-write PoC.
- This is specific to the SMB feature. The equivalent, similarly-named
  FTP anonymous-access feature on this same device was checked and
  found to correctly use a dedicated, unprivileged account
  (`anonymous`, UID 505), not the admin account. This is not a
  device-wide pattern.
- This does not claim the anonymous-access feature itself should not
  exist or should not grant broad file access when enabled, that
  appears to be its intended purpose. The issue is the specific choice
  of `admin` as the guest-mapped identity rather than a scoped one.

### Impact

Any device on the same network as this router can, once an
administrator has enabled the documented "Anonymous Access" storage
feature (a normal, supported configuration state, not a misconfiguration
outside the product's intended use), connect to SMB shares without
credentials under an identity that is the router's own administrative
account, rather than a limited guest identity. Combined with the
explicit per-share `everyone:full, anonymous:full` override, the
directly demonstrable impact of the feature-as-designed is already
broad; the additional risk from the `admin` guest-account mapping
specifically is in any path or resource not covered by that per-share
override falling back to full administrative filesystem permissions
instead of a properly scoped guest identity's permissions.

### Recommendation

Map the SMB anonymous/guest account to a dedicated, unprivileged system
account, matching the pattern already correctly used for this device's
FTP anonymous-access feature (a UID/GID scoped only to the shared
storage paths, not the administrative account). This preserves the
feature's documented behavior (shared folders accessible without a
password) while removing the unnecessary tie to the admin identity for
any access path not explicitly covered by the per-share permission
override.

