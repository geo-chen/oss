https://github.com/getarcaneapp/arcane

## Finding: Missing admin authorization on template mutation endpoints -- v1.19.5

There's a missing authorization check in the Arcane backend that allows any authenticated user with the default "user" role to create, modify, and delete compose templates, and to overwrite the system-wide default compose and env templates. The issue affects v1.19.5 and the latest commit as of 2026-06-04.

In backend/api/handlers/templates.go, five endpoints carry BearerAuth or ApiKeyAuth security declarations but are not annotated with the RequireAdmin middleware:
```
  POST   /api/templates
  PUT    /api/templates/{id}
  DELETE /api/templates/{id}
  POST   /api/templates/{id}/download
  POST   /api/templates/default
```
Registry management operations immediately below them in the same file correctly include RequireAdmin. The pattern is consistent elsewhere in the codebase; only these five template endpoints are missing the check.

A restricted user can use these endpoints to inject a privileged or host-volume-mounting compose definition into any template, or to silently replace the default compose template that is pre-populated whenever any user creates a new project. When an admin later deploys that template, the resulting container can mount the host filesystem and run with full privileges, equivalent to host-level compromise.

I reproduced the issue against a fresh Docker deployment of v1.19.5 (ghcr.io/getarcaneapp/manager:latest, image commit 66ec215f). A restricted user was created with the default "user" role. Steps: log in as the restricted user, issue POST /api/templates with a privileged compose body, and separately issue POST /api/templates/default with a poisoned compose. Both return HTTP 200. The admin-facing GET /api/templates/default then reflects the restricted user's content.

The fix is to add Middlewares: humamw.RequireAdmin(api) to the five operation registrations listed above, consistent with how registry management endpoints are guarded in the same file.


## Disclosure
 - 4 June 2026 - reported via email
 - 6 July 2026 - followed up on email, no response

<img width="1253" height="756" alt="image" src="https://github.com/user-attachments/assets/cfab1ee8-1e6f-4b9f-a10e-ae099b31c87d" />
