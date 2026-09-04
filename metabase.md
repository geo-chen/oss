https://github.com/metabase/metabase

## Finding: Missing function-level authorization on the Glossary management API

There's a missing-authorization issue, confirmed against the v0.62.1 build.

The Glossary API handlers in `src/metabase/glossary/api.clj` (POST "/" ~30, PUT "/:id" ~50, DELETE "/:id" ~70) do only `api/check-404` plus the DB op, with no authorization. The route is mounted `"/glossary" (+auth ...)` (api_routes/routes.clj:190), which authenticates only. The intended gate is admin-or-analyst (frontend selector data-studio/selectors.ts:7; sibling data_studio/api/table.clj calls `(api/check-data-analyst)` everywhere), but the glossary handlers never call it, and the model defines no permission methods.

What I observed: a low-priv user (is_superuser:false, is_data_analyst:false) created (200), tampered (200), and deleted (204) glossary entries; the same session got 403 on the permission-gated POST /api/measure.

Impact: any authenticated user can poison/tamper/delete the org-wide business glossary. CWE-862, ~6.5. (Net-new: no advisory and no open issue cover glossary authz; Metabase has prior CVEs in this missing-authz-on-routes class.)

POC:
```
POST   /api/glossary        {"term":"X","definition":"Y"}   (low-priv session) -> 200, entry created
PUT    /api/glossary/:id    {"definition":"tampered"}                          -> 200
DELETE /api/glossary/:id                                                       -> 204
```

Validated against v0.62.1 Docker build with a low-privilege user (`is_superuser:false`, `is_data_analyst:false`):

```
[EXPLOIT 1] POST /api/glossary  -> 200  {"id":1,"term":"PWNED_BY_LOWPRIV",...,"creator":{...,"is_superuser":false,"is_data_analyst":false}}
[EXPLOIT 2] PUT  /api/glossary/1 -> 200  definition -> "TAMPERED definition - integrity violation."
[EXPLOIT 3] DELETE /api/glossary/1 -> 204 ;  GET /api/glossary -> {"data":[]}  (destroyed)
CONTRAST (same user/session): POST /api/measure -> 403 "You don't have permissions to do that."
```

The permission-gated sibling returns 403 for the identical user while every glossary mutation succeeded.

Suggested fix: add `(api/check-data-analyst)` to the glossary POST/PUT/DELETE handlers (mirror data_studio/api/table.clj), or define can-write?/can-create? on :model/Glossary. A PoC is available.


## Disclosure
 - 13 June 2026 - reported via email
 - 22 June 2026 - report accepted (screenshot below)
 - 30 June 2026 - followed up with disclosure

   <img width="1241" height="214" alt="image" src="https://github.com/user-attachments/assets/6b2d4a5b-d63f-429c-ac8c-ce6415f9723a" />
