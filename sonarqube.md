https://github.com/SonarSource/sonarqube

## Finding: Authorization bypass in api/webhooks/deliveries allows authenticated users to probe webhook delivery counts without project access

### Disclosure
- 23 May 2026 reported privately via https://github.com/SonarSource/sonarqube/security/advisories/GHSA-x868-5383-4jxm
- 1 July 2026 no response, followed up via email
- 2 July 2026 responded deeming not a security vulnerability as UUID is treated as secret and will fix as normal release as opposed to CVE
- 2 July 2026 disagreed on the premise that a secret should not be passed via GET param
- 3 July 2026 Sonar maintained assessment, gave green light to publish advisory once fix is out

Affected version: 26.5.0.122743

### Summary

The `GET /api/webhooks/deliveries` endpoint skips its authorization check when the result set for a given page is empty. An authenticated user with no permissions on a project can send a request to a page number beyond the total delivery count and receive a `200 OK` response containing the `paging.total` field. This leaks the number of webhook deliveries associated with a webhook UUID belonging to a private project or a global webhook they should have no visibility into.

### Details

`WebhookDeliveriesAction` in `server/sonar-webserver-webapi/src/main/java/org/sonar/server/webhook/ws/WebhookDeliveriesAction.java` performs authorization as a post-load check inside the inner `Data` class:

```java
void ensureAdminPermission(UserSession userSession) {
  if (!projectUuidMap.isEmpty()) {
    List<ProjectDto> projectsUserHasAccessTo =
        userSession.keepAuthorizedEntities(ProjectPermission.ADMIN, projectUuidMap.values());
    if (projectsUserHasAccessTo.size() != projectUuidMap.size()) {
      throw new ForbiddenException("Insufficient privileges");
    }
  }
}
```

`projectUuidMap` is populated from the deliveries returned for the requested page. When the page contains zero deliveries (for example, page 2 when only one delivery exists), `deliveries` is empty, `projectUuidMap` is empty, and the `if (!projectUuidMap.isEmpty())` guard causes the entire permission check to be silently skipped.

Before this check runs, the handler already calls:
```java
totalElements = dbClient.webhookDeliveryDao().countDeliveriesByWebhookUuid(dbSession, webhookUuid);
```

That count is included in the response body regardless of authorization outcome, so the bypass also discloses the exact delivery count.

The same logic path applies to all three supported query parameters: `webhook` (webhook UUID), `ceTaskId`, and `componentKey` (deprecated). The `componentKey` path is resistant to this attack because `componentFinder.getProjectByKey` enforces access before the delivery query. The `webhook` and `ceTaskId` paths are both vulnerable.

Preconditions:
- `sonar.forceAuthentication` must be `true` (default), so anonymous access is not a factor; the attacker must be a logged-in user.
- The attacker must know a valid webhook UUID. Webhook UUIDs are random UUIDs and are not exposed through any API accessible to low-privilege users. However, they may be obtained through log exposure, shared tooling, or social engineering.
- For the bypass to return a non-zero `total`, at least one delivery must exist for the target webhook. For a fresh webhook with zero deliveries, the bypass returns `total: 0` (confirming the UUID is valid but reveals no additional count).

### PoC

**Setup (as admin):**
```
POST /api/projects/create?name=PrivateProject&project=private-proj&visibility=private
POST /api/webhooks/create?name=myhook&url=http://example.com/hook&project=private-proj
# Webhook UUID returned: <WH_UUID>
# Trigger at least one analysis to produce deliveries
```

**Attack (as authenticated non-admin user, no access to private-proj):**

Page 1 - blocked correctly:
```
GET /api/webhooks/deliveries?webhook=<WH_UUID>&p=1
HTTP/1.1 403 Forbidden
{"errors":[{"msg":"Insufficient privileges"}]}
```

Page 2 - authorization bypassed, delivery count disclosed:
```
GET /api/webhooks/deliveries?webhook=<WH_UUID>&p=2
HTTP/1.1 200 OK
{"paging":{"pageIndex":2,"pageSize":10,"total":1},"deliveries":[]}
```

The `total` value reveals that the private webhook has received deliveries, confirming both the validity of the webhook UUID and the activity level of that webhook.

**Verified on SonarQube 26.5.0.122743 (community edition, Docker).**

### Impact

An authenticated low-privilege user who obtains a webhook UUID (e.g., through log leakage or insider access) can:

1. Confirm that the UUID belongs to a valid, active webhook
2. Determine the exact number of webhook deliveries that have been triggered
3. Perform this reconnaissance without triggering access-denied audit events (since the server returns HTTP 200)

This is an information disclosure vulnerability rated low-severity because: the attacker must already be authenticated; webhook UUIDs are not obtainable through normal low-privilege API access; no delivery payload content is exposed (only the count); and SonarQube's standard deployment with `force_authentication=true` limits the attack to authenticated users.
