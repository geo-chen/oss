https://github.com/suitenumerique/docs/

## Finding: Revoking document access does not close live collaboration sessions on sub-documents

## Summary

When a document is shared at a parent/folder level and a user's access is
later revoked, the REST API immediately (and correctly) starts returning 403
for that user on every document in the tree. However, if that user already had
a sub-document open in the real-time collaborative editor, their websocket
session to the `y-provider` collaboration server is never notified and stays
fully functional - they keep receiving and sending live edits indefinitely.

Root cause: `DocumentAccessViewSet.perform_update` / `perform_destroy` in
`src/backend/core/api/viewsets.py` (around lines 2825-2856) always call
`CollaborationService().reset_connections(str(access.document.id), ...)` using
the id of the document the access record itself is attached to. When access is
granted/revoked at a parent level, this never reaches the room of any
descendant document, because `collaborationResetConnectionsHandler.ts`
(y-provider) only closes connections whose room name exactly equals the id
that was passed in.

Reproduction (full stack via the repo's dev `compose.yml`, two accounts from
`docker/auth/realm.json`):

1. User A creates parent doc `10ed89d7-6bcb-4677-b9d0-b0f82280210f` and child
   doc `c7ac4998-af77-4a21-ad2a-82db97cc5295`, then grants User B `editor` on
   the parent (`POST .../10ed89d7.../accesses/` with User B's id).
2. User B inherits editor rights on the child (`GET .../c7ac4998.../` shows
   `"user_role": "editor"`).
3. Both User A and User B open Hocuspocus websocket sessions to the
   child document's room and both sync successfully.
4. User A revokes User B's access on the parent:
   `DELETE .../10ed89d7.../accesses/c1c3c4bb-1c8c-4fd3-8d20-d40a723e9151/` -> 204.
5. `GET .../c7ac4998.../` as User B now correctly returns 403.
6. But the y-provider connection-count endpoint for the child room still
   reports both sessions active: `GET .../get-connections/?room=c7ac4998...`
   -> `{"count":2,"exists":false}`.
7. User B's still-open session inserts text into the shared document, and it
   is broadcast live to User A's still-connected client - both clients end up
   showing `"INJECTED-BY-REVOKED-USER-B"`, after the access was already
   revoked.
8. As a control, calling the same reset endpoint with the child's own room id
   directly does close a live connection for that room, confirming the
   mechanism works and is simply never invoked with the right id from the
   access-revocation code path.

Suggested fix: when a `DocumentAccess` is created, updated, or deleted, walk
`document.get_descendants()` (already used for cascades elsewhere, e.g.
`Document.soft_delete()`) and call `reset_connections` for every descendant
document id as well, not just the document the access row is attached to.

### Disclosure
 - 6 July 2026 - reported via email
 - 25 August 2026 - followed up via email
 - 25 August 2026 - fixed via https://github.com/suitenumerique/docs/commit/d35b81a6ed526dc284c8d0f68b762f2e81ffab13

