https://github.com/reworkd/AgentGPT - "This repository was archived by the owner on Jan 28, 2026. It is now read-only."


## Finding: Missing object-level authorization: a user can attach tasks to another user's agent run (cross-user run IDOR)

Affected Version: v1.0.0

### Summary

The AgentGPT backend identifies the caller from a server-side session token, but its agent-task creation path looks up the target `AgentRun` by a client-supplied `run_id` without verifying that the run belongs to the authenticated user. An authenticated user who knows another user's `run_id` can therefore attach tasks to that other user's run, corrupting the victim's task history and consuming the victim's per-run loop budget and LLM spend. The identifier is an unguessable UUID that is not returned to other users, which limits practical exploitability, so this is a missing-authorization (defense-in-depth) defect rather than a high-impact break. Confirmed against the CRUD/ORM code: a user attached a task to a different user's run with no error.

### Details

`platform/reworkd_platform/db/crud/agent.py`, `validate_task_count` (around line 38) and `create_task` (around lines 24 to 29):

```python
run = await AgentRun.get(self.session, run_id)   # db/base.py:28-29: bare PK lookup, no user_id filter
...
```

`run_id` is a client-supplied request body field (`schemas/agent.py` ~line 49, present on every `AgentRun`-derived request) passed through the dependency `web/api/agent/dependancies.py` (~lines 46 to 48) into `crud.create_task(body.run_id, type_)`, used by the `/agent/analyze`, `/execute`, `/create`, `/summarize`, and `/chat` validators. The caller's identity is available and correct (`get_current_user`, `web/api/dependencies.py` ~line 21, from the bearer session), but `AgentRun.user_id` is never compared to the authenticated user's id.

The boundary crossed is per-user object ownership (`AgentRun.user_id`). The check that should exist (ownership of the run) is absent on this path.

### PoC


```
POST /api/agent/execute   (authenticated as user B)
{ "run_id": "<user A's run_id>", ... }
```

Validated against the `AgentCRUD` / ORM (throwaway in-memory SQLite, no reimplementation):

```
[victim]   created run id=6d1c7403-...-7bc2f3d4d3e4  user_id=victim-1111
[attacker] create_task SUCCEEDED on victim's run     attacker=attacker-2222
[proof]    victim run (owner victim-1111) now has 1 task attached by attacker
```

An authenticated attacker (a different user) attached a task to the victim's run through the code path with no ownership error.

### Impact

An authenticated user who obtains another user's `run_id` attaches tasks to that user's agent run: corrupting the victim's task history, exhausting the victim's per-run `max_loops` budget (denial of the agent), and driving LLM cost against the victim's run/organization. There is no corresponding read route, so this is a cross-user write / cost-abuse issue, not data exfiltration. Practical exploitability is limited because `run_id` is an unguessable UUIDv4 that is not exposed to other users; the defect is the absent ownership check, which becomes exploitable if a `run_id` ever leaks (logs, a shared URL, an error message, or a future endpoint that returns it).

### Remediation

Enforce object-level authorization in `validate_task_count` / `create_task`: fetch the run scoped to the caller and reject if it is missing or not owned, for example `run = await AgentRun.get(self.session, run_id); if run is None or run.user_id != self.user.id: raise not_found()`. Apply the same ownership check to every route that accepts a client-supplied `run_id`.
