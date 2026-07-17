https://github.com/vanna-ai/vanna - "This repository was archived by the owner on Mar 29, 2026. It is now read-only."

## Finding: Unauthenticated path traversal (arbitrary file write + out-of-base read) via client-controlled conversation_id in FileSystemConversationStore

Affected Version: commit 365d061

### Summary

The file-backed conversation store builds filesystem paths by concatenating a client-supplied `conversation_id` directly onto its base directory with no sanitization or containment check. The chat server accepts `conversation_id` from the unauthenticated request body and passes it through unchanged. An attacker can therefore set `conversation_id` to a `../` traversal sequence and write attacker-controlled JSON (conversation metadata and per-message files whose content is the attacker's chat text) anywhere the server process can write, and read conversation metadata from outside the store base. Confirmed against the class: attacker content was written outside `base_dir` and a cross-base file was read back via traversal.

### Details

`src/vanna/integrations/local/file_system_conversation_store.py`:

```python
def _get_conversation_dir(self, conversation_id):
    return self.base_dir / conversation_id      # ~line 40, raw concatenation, no sanitization
...
conv_dir.mkdir(parents=True, exist_ok=True)     # ~line 53
json.dump(..., f)                               # _save_metadata ~62, _append_message ~99
```

`conversation_id` is concatenated as a raw path component with no `..` rejection and no `relative_to` containment, unlike the sibling `LocalFileSystem._resolve_path`, which does enforce containment. Data flow, all unauthenticated:

1. Source: `ChatRequest.conversation_id` (`src/vanna/servers/base/models.py:20`, `Optional[str]`, no validator), reached via the unauthenticated endpoints `POST /api/vanna/v2/chat_sse | chat_poll | chat_websocket` (`src/vanna/servers/fastapi/routes.py`). The default server binds `0.0.0.0` with no auth (`servers/cli/server_runner.py`).
2. `ChatHandler.handle_stream` -> `Agent.send_message(conversation_id=...)` passes it through unchanged (`core/agent/agent.py:142+`); a UUID is generated only when the id is `None`.
3. `Agent` calls `conversation_store.get_conversation(id, user)` and `update_conversation(conversation)`, persisting attacker-controlled message content.
4. In `FileSystemConversationStore`, the id becomes the directory path and escapes `base_dir`.

Two impacts: arbitrary file write (CWE-22) of attacker JSON to any writable location (config/autoload dirs, cron.d, web roots), and out-of-base / cross-tenant read (CWE-22/639) since `get_conversation` reads `metadata.json` from the traversed path and only afterward compares `metadata["user"]["id"]`, a gate the path escape sidesteps.

The untrusted input is the unauthenticated network request. No victim-authored artifact is required. `FileSystemConversationStore` is a first-class shipped persistence integration (exported from `vanna.integrations.local`); deployments selecting it for the chat server are exploitable. The in-memory default store scopes by `user.id` and is not affected.

### PoC

```
POST /api/vanna/v2/chat_sse
{ "message":"ATTACKER_CONTROLLED_CONTENT_12345",
  "conversation_id":"../../../../tmp/fake_cron.d/payload" }
```

Validated against the class (commit 365d061), calling the `create_conversation` / `update_conversation` / `get_conversation`:

```
write: base_dir=/tmp/vanna_poc/app_base  id=../victim_outside/pwned_by_vanna
  files written OUTSIDE base_dir:
    /tmp/vanna_poc/victim_outside/pwned_by_vanna/metadata.json
    /tmp/vanna_poc/victim_outside/pwned_by_vanna/messages/..._000000.json
      content: {"role":"user","content":"ATTACKER_CONTROLLED_CONTENT_12345", ...}

deep traversal id: ../../../../../../../../../../tmp/vanna_poc/fake_cron.d/payload
  exists: True
  cross-base read via traversal -> ['VICTIM_PRIVATE_DATA']
```

### Impact

An unauthenticated network client of a vanna chat server configured with `FileSystemConversationStore` writes attacker-controlled JSON to arbitrary filesystem locations the server can write (enabling tampering and, where the location is executable/auto-loaded, code execution) and reads conversation metadata from outside the store base. Integrity and availability impact is high; confidentiality is limited to JSON files the store can parse.

### Remediation

In `FileSystemConversationStore`, validate and normalize `conversation_id` before any path use: reject ids containing `/`, `\`, `..`, or null bytes (or enforce a strict UUID / `[A-Za-z0-9_-]` regex), and after joining verify `(self.base_dir / conversation_id).resolve().relative_to(self.base_dir.resolve())`, the same containment pattern already used in `LocalFileSystem._resolve_path`. Generate `conversation_id` server-side rather than trusting the client, and gate read/write on ownership before touching the filesystem.
