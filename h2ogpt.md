https://github.com/h2oai/h2ogpt - "This repository was archived by the owner on Feb 26, 2026. It is now read-only."

## Finding: Path traversal (arbitrary file read/delete/write) via the Authorization header in the OpenAI-compatible files API (default no-auth posture)

Affected Version: 0.2.1

### Summary

h2oGPT's OpenAI-compatible server derives the per-user storage directory from the bearer token string in the `Authorization` header, using it unsanitized as a path component. The files endpoints then read, delete, and write a path built from that directory. When the server is started with the default API key value (`EMPTY`), authentication is disabled and any attacker-chosen bearer value is accepted, so an unauthenticated client can place `..` segments in the bearer token to read, delete, and write arbitrary files on the host. Confirmed against the booted server: a traversal bearer token read a file above the app directory and `/etc/passwd`.

### Details

`openai_server/backend_utils.py`, `get_user_dir` (~lines 333 to 336):

```python
user_dir = os.path.join(base_path, authorization.split(" ")[1])   # bearer token used as a directory name, unsanitized
```

The files endpoints in `openai_server/server.py` build the target path from `user_dir`:

- `GET /v1/files/{file_id}/content` -> `open(file_path)` (~lines 1202/1215): arbitrary read
- `DELETE /v1/files/{file_id}` -> `os.remove(file_path)` (~lines 1176/1182): arbitrary delete
- `POST /v1/files` -> `run_upload_api` `open(file_path, "wb")` (`backend_utils.py` ~lines 349 to 353): arbitrary write (with directory creation)

The untrusted input is the `Authorization: Bearer <X>` header, where `<X>` becomes the path component (the `{file_id}` URL segment is blocked by Starlette's `[^/]+` convertor, but the header is not). Authentication: `verify_api_key` defaults `H2OGPT_OPENAI_API_KEY = 'EMPTY'`, which disables auth and returns immediately, so any bearer value is accepted. This is the shipped default. When an API key is configured, the exact `== "Bearer <key>"` comparison rejects a traversal token, so the issue is network-unauthenticated in the default posture.

### PoC

Validated against the route bodies and `get_user_dir` / `run_upload_api` (booted on uvicorn):

```
# read a file above the app dir
curl -H 'Authorization: Bearer u1/../../..' .../v1/files/SECRET_outside.txt/content
   -> TOP-SECRET-OUTSIDE-USERDIR   [200]
# absolute read of /etc/passwd
curl -H 'Authorization: Bearer u1/../../../../../../../../../etc' .../v1/files/passwd/content
   -> root:x:0:0:root:/root:/bin/bash ...   [200]
```

A upload first created `openai_files/u1/` (as production does); the `..` segments in the token escaped it. `DELETE` and `POST` reach the same path and provide arbitrary delete and write.

### Impact

Against an h2oGPT OpenAI-compatible server in its default posture (no API key configured), an unauthenticated remote attacker reads any file the process can access (configuration, credentials, `/etc/passwd`), deletes arbitrary files, and writes attacker-controlled files (which can escalate to code execution via a write to a startup hook or a served/loaded file). The condition is the default `EMPTY` key; configuring a key blocks the header payload.

### Remediation

Reject `Authorization` values whose bearer component contains a path separator or `..`, and confine the final path under the resolved user directory (`os.path.realpath(file_path)` must start with `os.path.realpath(user_dir) + os.sep`) before any open/remove. Do not derive a filesystem path from an authentication token; map authenticated users to directory names through a safe lookup. Refuse to run the OpenAI server with auth disabled on a non-loopback interface.
