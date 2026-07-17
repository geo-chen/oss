https://github.com/voideditor/void - "This repository was archived by the owner on Jun 3, 2026. It is now read-only."

- first reported to Mitre 12 June 2026


## Finding: Agent read_file tool reads arbitrary host files with no workspace confinement and no approval gate

Affected Version: v1.3.4

### Summary

Void's AI agent exposes a `read_file` tool (and `ls_dir`, `get_dir_tree`, `search_*`) that accepts any absolute path or `file://` URI with no restriction to the open workspace and with no approval prompt in any chat mode. An attacker who can inject instructions into content the agent reads (indirect prompt injection from a repository file, web page, or tool result) can make the agent silently read sensitive host files outside the workspace, such as SSH keys or cloud credentials, and then exfiltrate them via a following tool call. Both the lack of confinement and the lack of an approval gate were confirmed against the source.

### Details

`src/vs/workbench/contrib/void/browser/toolsService.ts`, `validateURI` (around lines 42 to 68), with an explicit developer comment at line 41 (`// We are NOT checking to make sure in workspace`), accepts any absolute path / `file://` URI. Run against the function:

```
validateURI("/etc/passwd")        => file:///etc/passwd
validateURI("file:///etc/passwd") => file:///etc/passwd
```

The `read_file` validator (`toolsService.ts` ~line 160) calls `validateURI` and returns the URI with no added workspace check, and no caller adds one.

The approval gate is keyed by `approvalTypeOfBuiltinToolName` (`src/vs/workbench/contrib/void/common/toolsServiceTypes.ts`, around lines 21 to 30), which maps only the edit and terminal tools:

```ts
export const approvalTypeOfBuiltinToolName = {
  'create_file_or_folder': 'edits', 'delete_file_or_folder': 'edits',
  'rewrite_file': 'edits', 'edit_file': 'edits',
  'run_command': 'terminal', 'run_persistent_command': 'terminal',
  'open_persistent_terminal': 'terminal', 'kill_persistent_terminal': 'terminal',
}
```

`read_file` / `ls_dir` / `get_dir_tree` / `search_*` are absent, so in the gate (`src/vs/workbench/contrib/void/browser/chatThreadService.ts` ~lines 644 to 652) `approvalType` is `undefined` and the `if (approvalType)` block is skipped: these tools run with zero approval in every chat mode (gather and agent).

The boundary crossed is the workspace, which the product presents as the bound of the agent's file context. The combination (no confinement plus no approval) means a single agent `read_file` of an out-of-workspace secret path executes silently.

### PoC

Two source-level checks confirm the two gaps, then an end-to-end scenario:

1. No path confinement on reads. In `src/vs/workbench/contrib/void/.../toolsService.ts`, `validateURI` (lines 42-68, with the developer comment at line 41 "We are NOT checking to make sure in workspace") returns a usable URI for any absolute or `file://` path; the `read_file` validator (toolsService.ts:160) calls `validateURI` with no workspace check:
   ```
   validateURI('/etc/passwd')          -> file:///etc/passwd   (no throw, no containment)
   validateURI('file:///etc/passwd')   -> file:///etc/passwd
   ```
2. No approval gate for reads. `approvalTypeOfBuiltinToolName` (`common/toolsServiceTypes.ts:21-30`) maps only edit/terminal tools; `read_file`/`ls_dir`/`get_dir_tree`/`search_*` are absent, so the approval block in `chatThreadService.ts:644-652` is skipped entirely (every approval mode).

End to end: a poisoned file the agent reads (indirect prompt injection) instructs it to call `read_file {"uri":"/home/<user>/.ssh/id_rsa"}` (or `~/.aws/credentials`); the contents return into the model context with no approval dialog, and a subsequent tool call (a fetch, a write into the repo, a command) exfiltrates them.

Confirmed against the source: `validateURI('/etc/passwd')` and `validateURI('file:///etc/passwd')` both return a usable `file:///etc/passwd` URI (no throw, no containment), and `approvalTypeOfBuiltinToolName` has no `read_file` entry (so the approval block is skipped). End to end, a poisoned file the agent reads can instruct it to call `read_file {"uri":"/home/<user>/.ssh/id_rsa"}` (or `~/.aws/credentials`); the contents return into the model context with no approval dialog, and a subsequent tool call (a fetch, a write into the repo, a command) exfiltrates them.

### Impact

Indirect prompt injection (untrusted content the agent reads) yields silent reads of arbitrary host files outside the workspace, with no approval, followed by exfiltration. The directly validated primitive is an unconfined, unapproved arbitrary file read by the agent; the end-to-end secret-theft chain additionally requires prompt injection to drive the read and a follow-up exfiltration call.

### Remediation

Confine `read_file` / `ls_dir` / `get_dir_tree` / `search_*` to the workspace folders by default (resolve the path and assert it is within an open workspace root), and require approval (or an explicit out-of-workspace consent) for reads outside the workspace. Treat read tools as security-relevant in `approvalTypeOfBuiltinToolName` rather than omitting them.
