
# Stored XSS in Actions run page via user Full Name field

https://codeberg.org/forgejo/forgejo

## Details
Stored cross-site scripting vulnerability in Forgejo's Actions run view that affects instances where `DEFAULT_SHOW_FULL_NAME = true` is configured.

**File:** `routers/web/repo/actions/view.go`, lines 279-283 and 296  
**Sink:** `web_src/js/components/RepoActionView.vue`, line 507  
**Confirmed on:** commit f4c319d (development branch, after v11.0.14)  
**Condition:** `[ui] DEFAULT_SHOW_FULL_NAME = true` in app.ini (non-default)

## What is happening

When `DEFAULT_SHOW_FULL_NAME` is enabled, `GetDisplayName()` returns a user's raw `FullName`. This value is interpolated via `fmt.Sprintf` into an HTML-bearing locale format string (`on_push_description`) with no HTML escaping, producing a string like:

```
Commit <a href="...">abc123</a> pushed by <a href="/attacker"><PAYLOAD></a>
```

This string is stored in `resp.State.Run.Description` and served in the Actions run JSON response. The Vue frontend renders it via `v-html="run.description"` without sanitization. Any user who visits the Actions run URL for a run triggered by the attacker has the payload execute in their browser.

## Who can exploit it

Any registered user on an instance with `DEFAULT_SHOW_FULL_NAME = true`. No elevated permissions are required -- only the ability to push to a repository with Actions enabled.

## Fix

HTML-escape the display name before interpolation into the format string:

```go
runDescription = ctx.Locale.TrString("actions.runs.on_push_description",
    run.CommitLink(),
    base.ShortSha(run.CommitSHA),
    run.TriggerUser.HomeLink(),
    html.EscapeString(run.TriggerUser.GetDisplayName()))
```

The same fix should be applied to the `workflow_dispatch_description` branch at line 279.

## Disclosure
 - 22 May 2026 - Reported via email
 - 23 May 2026 - Maintainer acknowledged saying they will coordinate a patch
 - 1 July 2026 - followed up to check on patch
 - 2 July 2026 - Maintainer advised that was released https://codeberg.org/forgejo/forgejo/src/branch/forgejo/release-notes-published/15.0.3.md and https://codeberg.org/forgejo/forgejo/pulls/13002

<img width="638" height="326" alt="image" src="https://github.com/user-attachments/assets/35e72d28-4e60-4a42-a54a-14d8f2b673e1" />
<img width="778" height="184" alt="image" src="https://github.com/user-attachments/assets/14bd9224-066a-422b-a416-361ef411ca98" />

