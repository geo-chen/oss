https://github.com/pixelfed/pixelfed

## Finding: Missing authorization on Story reply/reaction endpoints (cross-user IDOR + private-story media disclosure)

Package: pixelfed (app/Http/Controllers/Stories/StoryApiV1Controller.php, app/Http/Controllers/StoryComposeController.php)

Affected Versions: confirmed on current main (commit 032e443)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4 Medium)

CWE: CWE-862 Missing Authorization (with CWE-639 / CWE-200)

### Summary

The story reply and reaction endpoints fetch a story by an attacker-supplied numeric id and gate only on the story's `can_reply`/`can_react` flags; they never verify the requester follows the author or has visibility of the story. Stories are follower-only (and for private accounts, approved-follower-only), so a non-follower can interact with a private account's story, learn it exists, receive its media URL, and force an unsolicited DM and notification to the victim. Confirmed by invoking the shipped controller methods in a booted Laravel kernel: a non-follower wrote a story reply to a private account's story and the media URL was leaked.

### Details

Sinks (both controller variants share the defect):

- `app/Http/Controllers/Stories/StoryApiV1Controller.php:659` `comment()` -- only `abort_if(! $story->can_reply, 422)` at :671, then writes a `Status`, `DirectMessage` (leaking `story_media_url` + `story_username` at :690-696), `Conversation`, and `Notification` to the victim.
- `app/Http/Controllers/StoryComposeController.php:565` `comment()` (route `StoryController@comment`) -- same pattern at :578.
- `app/Http/Controllers/StoryComposeController.php:486` `react()` -- only `abort_if(! $story->can_react, 422)` at :499; same DM/notification + `story_media_url` leak at :525-531.

Routes (authenticated): `routes/web-api.php:158-159` (`web/stories/v1/react`, `web/stories/v1/comment`) and `routes/api.php:255,422`.

The intended control exists elsewhere and was omitted here: `viewed()` enforces it (`StoryApiV1Controller.php:634-635`, `Follower::whereProfileId...->whereFollowingId...->exists()` then `abort_if(! $following, 403)`), and `storyPollVote()` (`StoryComposeController.php:405`) and `storeReport()` (:460) call `FollowerService::follows()`. The source is an authenticated low-privilege attacker controlling `sid` (enumerable numeric story id) plus `caption`/`reaction`; no follow/visibility/block check gates the DB writes.

The boundary crossed is cross-user authorization: a non-follower interacts with a private account's follower-only story. Impact: a private-story existence oracle (enumerate `sid`); disclosure of the story media URL (`story_media_url`) and author username returned in the attacker's own DM/conversation thread; and a forced unsolicited DM plus in-app notification to a victim who never approved the attacker.

### PoC

```
POST /api/web/stories/v1/comment   { "sid": "<victim private story id>", "caption": "x" }
POST /api/web/stories/v1/react     { "sid": "<victim private story id>", "reaction": "..." }
# attacker does not follow the victim; DM with story_media_url is created in the attacker's thread
```

Validated by installing the composer deps, booting the actual Laravel kernel against a SQLite DB built from the project's  migrations, seeding a private victim + unrelated attacker + a victim story (`can_reply/can_react=true`, no follower rows), authenticating as the attacker via `Auth::login`, and invoking the shipped controller methods with a `Illuminate\Http\Request` (no vulnerable logic modified):

```
attacker follows victim? (DB followers rows) = 0 -> no follow relationship
Auth::user()->username = attacker
--- Invoking StoryApiV1Controller::comment() ---
DirectMessage CREATED from attacker -> victim (id=1, type=story:comment)
  LEAKED via DM meta -> story_media_url = https://localhost/storage/_esm/secret-private-story-media-XYZ.jpg
  LEAKED via DM meta -> story_username  = victim
Notification CREATED to victim (action=story:comment) -> unsolicited contact
=== VULNERABLE: a non-follower wrote a story reply to a PRIVATE account's story ===
```

A second run against the older `StoryController@comment` reproduced it (`media_url leaked=...secret-XYZ.jpg`). The `react()` path reaches the same unauthorized region (a Redis-backed react counter throws first only in the Redis-less harness, which is after the missing follow check). The only environment adjustment was relaxing a SQLite-only `statuses.rendered NOT NULL` artifact (MySQL provides a default), orthogonal to the auth check.

### Impact

Any registered user reads whether a private account has an active story and obtains its media URL and author, and forces unsolicited DMs/notifications to users who never approved them, bypassing the follower gate. Confidentiality and integrity low; requires the stories feature enabled (standard).

### Remediation

In `react()` and both `comment()` methods, add the same follower/visibility gate used by `viewed()`/`storyPollVote()` before any write, e.g.:

```php
abort_if($story->profile_id !== $pid && ! FollowerService::follows($pid, $story->profile_id), 403, 'Invalid permission');
```

Also honor blocks and do not echo `story_media_url` to non-authorized actors.


## Disclosure
 - 20 May 2026 - reported via email
 - 13 June 2026 - followed up via email
