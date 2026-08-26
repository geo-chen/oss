https://github.com/openfaas/faas/issues/4329

## Finding: /system/telemetry endpoint omitted from BasicAuth wrap, allowing unauthenticated proxy to the OpenFaaS provider's telemetry

Affected Versions: Confirmed on commit f4dc39f8 (HEAD as of 2026-05-25) and ghcr.io/openfaas/gateway:latest (gateway 0.27.13 CE)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)

CWE: CWE-306 (Missing Authentication for Critical Function)

### Summary
When `basic_auth=true` is configured, the OpenFaaS gateway wraps every administrative `/system/*` handler in `auth.DecorateWithBasicAuth` — except `TelemetryHandler`. The `/system/telemetry` route therefore reaches the forwarding proxy without authentication and returns whatever the configured provider (faasd, faas-netes) responds with for `/system/telemetry`. The same omission is visible in the source as a clearly inconsistent treatment compared to `InfoHandler`, `ListFunctions`, and the rest of the `/system/*` family.

### Details

File: `gateway/main.go`

The handler is created at line 132:

```go
faasHandlers.TelemetryHandler = handlers.MakeForwardingProxyHandler(reverseProxy, forwardingNotifiers, urlResolver, nilURLTransformer, nil)
```

And registered on the mux at line 213:

```go
r.HandleFunc("/system/telemetry", faasHandlers.TelemetryHandler).Methods(http.MethodGet)
```

The BasicAuth wrap block at lines 177-205 wraps every other `/system/*` handler:

```go
if credentials != nil {
    faasHandlers.Alert            = auth.DecorateWithBasicAuth(faasHandlers.Alert, credentials)
    faasHandlers.UpdateFunction   = auth.DecorateWithBasicAuth(faasHandlers.UpdateFunction, credentials)
    faasHandlers.DeleteFunction   = auth.DecorateWithBasicAuth(faasHandlers.DeleteFunction, credentials)
    faasHandlers.DeployFunction   = auth.DecorateWithBasicAuth(faasHandlers.DeployFunction, credentials)
    faasHandlers.ListFunctions    = auth.DecorateWithBasicAuth(faasHandlers.ListFunctions, credentials)
    faasHandlers.ScaleFunction    = auth.DecorateWithBasicAuth(faasHandlers.ScaleFunction, credentials)
    faasHandlers.FunctionStatus   = auth.DecorateWithBasicAuth(faasHandlers.FunctionStatus, credentials)
    faasHandlers.InfoHandler      = auth.DecorateWithBasicAuth(faasHandlers.InfoHandler, credentials)
    faasHandlers.SecretHandler    = auth.DecorateWithBasicAuth(faasHandlers.SecretHandler, credentials)
    faasHandlers.LogProxyHandler  = auth.DecorateWithBasicAuth(faasHandlers.LogProxyHandler, credentials)
    faasHandlers.NamespaceListerHandler  = auth.DecorateWithBasicAuth(faasHandlers.NamespaceListerHandler, credentials)
    faasHandlers.NamespaceMutatorHandler = auth.DecorateWithBasicAuth(faasHandlers.NamespaceMutatorHandler, credentials)
}
```

`TelemetryHandler` is not in this list, so the registered route at `/system/telemetry` is reachable without credentials.

### PoC

Tested against `ghcr.io/openfaas/gateway:latest` (gateway 0.27.13 CE) with `basic_auth=true` configured (admin/testpass credentials in `/run/secrets/basic-auth-{user,password}`) and an unreachable dummy provider URL.

```
GET /system/functions HTTP/1.1
Host: localhost:8080
->
HTTP/1.1 401 Unauthorized
Www-Authenticate: Basic realm="Restricted"

GET /system/info HTTP/1.1
Host: localhost:8080
->
HTTP/1.1 401 Unauthorized

GET /system/telemetry HTTP/1.1
Host: localhost:8080
->
HTTP/1.1 502 Bad Gateway
(handler reached forwarding-proxy stage and tried to reach the upstream provider — BasicAuth did not block the request)
```

The 502 confirms the request bypassed the BasicAuth middleware and reached the forwarding-proxy logic. With a provider running upstream (faasd or faas-netes), `/system/telemetry` returns whatever provider state that endpoint exposes (CPU/memory/container counts depending on provider).

### Impact

Any client with network reach to the OpenFaaS gateway port can read the FaaS provider's telemetry output without credentials, regardless of the `basic_auth=true` setting. The exact content depends on the provider — for faasd, this typically includes resource metrics (function invocations, system stats); for faas-netes (Kubernetes), this may include pod/cluster info. Even when content is "telemetry only", the inconsistent omission from the BasicAuth wrap defeats the operator's intent for the entire `/system/*` namespace.

Suggested fix: add `faasHandlers.TelemetryHandler = auth.DecorateWithBasicAuth(faasHandlers.TelemetryHandler, credentials)` to the BasicAuth wrap block in `gateway/main.go`. Alternatively, refactor the wrapping into a per-route loop driven by a slice/map so future `/system/*` additions cannot accidentally miss the wrap.

### Disclosure
 - 25 May 2026: reported via email; no response
 - June/July: opened https://github.com/openfaas/faas/issues/4329 but got deleted

<img width="1039" height="338" alt="image" src="https://github.com/user-attachments/assets/6eb17efb-388a-48d0-9e47-f02438f9dea9" />

