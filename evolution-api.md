https://github.com/evolution-foundation/evolution-api

## Finding: Evolution API — Prometheus metrics IP allowlist bypass 

**Version: (v2.3.7)**

### Disclosure

 - 14 June 2026 - reported via email
 - 30 June 2026 - acknowledged and fix in progress
 - 14 September 2026 - disclosed


### Email

I am reporting a security vulnerability in evolution-api v2.3.7 that allows unauthenticated remote access to the Prometheus metrics endpoint even when an IP allowlist is configured.

The metricsIPWhitelist middleware in src/api/routes/index.router.ts (line 58) contains a JavaScript type error. The access control check reads:
```
  if (allowedIPs.filter(ip => clientIPs.includes(ip)) === 0) {
```
Array.prototype.filter() returns an Array, not a number. A JavaScript Array is never strictly equal to the number 0, so this condition is always false and the 403 block is never reached. Every request, from every IP, passes through to the /metrics handler regardless of the METRICS_ALLOWED_IPS setting.

This only affects deployments with PROMETHEUS_METRICS=true and METRICS_ALLOWED_IPS set. If METRICS_AUTH_REQUIRED=true is also set, the subsequent Basic Auth check provides a second layer that continues to work correctly. The exposed window is specifically: metrics enabled, ALLOWED_IPS configured, AUTH_REQUIRED omitted or false.

The /metrics endpoint leaks server version, database client name, server URL, and all WhatsApp instance names with their integration types and connection states. In production multi-tenant deployments instance names frequently correspond to company or client identifiers.

I confirmed this by running a Docker container of v2.3.7 with METRICS_ALLOWED_IPS=127.0.0.1 and METRICS_AUTH_REQUIRED=false. A curl request from a non-loopback address received HTTP 200 and the full metrics payload.

Suggested fix: change the comparison from array equality to checking the array length:
```
  if (allowedIPs.filter(ip => clientIPs.includes(ip)).length === 0) {
```
Additionally, consider enabling METRICS_AUTH_REQUIRED in the default env.example to reduce misconfiguration risk.

<img width="1250" height="633" alt="image" src="https://github.com/user-attachments/assets/8b2bdcad-a11d-4d34-b9d3-64f4956c2a06" />
