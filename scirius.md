https://github.com/StamusNetworks/scirius

## Finding: Arbitrary file write via path traversal in PCAP upload endpoint (User role, Scirius <= 3.8.0)

## Details:

There is a path traversal vulnerability in Scirius that allows any user holding the default "User" role to write attacker-controlled files to arbitrary filesystem paths on the server.

The vulnerable endpoint is `POST /rest/rules/filestore_pcap/upload/`, implemented in `suricata/rest_api.py` (class `PcapFilestoreViewSet`, method `upload`). The endpoint is protected by the `events_view` permission, which is granted to every non-administrative user by default.

The upload handler reads a filename from the `_id` field of a user-supplied JSON file and passes it without sanitization to `os.path.join('/tmp', '%s.json' % filename)`. Setting `_id` to a path like `../../etc/cron.d/pwn` causes the server to write the user-controlled `_source` content to `/etc/cron.d/pwn.json`. The official Dockerfile contains no `USER` directive, so Scirius runs as root in the Docker/SELKS deployment, making this a direct path to remote code execution.

Reproduction (against a local instance with a "User"-role API token):

```
# Write file outside /tmp/ via _id traversal
cat > /tmp/traversal.json <<'EOF'
{"_id": "../tmp/traversal_success", "_source": {"PWNED": "arbitrary_write"}}
EOF

curl -s -X POST "http://<scirius>/rest/rules/filestore_pcap/upload/?format=json" \
  -H "Authorization: Token <user-role-token>" \
  -F "file=@/tmp/traversal.json;type=application/json"
# Response: {"upload":"done","filename":"../tmp/traversal_success"}

# Confirm the file was written one level above /tmp/
cat /tmp/traversal_success.json
# Output: {"PWNED": "arbitrary_write"}
```

I validated this against commit 3bb49d3 (Scirius CE 3.8.0, current HEAD as of 2026-06-19).

The fix is to sanitize `filename` before constructing `src_path`, for example:

```python
import os
filename = os.path.basename(json_file['_id'])
```

This ensures the filename cannot escape the `/tmp/` directory.

### Disclosure

 - 19 June 2026 - reported via email
 - 20 June 2026 - report accepted and is being evaluated
 - 17 August 2026 - followed up
 - 14 September 2026 - no response; disclosed 
