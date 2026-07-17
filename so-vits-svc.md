https://github.com/svc-develop-team/so-vits-svc - "This repository was archived by the owner on Nov 12, 2023. It is now read-only."

## Finding: Unauthenticated arbitrary file read/exfiltration and arbitrary-location file write via audio_path in the /wav2wav Flask API

Affected Version: commit 730930d

### Summary

The so-vits-svc full-song inference server exposes a Flask `/wav2wav` route that takes a server-side filesystem path directly from the unauthenticated request body and passes it to the project's audio-loading code. The server binds `0.0.0.0` with no authentication (and the sibling `flask_api.py` additionally applies a wildcard CORS policy). An unauthenticated network client can name any path the server can decode, and the decoded audio is returned in the HTTP response, giving arbitrary file exfiltration of any server-side audio/media file. The same path also flows into a conversion helper that writes a new `.wav` next to the named path, an attacker-controlled-location write side-effect. Confirmed against the `format_wav` / `slicer` functions: a planted server-private file was exfiltrated and an attacker-located `.wav` was written.

### Details

`flask_api_full_song.py`:

```python
audio_path = request_form.get("audio_path", None)   # ~line 15, attacker-controlled
...
infer_tool.format_wav(audio_path)                    # ~line 19
chunks = slicer.cut(audio_path, db_thresh=slice_db)  # ~line 20
audio_data, audio_sr = slicer.chunks2audio(audio_path, chunks)  # ~line 21
...
return send_file(out_wav_path, ...)                  # ~line 48 -> response body
```

The `audio_path` value is taken verbatim from the POST form and reaches three sinks with no validation, canonicalization, or confinement:

- `inference/infer_tool.py` `format_wav` (~line 66): `librosa.load(audio_path)` then `soundfile.write(Path(audio_path).with_suffix(".wav"), ...)` -- decodes any path the attacker names and writes a sibling `.wav`.
- `inference/slicer.py` `cut` (~line 128): `librosa.load(audio_path)`.
- `inference/slicer.py` `chunks2audio` (~line 132): `torchaudio.load(audio_path)`.

The decoded result is returned to the caller via `send_file` (~line 48), so any file the server can decode is exfiltrated. Exposure: the server runs `app.run(host="0.0.0.0", port=1145)` with no auth; `flask_api.py` wraps the app in `CORS(app)` (wildcard `Access-Control-Allow-Origin: *`).

The untrusted input is the unauthenticated network request. The attacker reads and writes files that already exist on the victim's server and that they never supplied; this is not a victim-loads-attacker-artifact path.

### PoC

```
curl -X POST http://TARGET:1145/wav2wav \
  -F 'audio_path=/path/to/server_private_audio.mp3' \
  -F 'model_name=x.pth' -F 'config_name=x.json' -F 'f_pitch_change=0' \
  -F 'enhancer_adaptive_key=0' -F 'keychange=0' -F 'tran=0' -F 'spk=x'
# response body = the decoded server-side file (exfiltration)
```

Validated against the `inference.infer_tool.format_wav` and `inference.slicer` functions (commit 730930d), with the server bound to `0.0.0.0:1145` exactly as the file does; only the GPU `svc_model.infer()` (which runs after all the attacker-controlled file ops) was stubbed. A server-private file `victim_secret_dir/server_private_audio.mp3` (a 440 Hz tone) was planted, and a separate unauthenticated client posted its path:

```
POST /wav2wav  audio_path=.../victim_secret_dir/server_private_audio.mp3
-> HTTP 200 | exfiltrated bytes: 88244
-> exfiltrated audio sr=22050 samples=44100 dominant_freq~440Hz (planted=440Hz)   # contents left the server
-> NEW file server_private_audio.wav (88244 bytes) appeared next to the source     # attacker-located write
```

Both primitives fired on project code. (SSRF via `audio_path=http://...` was tested and did not fire on this librosa/soundfile build, so SSRF is not claimed.)

### Impact

An unauthenticated network client of a so-vits-svc full-song server reads and exfiltrates any audio/media file the server can decode (arbitrary file read), and triggers a `.wav` write at an attacker-named location (file-write side-effect that can clobber files next to any decodable path). With the wildcard CORS in `flask_api.py`, a malicious web page can also drive the request from a victim operator's browser context.

### Remediation

Do not accept a server-side filesystem path from the request. Accept the audio as an uploaded file (`request.files` into an in-memory `BytesIO`) as `flask_api.py` already does for its other route. If a path must be accepted, canonicalize with `os.path.realpath` and confine it to a dedicated input directory via an `os.path.commonpath` check, and reject URLs and non-allowlisted extensions. Bind to `127.0.0.1` by default rather than `0.0.0.0`, add an authentication token, and remove the unconfigured wildcard `CORS(app)`. Write conversions to a controlled temp directory instead of next to the source path.
