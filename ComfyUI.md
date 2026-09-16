https://github.com/Comfy-Org/ComfyUI

## Finding: Arbitrary file write (→ RCE) via `folder_name` path traversal in built-in dataset save nodes

Version: v0.24.0

## Summary

The built-in dataset save nodes take a free-form `folder_name` string and join it to the output directory with no sanitization, then write attacker-controlled file content there. A workflow can therefore write arbitrary content to an arbitrary path (`../../...`), e.g. into `custom_nodes/*/__init__.py`, `~/.bashrc`, or an autostart/cron file → code execution on next start.

## Details

`comfy_extras/nodes_dataset.py`, `SaveImageTextDataSetToFolderNode.execute` (L303-318):

```python
folder_name = folder_name[0]
output_dir = os.path.join(folder_paths.get_output_directory(), folder_name)  # L309: unsanitized
...
caption_path = os.path.join(output_dir, caption_filename)                     # L316
with open(caption_path, "w", encoding="utf-8") as f:
    f.write(caption)                                                          # L318: attacker content
```

`folder_name`, `filename_prefix`, and the caption `texts` are declared as free-form `io.String.Input` (L226/281/1443), **not** `io.Combo.Input`. ComfyUI's server-side validation (`execution.py:1025-1045`) only enforces allowed-value lists for Combo/list types; plain String inputs get no path sanitization, and these nodes define no `VALIDATE_INPUTS`. There is no `normpath`/`commonpath`/`..` check in `nodes_dataset.py`. Same unguarded `os.path.join(get_output_directory(), folder_name)` pattern at `SaveImageDataSetToFolderNode.execute` (L255, writes PNGs) and `SaveTrainingDataset` (L1477 → `torch.save` at L1503). The nodes are built-in (`nodes.py:2367` default `extras_files`), reachable via `POST /prompt`.

## PoC (validated against the shipped `folder_paths` resolver)

```
output_directory     = <comfyui>/output
attacker folder_name = ../../../../../../tmp/comfy_escape_demo
resolved write path  = /tmp/comfy_escape_demo/pwned_00000.txt
escaped output dir?  = True
file content read back = ARBITRARY ATTACKER CONTENT / #!/bin/sh / echo owned
```
(`scripts/poc_folder_name_traversal.py` — the caption-write branch needs neither torch nor PIL; `folder_paths` imports with stdlib.)

## Impact

Loading and running a malicious workflow (the in-scope ComfyUI threat) writes attacker-chosen content to an attacker-chosen path → integrity/availability High and realistic escalation to code execution.

## Net-new

Distinct from the published core path-traversal CVEs CVE-2026-6590 (`get_model_preview`, read) and CVE-2026-6591 (`get_annotated_filepath`, read), and from CVE-2024-21575 (ComfyUI-Impact-Pack, third-party). No advisory covers `nodes_dataset.py` / the `folder_name` write traversal. (`/view`, `/upload/*`, `/userdata` containment checks were tested and hold; the dataset *read* nodes use validated Combo inputs.)

## Remediation

Add a `normpath` + `commonpath` containment check (the same guard `server.py` uses) to every `os.path.join(get_output_directory()/get_input_directory(), folder_name)` in `nodes_dataset.py`, or convert `folder_name`/`filename_prefix` to sanitized inputs.


### Disclosure
 - 9 June 2026 - reported via https://github.com/Comfy-Org/ComfyUI/security/advisories/GHSA-8rx4-prq7-7vh8
 - 3 September 2026 - followed up
 - 17 September 2026 - still no response, disclosed
