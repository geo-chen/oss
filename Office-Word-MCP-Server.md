https://github.com/GongRzhe/Office-Word-MCP-Server - "This repository was archived by the owner on Mar 3, 2026. It is now read-only."

## Finding: No path confinement: arbitrary .docx read and write/overwrite outside the working directory (absolute paths and ../ traversal)

Package: office-word-mcp-server (PyPI)

Affected Versions: confirmed on 1.1.11 (latest)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

CWE: CWE-22 Path Traversal

### Summary
The document tools accept a filename with no base-directory confinement. There is no root, no realpath/commonpath check, and absolute paths and ../ traversal are honored. As a result an attacker who can influence the filename argument can read any .docx file the process can access and create or overwrite .docx files anywhere writable, outside the intended directory. Confirmed on 1.1.11: get_document_text read a .docx outside the working directory, and create_document wrote files outside it via both an absolute path and a ../ path.

### Details
word_document_server/utils/file_utils.py check_file_writeable (around lines 9-43) performs no base-directory confinement; ensure_docx_extension (around lines 73-85) only appends ".docx". The tool handlers use the raw path: word_document_server/tools/document_tools.py create_document -> doc.save(filename) (around line 43), and get_document_text -> extract_document_text(filename) (around lines 68-76). No path is validated against an allowed directory. Because ensure_docx_extension forces a .docx extension, reads/writes are limited to .docx files (arbitrary-location read/overwrite of Office documents, not arbitrary /etc/passwd LFI).

### PoC
Validated on office-word-mcp-server 1.1.11 with the working directory set to /tmp/word_intended (the "intended" location), calling the tools:
```
OOB READ /tmp/word_outside/victim.docx -> True | VICTIM-OOB-SECRET-7799
../ traversal write exists: True
```
get_document_text("/tmp/word_outside/victim.docx") returned the document text "VICTIM-OOB-SECRET-7799" from outside the working directory, and create_document("../word_outside/TRAVERSAL_WRITE") created /tmp/word_outside/TRAVERSAL_WRITE.docx outside it (absolute-path writes outside the dir likewise succeed).

### Impact
An attacker who can influence the filename (LLM-produced, prompt-injection steerable) can read the contents of any .docx on the host (for example documents in other users' directories) and create or overwrite .docx files anywhere the process can write (overwriting a victim's documents, or planting content in a shared location). There is no confinement to an intended directory.

### Remediation
Confine all file operations to an explicitly configured base directory: resolve the requested path with os.path.realpath and verify with os.path.commonpath that it is within the allowed root, rejecting absolute paths outside it and ../ escapes (and symlinks that leave the root). Apply this in check_file_writeable and before every open/save/extract in the tool handlers.

