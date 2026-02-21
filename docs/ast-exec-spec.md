# LNAST v1 — Linux-Native AST Executable Contract

## 1. Normative Principles

LNAST is:
- deterministic,
- canonical,
- hash-stable,
- capability-scoped,
- syscall-lowered,
- verifier-first.

LNAST is not:
- a language,
- a bytecode VM,
- a JIT runtime,
- an implicit-semantics format.

LNAST is an **Executable Object Tree**.

---

## 2. Canonical Binary Schema (Normative)

### 2.1 Top-Level File Structure

```text
LNAST_FILE :=
  HEADER
  SYMBOL_TABLE
  NODE_TABLE
  CHILD_INDEX_TABLE
  METADATA_TABLE
  DATA_SECTION
```

All integers are fixed-width little-endian. Varints are disallowed.

### 2.2 Header (Fixed 64 bytes)

| Offset | Size | Field                     |
| ------ | ---- | ------------------------- |
| 0x00   | 4    | Magic = `LNA1`            |
| 0x04   | 2    | Version = `0x0001`        |
| 0x06   | 2    | Flags                     |
| 0x08   | 32   | Canonical Blake3-256 Hash |
| 0x28   | 8    | Capability Bitmap         |
| 0x30   | 4    | Symbol Count              |
| 0x34   | 4    | Node Count                |
| 0x38   | 4    | Child Index Count         |
| 0x3C   | 4    | Metadata Count            |

Canonical hash rule:
1. Zero bytes `0x08..0x27`.
2. Hash entire file with Blake3-256.
3. Write result back into hash field.

### 2.3 Symbol Table

```text
SYMBOL_ENTRY :=
  u16 length
  u8[length] utf8
```

Invariants:
- lexicographically strictly increasing,
- no duplicate symbols,
- UTF-8 only.

### 2.4 Node Table

```c
struct LNA_Node {
  uint16_t opcode;
  uint16_t arity;
  uint32_t child_start;
  uint32_t metadata_index;
};
```

Invariants:
- `arity` equals number of child indices for the node,
- indices are bounds-checked,
- node graph is acyclic,
- nodes are in topological order.

### 2.5 Child Index Table

Flat `uint32_t[]` storing child node indices.

### 2.6 Metadata Table

Typed immutable constant entries:
- `TYPE_U64`
- `TYPE_I64`
- `TYPE_STRING_REF`
- `TYPE_BYTES_REF`

### 2.7 Data Section

Opaque payloads referenced from metadata by offset/length.

---

## 3. Canonical Encoding Rules

To guarantee hash-stable identity:
- no optional fields in encoded structures,
- deterministic section ordering,
- deterministic node/child ordering,
- zero-padded alignment where required by versioned flags,
- reject non-canonical floating-point encodings in deterministic profiles.

Identity statement:

> Two files with the same canonical hash are identical executable objects under this versioned law.

---

## 4. Kernel Integration Draft (Native Loader)

### 4.1 Binfmt Path

Preferred path is a dedicated binfmt handler using `LNA1` magic:

- implementation target: `fs/binfmt_lnast.c`,
- registration path: `fs/exec.c`.

Sketch:

```c
static int load_lnast_binary(struct linux_binprm *bprm);

static struct linux_binfmt lnast_format = {
    .module = THIS_MODULE,
    .load_binary = load_lnast_binary,
};
```

### 4.2 `execve()` Flow

```text
execve()
  -> search_binary_handler()
      -> load_lnast_binary()
```

### 4.3 Kernel Validation Stages

1. Magic check (`LNA1`) else `-ENOEXEC`.
2. Canonical hash recomputation and compare.
3. Capability bitmap translation to kernel policy guards.
4. AST context allocation (`nodes`, `cap_mask`, task linkage).
5. Deterministic node execution loop.
6. Controlled exit via `do_exit()` on `OP_EXIT`.

### 4.4 Deterministic Mode Flag

`LNAST_FLAG_DETERMINISTIC` profile:
- disallow nondeterministic time/random sources,
- enforce deterministic lowering profile,
- require replay-compatible syscall policy.

---

## 5. Capability Bitmap

| Bit | Capability      |
| --- | --------------- |
| 0   | IO              |
| 1   | FILESYSTEM      |
| 2   | NETWORK         |
| 3   | MEMORY_MAP      |
| 4   | PROCESS_SPAWN   |
| 5   | THREAD/SYNC     |
| 6   | TIME            |
| 7   | IPC             |
| 8   | RANDOM          |

Execution must abort before dispatch if an opcode requires an undeclared capability.

---

## 6. Complete Opcode Registry (v1 Draft)

Normative machine-readable sources:
- `specs/opcode-registry-v1.csv`
- `specs/opcode-registry-v1.json`

Current draft count: **86 opcodes**.

Each opcode is specified as:

```text
OPCODE_SPEC :=
  opcode_id
  capability_mask
  argument_schema
  syscall_number
  deterministic_lowering_rule
```

### 6.1 Core I/O

| ID     | Name  | Syscall | Capability |
| ------ | ----- | ------- | ---------- |
| 0x0001 | PRINT | write   | IO         |
| 0x0002 | READ  | read    | IO         |
| 0x0003 | OPEN  | openat  | FILESYSTEM |
| 0x0004 | CLOSE | close   | FILESYSTEM |
| 0x0005 | EXIT  | exit    | NONE       |

### 6.2 Memory

| ID     | Name     | Syscall  | Capability |
| ------ | -------- | -------- | ---------- |
| 0x0010 | MMAP     | mmap     | MEMORY_MAP |
| 0x0011 | MUNMAP   | munmap   | MEMORY_MAP |
| 0x0012 | MPROTECT | mprotect | MEMORY_MAP |

### 6.3 Process

| ID     | Name  | Syscall | Capability    |
| ------ | ----- | ------- | ------------- |
| 0x0020 | CLONE | clone   | PROCESS_SPAWN |
| 0x0021 | WAIT  | wait4   | PROCESS_SPAWN |
| 0x0022 | EXEC  | execve  | PROCESS_SPAWN |

### 6.4 Network

| ID     | Name    | Syscall  | Capability |
| ------ | ------- | -------- | ---------- |
| 0x0030 | SOCKET  | socket   | NETWORK    |
| 0x0031 | CONNECT | connect  | NETWORK    |
| 0x0032 | SEND    | sendto   | NETWORK    |
| 0x0033 | RECV    | recvfrom | NETWORK    |

### 6.5 Synchronization

| ID     | Name       | Syscall | Capability  |
| ------ | ---------- | ------- | ----------- |
| 0x0040 | FUTEX_WAIT | futex   | THREAD/SYNC |
| 0x0041 | FUTEX_WAKE | futex   | THREAD/SYNC |

### 6.6 Deterministic Compute (No Syscall)

| ID     | Name    | Meaning                    |
| ------ | ------- | -------------------------- |
| 0x0100 | ADD_U64 | deterministic arithmetic   |
| 0x0101 | SUB_U64 | deterministic arithmetic   |
| 0x0102 | MUL_U64 | deterministic arithmetic   |
| 0x0103 | SHA256  | deterministic hashing op   |
| 0x0104 | BLAKE3  | deterministic hashing op   |

---

## 7. Direct Execution Law (No Mandatory IR)

Normative execution loop:

```text
for node in node_table:
  verify_capability(node.opcode)
  resolve_args(node)
  perform_lowering(node)
  dispatch_syscall_or_compute(node)
```

Disallowed in deterministic profile:
- reflection-based dispatch,
- runtime opcode mutation,
- hidden side-effect channels.

---

## 8. Deterministic eBPF Lowering Compiler Plan

Architecture:

```text
LNAST
  -> opcode template lookup
  -> constant substitution
  -> BPF instruction array
  -> bpf(BPF_PROG_LOAD)
```

Template shape:

```c
struct bpf_template {
    uint16_t opcode;
    uint16_t insn_count;
    struct bpf_insn insns[MAX_INSNS];
};
```

Compiler rule:
- template set is immutable/versioned,
- only argument substitution is permitted,
- emitted instruction order follows AST order.

Determinism constraints:
- no unbounded loops,
- no dynamic jumps,
- no map iteration,
- max program size bounded by profile.

Verifier pre-checks:
- no backward jumps unless bounded and admitted by profile,
- stack usage <= 512 bytes,
- helper calls in allowlist only.

---

## 9. Security and Policy Verification

Mandatory checks before execution:
1. canonical hash verification,
2. opcode table validity and unknown-op rejection,
3. capability closure check,
4. resource quota checks (cpu/mem/fd/time),
5. backend admissibility check (direct/eBPF/hybrid).

Optional hardening:
- seccomp profile derived from opcode/capability closure,
- Landlock policy derived from filesystem declarations.

---

## 10. Replay + STARK Trace Layout

### 10.1 Replay Record

```json
{
  "hash": "<lnast_hash>",
  "syscall_trace": [],
  "result_state_hash": "<hash>"
}
```

### 10.2 Trace Table Columns

| Column     | Meaning                |
| ---------- | ---------------------- |
| step       | execution row index    |
| node_id    | AST node index         |
| opcode     | opcode id              |
| arg0       | argument 0             |
| arg1       | argument 1             |
| arg2       | argument 2             |
| syscall_no | resolved syscall no    |
| ret_val    | syscall return value   |
| state_hash | rolling state hash     |

### 10.3 Transition Constraints

```text
state_hash[i+1] = H(state_hash[i] || opcode || args || ret_val)
```

Constraint families:
- opcode validity: `opcode in registry`,
- syscall mapping: `syscall_no == registry[opcode].syscall`,
- capability closure: `cap_bitmap & registry[opcode].cap != 0` (or cap is NONE),
- argument conformance: args must match AST metadata and opcode schema.

AIR shape:

```text
S_{i+1} - H(S_i, O_i, A_i, R_i) = 0
```

Final boundary condition:

```text
S_n == claimed_final_hash
```

Public inputs:
- AST hash,
- initial state hash,
- final state hash.

Witness:
- trace rows and return vector.

---

## 11. CI Conformance Test Vectors

1. Canonical encoding vectors:
   - AST input -> exact `.lna` bytes -> expected hash.
2. Syscall trace vectors:
   - runtime output trace equals golden trace file.
3. Deterministic replay vectors:
   - repeated runs produce identical trace bytes.
4. Capability violation vectors:
   - undeclared capability usage fails deterministically.
5. eBPF lowering vectors:
   - emitted BPF passes verifier and matches expected behavior.
6. Proof vectors (optional profile):
   - trace + public inputs verify against proof artifact.

---

## 12. Optional Packaging and Distribution

### 12.1 Merkle-Rooted Multi-File Bundle

```text
bundle/
  manifest.json
  a.lna
  b.lna
  c.lna
```

Manifest binds per-file hashes and bundle root. Bundle identity is manifest hash.

### 12.2 Shard Execution Mesh (Deterministic)

Shards execute independently or with declared deterministic IPC edges. Coordinator validates shard hashes and trace commitments against bundle root.

---

## 13. Formal Executable Object Laws

Law 1 — Canonical Identity:
- equal canonical hash implies equal executable object identity.

Law 2 — No Hidden State:
- effects must be represented by declared syscall/eBPF operations.

Law 3 — Capability Closure:
- no effect outside declared capability bitmap.

Law 4 — Deterministic Collapse:
- with equivalent external returns, execution trace is equivalent.

Law 5 — Replayability:
- execution reproducible from object + initial state + return vector.

---

## 14. Conformance Direction

Recommended next artifacts:
- machine-readable opcode registry,
- canonical binary test vectors,
- reference runtime (small C implementation),
- syscall trace conformance harness,
- eBPF template verification suite,
- optional STARK/zk proof profile harness.

---

## 15. Reference Artifacts in This Repository

- Kernel loader draft:
  - `kernel/binfmt_lnast_draft/binfmt_lnast.c`
  - `kernel/binfmt_lnast_draft/README.md`
- Opcode registry artifacts:
  - `specs/opcode-registry-v1.csv`
  - `specs/opcode-registry-v1.json`
