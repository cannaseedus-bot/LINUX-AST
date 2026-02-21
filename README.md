# LINUX-AST

`LINUX-AST` defines **LNAST (Linux-Native AST)**: a deterministic, capability-scoped executable object format that lowers directly to Linux syscalls (with an optional eBPF bridge).

## What This Repository Specifies

- A **canonical binary format** (`.lna`) with hash-stable encoding
- A **direct AST -> syscall execution law** (no mandatory IR layer)
- A deterministic **AST -> eBPF bridge** for verifier-constrained kernel paths
- A replay model, STARK-trace-ready layout, and CI conformance vectors
- A kernel-native loader draft (`binfmt_lnast`) for first-class Linux execution
- A machine-readable v1 opcode registry (`specs/opcode-registry-v1.{csv,json}`)

## Design Position

Linux is treated as execution physics (syscalls + kernel semantics), while LNAST is treated as executable law.

```text
Language syntax -> LNAST object -> (Direct syscall | eBPF bridge | Kernel-native loader) -> Linux kernel
```

## Read the Spec

- Formal executable contract: [`docs/ast-exec-spec.md`](docs/ast-exec-spec.md)

## Planned Artifacts

```text
docs/
  ast-exec-spec.md
specs/
  opcode-registry-v1.csv  # 86-opcode draft registry
  opcode-registry-v1.json # same registry in JSON form
runtime/
  lnast_runtime.c         # reference runtime (planned)
conformance/
  vectors/                # canonical encoding + trace test vectors (planned)
kernel/
  binfmt_lnast_draft/     # loader draft notes (planned)
```
