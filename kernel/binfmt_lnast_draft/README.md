# binfmt_lnast Draft

This directory contains an **experimental** Linux 6.x kernel-module draft for a native `LNA1` executable loader.

## Files

- `binfmt_lnast.c`: loadable `linux_binfmt` handler sketch with:
  - header parsing,
  - hash verification hook,
  - capability-gated opcode dispatch,
  - deterministic node iteration.

## Intentional Gaps

Before production use, implement:

1. Blake3-256 kernel hash implementation (replace stub).
2. Full metadata/child/symbol bounds validation.
3. Full opcode dispatch registry integration.
4. Seccomp/Landlock policy derivation from capability closure.
5. Trace emission pipeline for replay/STARK profiles.

## Integration Path

- Primary route: loadable module registration via `register_binfmt`.
- Optional route: in-tree registration in `fs/exec.c` after hardening.
