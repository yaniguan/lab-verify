# LabVerifyLean (Lean 4.36.0 Default-Deny SQL, Proof & Lean-MCP Firewall Gates)

`LabVerifyLean` provides machine-checked L4 verification invariants and the compiled `lab-verify-lean` kernel executable for `lab-verify` in Lean 4 (`v4.36.0`), with zero `sorry` and zero custom `axiom` declarations (`{propext, Classical.choice, Quot.sound}` only).

## Covered Invariants, Executable, and Theorems

1. **4-Layer Default-Deny SQL Gate & Adversarial Counterexample DBs ([LabVerifyLean.lean](LabVerifyLean.lean))**
   - `SqlCandidateCheck`, `SqlGateOK`, `checkSqlGate`, and `checkSqlGate_ok_iff`.
   - `mutating_or_stacked_sql_denied`: blocks multi-statement stacking, non-read-only ASTs, and gold mismatches.
   - `counterexample_mutant_mismatch_denied`: denies candidates that pass the seed DB but fail synthesized counterexample mutants.
2. **Formal Lean 4 Proof Gate**
   - `LeanProofCheck`, `checkLeanProofGate`, `sorry_proof_always_denied`, and `unsafe_or_vacuous_proof_denied`.
   - Paired at runtime with `src/lab_verify/lean_gate.py`, which compiles every candidate `.lean` source with `#print axioms <decl>` appended for all theorems/lemmas/defs and optionally replays `.olean` modules through `leanchecker`.
3. **Zero-Trust `Lean-MCP` Capability Firewall & Key/TTL Boundaries ([Main.lean](Main.lean))**
   - `McpHardwareEnvelope`, `checkMcpHardwareCall`, `McpWireEnvelope`, `checkMcpWireEnvelope`.
   - `autonomous_mcp_requires_fresh_lean_proof`, `stale_epoch_mcp_always_denied`, and `unsigned_frontier_mcp_always_denied`.
   - `revoked_key_epoch_always_denied`, `expired_ttl_mcp_always_denied`, and `expired_cosign_mcp_always_denied`.
   - `autonomous_wire_envelope_soundness` and `cosigned_frontier_wire_envelope_soundness`.
   - `lab-verify-lean --self-check` and `lab-verify-lean --batch-tsv` (`MCP\t...` TSV cross-check invoked by `verify_mcp_envelope(..., check_lean_kernel=True)`).

## Build and Verify

```bash
cd lean
lake build
./.lake/build/bin/lab-verify-lean --self-check
```
