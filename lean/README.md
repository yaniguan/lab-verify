# LabVerifyLean (Lean 4.36.0 Default-Deny SQL, Proof & Lean-MCP Firewall Gates)

`LabVerifyLean` provides machine-checked L4 verification invariants for `lab-verify` in Lean 4 (`v4.36.0`), with zero `sorry` and zero custom `axiom` declarations.

## Covered Invariants and Theorems

1. **4-Layer Default-Deny SQL Gate & Adversarial Counterexample DBs ([LabVerifyLean.lean](LabVerifyLean.lean))**
   - `SqlCandidateCheck`, `SqlGateOK`, `checkSqlGate`, and `checkSqlGate_ok_iff`.
   - `mutating_or_stacked_sql_denied`: blocks multi-statement stacking, non-read-only ASTs, and gold mismatches.
   - `counterexample_mutant_mismatch_denied`: formalizes Idea #13 (`mutant_sql_synthesizer.py`), denying candidates that pass the seed DB but fail synthesized counterexample mutants.
2. **Formal Lean 4 Proof Gate**
   - `LeanProofCheck`, `checkLeanProofGate`, `sorry_proof_always_denied`, and `unsafe_or_vacuous_proof_denied`.
3. **Zero-Trust `Lean-MCP` Capability Firewall (Idea #12)**
   - `McpHardwareEnvelope`, `checkMcpHardwareCall`.
   - `autonomous_mcp_requires_fresh_lean_proof`, `stale_epoch_mcp_always_denied`, and `unsigned_frontier_mcp_always_denied`.

## Build and Verify

```bash
cd lean
lake build
```
