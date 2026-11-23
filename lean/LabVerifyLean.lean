/-!
# LabVerifyLean: Formal L4 Default-Deny SQL, Lean Proof & Zero-Trust Lean-MCP Firewall Gates

Self-contained Lean 4.36.0 formalization for `lab-verify` (L4 Mechanical Verification Gate).
Formalizes:
1. 4-layer default-deny SQL verification gate (`SqlCandidateCheck`, `checkSqlGate`,
   `mutating_or_stacked_sql_denied`, and `counterexample_mutant_mismatch_denied`).
2. Formal Lean proof gate (`LeanProofCheck`, `checkLeanProofGate`, `sorry_proof_always_denied`).
3. Stateful zero-trust `Lean-MCP` capability firewall (`McpHardwareEnvelope`,
   `checkMcpHardwareCall`, `autonomous_mcp_requires_fresh_lean_proof`, and
   `stale_epoch_mcp_always_denied`).
-/
namespace LabVerifyLean

structure RegimeViolation where
  rule   : String
  detail : String
  deriving DecidableEq, Repr

def firstViolation : List (Bool × RegimeViolation) → Option RegimeViolation
  | [] => none
  | (true, _) :: rest => firstViolation rest
  | (false, v) :: _ => some v

@[simp] theorem firstViolation_nil : firstViolation [] = none := rfl

@[simp] theorem firstViolation_cons (b : Bool) (v : RegimeViolation)
    (rest : List (Bool × RegimeViolation)) :
    firstViolation ((b, v) :: rest) = none ↔ b = true ∧ firstViolation rest = none := by
  cases b <;> simp [firstViolation]

theorem firstViolation_none_iff (checks : List (Bool × RegimeViolation)) :
    firstViolation checks = none ↔ ∀ p ∈ checks, p.1 = true := by
  induction checks with
  | nil => simp [firstViolation]
  | cons hd tl ih =>
    rcases hd with ⟨b, v⟩
    cases b with
    | false => simp [firstViolation]
    | true  => simp [firstViolation, ih]

/-! ## 1. 4-Layer Default-Deny SQL Gate & Adversarial Counterexample DB Gate (Idea #13) -/

structure SqlCandidateCheck where
  parsedNonEmpty       : Bool
  statementCount       : Nat
  astReadOnly          : Bool
  authorizerReadOnly   : Bool
  usesSystemTables     : Bool
  unknownColumnsCount  : Nat
  hasImplicitCrossJoin : Bool
  matchesGoldResult    : Bool
  matchesCounterexDBs  : Bool
  runtimePropsHold     : Bool
  deriving DecidableEq, Repr

structure SqlGateOK (q : SqlCandidateCheck) : Prop where
  layer1Parse    : q.parsedNonEmpty = true ∧ q.statementCount = 1
  layer2ReadOnly : (q.astReadOnly = true ∧ q.authorizerReadOnly = true) ∧ q.usesSystemTables = false
  layer3Schema   : q.unknownColumnsCount = 0 ∧ q.hasImplicitCrossJoin = false
  layer4Behavior : (q.matchesGoldResult = true ∧ q.matchesCounterexDBs = true) ∧ q.runtimePropsHold = true

def checkSqlGate (q : SqlCandidateCheck) : Option RegimeViolation :=
  firstViolation
    [ (q.parsedNonEmpty && decide (q.statementCount == 1),
        { rule := "layer1_single_statement_parse",
          detail := "SQL failed parsing, was empty/comment-only, or stacked multiple statements" }),
      (q.astReadOnly && q.authorizerReadOnly && !q.usesSystemTables,
        { rule := "layer2_strict_readonly",
          detail := "SQL attempted mutation, PRAGMA/ATTACH, dangerous function, or sqlite_master read" }),
      (decide (q.unknownColumnsCount == 0) && !q.hasImplicitCrossJoin,
        { rule := "layer3_schema_and_join_safety",
          detail := "SQL referenced unknown table/column or contained an unguarded Cartesian join" }),
      (q.matchesGoldResult && q.matchesCounterexDBs && q.runtimePropsHold,
        { rule := "layer4_behavioral_verification",
          detail := "SQL failed reference execution, adversarial mutant DBs, or property checks" }) ]

theorem checkSqlGate_ok_iff (q : SqlCandidateCheck) :
    checkSqlGate q = none ↔ SqlGateOK q := by
  unfold checkSqlGate
  simp only [firstViolation_cons, firstViolation_nil, and_true,
             Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, beq_iff_eq]
  constructor
  · rintro ⟨h1, h2, h3, h4⟩; exact ⟨h1, h2, h3, h4⟩
  · rintro ⟨h1, h2, h3, h4⟩; exact ⟨h1, h2, h3, h4⟩

/-- Hard boundary theorem: Stacked, mutating, or gold-mismatched SQL is provably denied. -/
theorem mutating_or_stacked_sql_denied (q : SqlCandidateCheck)
    (hbad : q.statementCount ≠ 1 ∨ q.astReadOnly = false ∨ q.matchesGoldResult = false) :
    checkSqlGate q ≠ none := by
  intro hok
  unfold checkSqlGate at hok
  simp only [firstViolation_cons, firstViolation_nil, and_true,
             Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hok
  rcases hok with ⟨⟨_, hst1⟩, ⟨⟨hro1, _⟩, _⟩, _, ⟨⟨hgold1, _⟩, _⟩⟩
  rcases hbad with hst | hro | hgold
  · exact hst hst1
  · rw [hro] at hro1; contradiction
  · rw [hgold] at hgold1; contradiction

/-- Idea #13 theorem: Even if a query matches the clean seed DB (`matchesGoldResult = true`),
    diverging on any synthesized mutant counterexample DB (`matchesCounterexDBs = false`) denies it! -/
theorem counterexample_mutant_mismatch_denied (q : SqlCandidateCheck)
    (hmut : q.matchesCounterexDBs = false) :
    checkSqlGate q ≠ none := by
  intro hok
  have hb := ((checkSqlGate_ok_iff q).mp hok).layer4Behavior
  rcases hb with ⟨⟨_, hcx⟩, _⟩
  rw [hmut] at hcx
  contradiction

/-! ## 2. Formal Lean 4 Proof Gate -/

structure LeanProofCheck where
  hasSorryOrAdmit   : Bool
  hasUnsafeOrAxiom  : Bool
  hasVacuousTrueThm : Bool
  kernelVerified    : Bool
  deriving DecidableEq, Repr

def checkLeanProofGate (p : LeanProofCheck) : Option RegimeViolation :=
  firstViolation
    [ (!p.hasSorryOrAdmit,
        { rule := "no_sorry_or_admit",
          detail := "Lean artifact contains `sorry` or `admit`" }),
      (!p.hasUnsafeOrAxiom,
        { rule := "no_custom_axiom_or_native_decide",
          detail := "Lean artifact declares custom `axiom`, `unsafe`, or `native_decide`" }),
      (!p.hasVacuousTrueThm && p.kernelVerified,
        { rule := "non_vacuous_kernel_checked",
          detail := "Lean theorem is vacuous (`: True`) or has not passed kernel verification" }) ]

/-- Hard boundary theorem: Any Lean artifact containing `sorry` or `admit` is always denied. -/
theorem sorry_proof_always_denied (p : LeanProofCheck) (hs : p.hasSorryOrAdmit = true) :
    checkLeanProofGate p ≠ none := by
  unfold checkLeanProofGate
  simp [firstViolation, hs]

/-- Hard boundary theorem: Custom `axiom`, `unsafe`, or vacuous theorems are always denied. -/
theorem unsafe_or_vacuous_proof_denied (p : LeanProofCheck)
    (hbad : p.hasUnsafeOrAxiom = true ∨ p.hasVacuousTrueThm = true ∨ p.kernelVerified = false) :
    checkLeanProofGate p ≠ none := by
  intro hok
  unfold checkLeanProofGate at hok
  simp only [firstViolation_cons, firstViolation_nil, and_true,
             Bool.and_eq_true, Bool.not_eq_true'] at hok
  rcases hok with ⟨_, hax, hvac, hker⟩
  rcases hbad with ha | hv | hk
  · rw [ha] at hax; contradiction
  · rw [hv] at hvac; contradiction
  · rw [hk] at hker; contradiction

/-! ## 3. Idea #12: Zero-Trust `Lean-MCP` Capability Firewall -/

structure McpHardwareEnvelope where
  tokenEpoch          : Nat
  currentDeckEpoch    : Nat
  leanProofValid      : Bool
  isFrontierException : Bool
  humanSupervisorSign : Bool
  deriving DecidableEq, Repr

def checkMcpHardwareCall (e : McpHardwareEnvelope) : Option RegimeViolation :=
  firstViolation
    [ (decide (e.tokenEpoch == e.currentDeckEpoch),
        { rule := "mcp_epoch_freshness",
          detail := "stale MCP capability token replayed against an updated deck state" }),
      (decide ((e.leanProofValid && !e.isFrontierException) ∨
               (e.isFrontierException && e.humanSupervisorSign)),
        { rule := "mcp_proof_or_cosigned_exception",
          detail := "hardware MCP call lacks both a valid Lean proof certificate and human co-signature" }) ]

/-- Zero-click autonomy inside regime, mandatory human co-signature outside:
    when `humanSupervisorSign = false`, execution succeeds iff `tokenEpoch = currentDeckEpoch`,
    `leanProofValid = true`, and `isFrontierException = false`. -/
theorem autonomous_mcp_requires_fresh_lean_proof (e : McpHardwareEnvelope)
    (hnoHuman : e.humanSupervisorSign = false) :
    checkMcpHardwareCall e = none ↔
      (e.tokenEpoch = e.currentDeckEpoch ∧ e.leanProofValid = true ∧ e.isFrontierException = false) := by
  unfold checkMcpHardwareCall
  simp [firstViolation_cons, firstViolation_nil, hnoHuman]

/-- Replay firewall theorem: any stale or mismatched `tokenEpoch` is unconditionally blocked. -/
theorem stale_epoch_mcp_always_denied (e : McpHardwareEnvelope)
    (hstale : e.tokenEpoch ≠ e.currentDeckEpoch) :
    checkMcpHardwareCall e ≠ none := by
  intro hok
  unfold checkMcpHardwareCall at hok
  simp only [firstViolation_cons, firstViolation_nil, and_true, decide_eq_true_eq, beq_iff_eq] at hok
  exact hstale hok.1

/-- Frontier override theorem: any frontier exception without human co-signature is blocked. -/
theorem unsigned_frontier_mcp_always_denied (e : McpHardwareEnvelope)
    (hf : e.isFrontierException = true) (hns : e.humanSupervisorSign = false) :
    checkMcpHardwareCall e ≠ none := by
  intro hok
  have hiff := (autonomous_mcp_requires_fresh_lean_proof e hns).mp hok
  rw [hf] at hiff
  simp at hiff

/-- Full wire-compatible `lean-mcp/v1` zero-trust capability envelope binding HMAC authenticity,
    SHA-256 protocol payload hash, deck epoch freshness, single-use nonce, and proof/co-signature. -/
structure McpWireEnvelope where
  hmacAuthentic       : Bool
  tokenPayloadHash    : String
  actualPayloadHash   : String
  tokenEpoch          : Nat
  currentDeckEpoch    : Nat
  nonceFresh          : Bool
  leanProofValid      : Bool
  isFrontierException : Bool
  humanSupervisorSign : Bool
  deriving DecidableEq, Repr

def checkMcpWireEnvelope (w : McpWireEnvelope) : Option RegimeViolation :=
  firstViolation
    [ (w.hmacAuthentic,
        { rule := "mcp_hmac_authentic",
          detail := "envelope HMAC-SHA256 verification failed" }),
      (decide (w.tokenPayloadHash == w.actualPayloadHash),
        { rule := "mcp_payload_binding",
          detail := "compiled protocol SHA-256 does not match envelope protocol_sha256" }),
      (decide (w.tokenEpoch == w.currentDeckEpoch),
        { rule := "mcp_epoch_freshness",
          detail := "stale MCP capability token replayed against an updated deck state" }),
      (w.nonceFresh,
        { rule := "mcp_nonce_single_use",
          detail := "replay detected: capability nonce already consumed" }),
      (decide ((w.leanProofValid && !w.isFrontierException) ∨
               (w.isFrontierException && w.humanSupervisorSign)),
        { rule := "mcp_proof_or_cosigned_exception",
          detail := "hardware MCP call lacks both a valid Lean proof certificate and human co-signature" }) ]

/-- Payload-swap firewall theorem: post-verification tampering or script substitution
    (`tokenPayloadHash ≠ actualPayloadHash`) is unconditionally denied. -/
theorem mcp_payload_hash_binding (w : McpWireEnvelope)
    (hswap : w.tokenPayloadHash ≠ w.actualPayloadHash) :
    checkMcpWireEnvelope w ≠ none := by
  intro hok
  unfold checkMcpWireEnvelope at hok
  simp only [firstViolation_cons, firstViolation_nil, and_true, decide_eq_true_eq, beq_iff_eq] at hok
  exact hswap hok.2.1

/-- HMAC authenticity theorem: any tampered envelope (`hmacAuthentic = false`) is denied. -/
theorem mcp_hmac_tamper_always_denied (w : McpWireEnvelope)
    (htamp : w.hmacAuthentic = false) :
    checkMcpWireEnvelope w ≠ none := by
  unfold checkMcpWireEnvelope
  simp [firstViolation, htamp]

/-- Single-use nonce theorem: any replayed nonce (`nonceFresh = false`) is denied. -/
theorem mcp_nonce_replay_always_denied (w : McpWireEnvelope)
    (hrep : w.nonceFresh = false) :
    checkMcpWireEnvelope w ≠ none := by
  intro hok
  unfold checkMcpWireEnvelope at hok
  simp only [firstViolation_cons, firstViolation_nil, and_true] at hok
  have hnf := hok.2.2.2.1
  rw [hrep] at hnf
  contradiction

/-- Complete autonomous wire-envelope soundness theorem: without human intervention
    (`humanSupervisorSign = false`), hardware dispatch is permitted iff all 5 zero-trust
    invariants hold simultaneously. -/
theorem autonomous_wire_envelope_soundness (w : McpWireEnvelope)
    (hnoHuman : w.humanSupervisorSign = false) :
    checkMcpWireEnvelope w = none ↔
      (w.hmacAuthentic = true ∧
       w.tokenPayloadHash = w.actualPayloadHash ∧
       w.tokenEpoch = w.currentDeckEpoch ∧
       w.nonceFresh = true ∧
       w.leanProofValid = true ∧
       w.isFrontierException = false) := by
  unfold checkMcpWireEnvelope
  simp [firstViolation_cons, firstViolation_nil, hnoHuman]

/-! ## Compile-Time `#guard` Verification Witnesses -/

private def cleanSql : SqlCandidateCheck :=
  { parsedNonEmpty := true, statementCount := 1, astReadOnly := true,
    authorizerReadOnly := true, usesSystemTables := false, unknownColumnsCount := 0,
    hasImplicitCrossJoin := false, matchesGoldResult := true,
    matchesCounterexDBs := true, runtimePropsHold := true }

#guard (checkSqlGate cleanSql).isNone == true
#guard (checkSqlGate { cleanSql with matchesCounterexDBs := false }).isSome == true
#guard (checkSqlGate { cleanSql with statementCount := 2 }).isSome == true

#guard (checkLeanProofGate
         { hasSorryOrAdmit := false, hasUnsafeOrAxiom := false,
           hasVacuousTrueThm := false, kernelVerified := true }).isNone == true

#guard (checkLeanProofGate
         { hasSorryOrAdmit := true, hasUnsafeOrAxiom := false,
           hasVacuousTrueThm := false, kernelVerified := true }).isSome == true

#guard (checkMcpHardwareCall
         { tokenEpoch := 5, currentDeckEpoch := 5, leanProofValid := true,
           isFrontierException := false, humanSupervisorSign := false }).isNone == true

#guard (checkMcpHardwareCall
         { tokenEpoch := 4, currentDeckEpoch := 5, leanProofValid := true,
           isFrontierException := false, humanSupervisorSign := false }).isSome == true

#guard (checkMcpHardwareCall
         { tokenEpoch := 5, currentDeckEpoch := 5, leanProofValid := true,
           isFrontierException := true, humanSupervisorSign := false }).isSome == true

private def cleanWireEnv : McpWireEnvelope :=
  { hmacAuthentic := true, tokenPayloadHash := "deadbeef", actualPayloadHash := "deadbeef",
    tokenEpoch := 1, currentDeckEpoch := 1, nonceFresh := true,
    leanProofValid := true, isFrontierException := false, humanSupervisorSign := false }

#guard (checkMcpWireEnvelope cleanWireEnv).isNone == true
#guard (checkMcpWireEnvelope { cleanWireEnv with actualPayloadHash := "tampered" }).isSome == true
#guard (checkMcpWireEnvelope { cleanWireEnv with nonceFresh := false }).isSome == true
#guard (checkMcpWireEnvelope { cleanWireEnv with hmacAuthentic := false }).isSome == true

end LabVerifyLean
