# lab-verify

Trust nothing a model writes until a *strict checker* says yes: Lean for logic, SQL for data, protocol rules for the bench.

> **Auto-Lab Ecosystem**: Layer `L4 · Digital-Twin Rehearsal & Default-Deny Verification` in [auto-lab](https://github.com/yaniguan/auto-lab) · [Project Studio](https://yaniguan.github.io/auto-lab/)

## Where it fits

In the [Auto-Lab](https://github.com/yaniguan/auto-lab) system ([yaniguan.github.io/auto-lab](https://yaniguan.github.io/auto-lab/)), the body (a bounded harness around every job) puts a default-deny gate on each job. This repo collects checkers and benchmarks for three kinds of model output: Lean 4 proofs, SQL queries over lab and clinical data, and machine-readable benchtop protocols plus `lean-mcp/v1` capability envelopes.

## System Profile: Object · Data · Model · Training · History · Unique Properties

Full architectural documentation, verification-layer semantics, commit history, and sibling-repository contracts are maintained in [`docs/ARCHITECTURE_AND_HISTORY.md`](docs/ARCHITECTURE_AND_HISTORY.md):

- **Object**: Default-deny mechanical verification gate (`L4`) auditing LLM-generated SQL queries, Lean 4 proofs (`lean/` and external formal math suites), and laboratory protocol / `lean-mcp/v1` capability envelopes before database execution or benchtop dispatch.
- **Data**: Deterministic 30-row **synthetic** in-memory SQLite lab database (`12` experiments, `14` samples, `4` instruments; ISO-8601 `YYYY-MM-DD` `CHECK` constraints + `3` counterexample perturbation DBs), `12` analytics questions with gold SQL and `22` labeled candidate queries (`7` correct, `15` error cases in `demo/candidates.json`), real clinical **EHRSQL-2024** over **MIMIC-IV Demo v2.2** (`17` tables, `317,875` rows; `931/931` answerable gold-vs-gold + `232/232` unanswerable abstentions in `results/ehrsql_2024_real.json`), and verified 2024–2026 open-source Text-to-SQL and Lean 4 benchmark adapters (`catalog/sources.json`).
- **Model**: Four-layer sequential fail-fast SQL gate (`src/lab_verify/sql_gate.py`): Layer 1 syntax parse (`sqlglot`), Layer 2 AST + SQLite `PRAGMA query_only` + authorizer read-only enforcement, Layer 3 lexical schema & join-connectivity resolution, and Layer 4 Hopcroft-Karp `math.isclose` multiset + tie-aware `ORDER BY` equivalence (`22/22` label agreement; catches `8/15` semantic errors missed by static layers 1–3), paired with live Lean 4.36.0 `#print axioms` proof verification (`src/lab_verify/lean_gate.py`) and fail-closed `lean-mcp/v1` capability verification (`src/lab_verify/mcp_gate.py`). No neural model is trained here.
- **Training**: Zero parametric training; deterministic symbolic/execution checker designed to gate runtime inference and supply verifiable pass/fail feedback to `L3` post-training (`labbench-posttrain`, `twinstep`).
- **History**: Initialized in `3255ec7` (`2026-11-18`) with the 4-layer SQLite gate and 22-candidate benchmark suite; expanded with `lean-mcp/v1` Ed25519/HMAC capability envelopes, 2024–2026 open SQL/Lean adapters, live Lean 4.36.0 `#print axioms` compilation, tie-aware clinical EHRSQL-2024 evaluation, and fail-closed wire defaults.
- **Unique Properties**: Dual AST + engine-level read-only isolation, live Lean 4 kernel + `#print axioms` auditing (`{propext, Classical.choice, Quot.sound}` only), tie-aware SQL `ORDER BY` & `LIMIT`-cut tie handling (`"ambiguous_gold"`), and fail-closed `lean-mcp/v1` hardware capability verification shared with [`stepbot`](https://github.com/yaniguan/stepbot).

## Repository Layout

```text
lab-verify/
├── .github/workflows/
│   └── demo.yml                          # CI: Python 3.10-3.12 matrix + Lean 4.36.0 kernel & axiom job
├── catalog/
│   └── sources.json                      # SPDX, ShareAlike, and commercial-use manifest for benchmarks/repos
├── community_extensions/
│   ├── lean_mcp_firewall.py              # Stateful Lean-MCP capability firewall benchmark
│   └── mutant_sql_synthesizer.py         # 5-mutant SQLite counterexample synthesizer (14 rewrites + 18 bugs)
├── demo/
│   ├── candidates.json                   # Core 12 lab SQL questions, gold queries, and 22 candidates (22/22)
│   ├── candidates_extended.json          # Extended CTE, multi-row ORDER BY, and NULL-aware benchmark suite
│   ├── output.txt                        # Reference 4-layer gate evaluation table and summary
│   └── sql_gate.py                       # CLI / benchmark wrapper around lab_verify
├── docs/
│   └── ARCHITECTURE_AND_HISTORY.md       # Deep technical profile (Object, Data, Model, History)
├── lean/
│   ├── LabVerifyLean.lean                # Machine-checked L4 SQL, proof & MCP firewall invariants (Lean 4.36.0)
│   ├── Main.lean                         # lab-verify-lean CLI (--self-check, --batch-tsv)
│   ├── lakefile.toml                     # Lake package manifest
│   └── lean-toolchain                    # leanprover/lean4:v4.36.0
├── results/
│   └── ehrsql_2024_real.json             # Measured real MIMIC-IV Demo v2.2 EHRSQL-2024 & BIRD Mini-Dev report
├── schema/
│   └── candidates.schema.json            # Strict JSON Schema for SQL candidate benchmarks
├── scripts/
│   ├── check_catalog.py                  # Automated SPDX, eval_only/training & markdown URL validator
│   ├── fetch_open_benchmarks.py          # On-demand fetcher & smoke verifier for 2024-2026 SQL/Lean suites
│   └── run_ehrsql_real.py                # Cross-platform MIMIC-IV Demo v2.2 builder & real EHRSQL-2024 runner
├── src/lab_verify/
│   ├── __init__.py                       # Unified verify() entry point and public API
│   ├── cli.py                            # CLI (--sql, --lean, --protocol, mcp-mint, mcp-verify)
│   ├── lean_gate.py                      # Fail-closed Lean 4 compiler, #print axioms & leanchecker gate
│   ├── mcp_gate.py                       # Fail-closed lean-mcp/v1 capability minting & stateful gate
│   ├── open_benchmarks.py                # BIRD/Spider2/EHRSQL SQLite & LeanWorkbook/PutnamBench/ProofNet adapters
│   ├── properties.py                     # Runtime semantic property checks (fanout, ranges, uniqueness)
│   ├── protocol_gate.py                  # Benchtop protocol verifier compatible with lab-rehearsal/twinstep
│   ├── sql_gate.py                       # 4-layer SQL gate + tie-aware ORDER BY + configurable limits
│   └── verdict.py                        # Common VerifyVerdict / Verdict dataclass
├── tests/
│   ├── test_autolab_wire.py              # Auto-Lab 15-repo wire node (autolab-wire/v1) test suite
│   ├── test_community_extensions.py      # Firewall & mutant-SQL counterexample benchmark tests
│   ├── test_mcp_runtime_gate.py          # Zero-trust lean-mcp/v1 envelope, deferral & CLI test suite
│   ├── test_open_datasets_2026.py        # Catalog, live Lean 4 compilation, & EHRSQL real report tests
│   └── test_sql_gate.py                  # Unit & adversarial SQL/Lean/protocol red-team test suite
├── autolab_wire.py                       # Layer L4 autolab-wire/v1 node & stepbot capability minter
├── LICENSE                               # MIT License
├── pyproject.toml                        # Package metadata and lab-verify console script
├── README.md                             # Overview, SQL/Lean/MCP gate results, and verification catalog
└── requirements.txt                      # Pinned runtime dependency (sqlglot>=25.0,<31.0)
```

## First attempt: 4-Layer Synthetic Lab SQL Gate

An in-memory SQLite database with **synthetic** experiments, samples and instruments (`PRIMARY KEY` / `FOREIGN KEY` constraints, ISO-8601 date `CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')` on `experiments.date` and `instruments.last_calibrated` so lexical date predicates such as `q12`'s `date >= '2026-03-01'` match chronological order, `PRAGMA query_only = ON`, strict `sqlite3.set_authorizer`, configurable `--max-vm-steps` / `--max-rows` / `--timeout-s` budgets, and 3 counterexample perturbation DBs including NULL `yield_pct` injection). 12 questions with gold SQL and 22 hand-written candidates (`7` correct, `15` with typical model errors: wrong column, missing filter, NULL-unsafe `SUM/COUNT(*)` average, `COUNT` vs `COUNT DISTINCT`, wrong join, syntax error, `DELETE`/`UPDATE`/`DROP`). The gate has four layers and stops at the first failure: 1 parse (`sqlglot`), 2 read-only, 3 lexical schema & join connectivity, 4 execution match against gold (or runtime property checks when no gold query exists).

```bash
pip install -e .
python demo/sql_gate.py
```

Output:

```
Toy lab database with SYNTHETIC data: 12 experiments, 14 samples, 4 instruments.
12 questions, 22 candidates

 q  label                    first failed layer   reason
------------------------------------------------------------------------------------------------
 1  correct                  PASS                 match
 1  missing filter           4 execution          value (12,) vs gold (7,)
 2  wrong column             3 schema             unknown column scientist in experiments
 2  correct                  PASS                 match
 3  COUNT vs COUNT DISTINCT  4 execution          value (14,) vs gold (5,)
 4  syntax error             1 parse              Expecting ). Line 1, Col: 25.
 4  NULL-unsafe average      4 execution          counterexample db #3 mismatch: value (54.1,) vs 
 5  DELETE                   2 read-only          Delete statement
 5  stacked DROP             2 read-only          2 statements (Select, Drop)
 6  wrong join               4 execution          0 rows vs 4 gold rows
 6  correct                  PASS                 match
 7  wrong column             3 schema             unknown column calibrated_on in instruments
 7  wrong comparison         4 execution          row content mismatch (2 rows): e.g. ('Pipette ro
 8  COUNT vs COUNT DISTINCT  4 execution          value (3,) vs gold (7,)
 8  correct                  PASS                 match
 9  wrong sort order         4 execution          value ('Western',) vs gold ('PCR',)
 9  UPDATE                   2 read-only          Update statement
10  wrong table              3 schema             unknown column well in experiments
10  correct                  PASS                 match
11  correct                  PASS                 match
12  missing filter           4 execution          5 rows vs 3 gold rows
12  correct                  PASS                 match

Candidates stopped at each layer:
  layer 1 parse      1
  layer 2 read-only  3
  layer 3 schema     3
  layer 4 execution  8
  passed all     7

Gate verdict agrees with hand label: 22/22
Wrong candidates: 15; wrong ones passing the full gate: 0
Wrong candidates that would pass with layers 1-3 only: 8/15
```

Parse, read-only and schema checks catch the loud errors, while over half of the wrong queries (`8` of `15`, including `q4`'s `SUM(yield_pct) / COUNT(*)` NULL-denominator bug) look valid statically and are caught only by Layer 4 execution and counterexample perturbations.

## Real Clinical SQL Evaluation: EHRSQL-2024 on MIMIC-IV Demo v2.2

`scripts/run_ehrsql_real.py` downloads the open **MIMIC-IV Clinical Database Demo v2.2** (`ODbL-1.0`) and the official **EHRSQL-2024** validation split (`CC-BY-4.0`) into gitignored `data/ehrsql_2024/`, builds the 17-table (`317,875`-row) clinical SQLite database in pure Python across Windows and Linux CPU, evaluates every answerable and unanswerable item through `verify_open_sql_item`, and audits all 500 **BIRD Mini-Dev** SQLite (`CC-BY-SA-4.0`) gold queries (`results/ehrsql_2024_real.json`):

- **MIMIC-IV Demo v2.2 + EHRSQL-2024 (`1,163` validation items)**:
  - **Answerable gold-vs-gold queries**: **`931/931` passed** (`0` Layer 1–4 false rejects, `0` execution-limit aborts).
  - **Unanswerable clinical abstention items**: **`232/232` passed** (`is_unanswerable=True` abstention gating).
- **BIRD Mini-Dev SQLite (`500` items)**: **`500/500` passed** static parse, read-only, and join-connectivity audit (`0` false rejects on comma joins or bounded scalar CTE `CROSS JOIN`s).

```bash
python scripts/run_ehrsql_real.py
```

## Lean 4 Proof Gate (`src/lab_verify/lean_gate.py`)

`verify_lean` and `verify_open_lean_item` compile every candidate proof file or string by writing a temporary `.lean` module with `#print axioms <decl>` appended for every `theorem`, `lemma`, `def`, and `abbrev` declaration, invoking `lean` (standalone) or `lake env lean` (with absolute paths inside `--lean-project`), and optionally replaying `.olean` outputs through `leanchecker` (`--leanchecker`):

- **Allowed standard axioms**: strictly `{propext, Classical.choice, Quot.sound}`.
- **Rejected**: unproved `rfl` (`a + b = b + a`), `sorry` / `sorryAx` (including custom `elab ... => Lean.Elab.Tactic.admitGoal` tactics), `Lean.ofReduceBool` / `Lean.trustCompiler` (`native_decide`), custom `axiom` declarations, `#exit`, `opaque`, and vacuous `True` / `False -> ...` theorems.
- **Fail-closed default**: if `lean` / `lake` is not installed on `PATH`, `verify_lean` and `lab-verify --lean` fail closed (`passed=False`, exit code `1`) unless `static_only=True` / `--lean-static-only` is passed explicitly (which sets `reason="static_only"`).

```bash
lab-verify --lean lean/LabVerifyLean.lean --leanchecker
```

## Lean-MCP Runtime Gate (`lean-mcp/v1`)

`lab_verify.mcp_gate` implements fail-closed, wire-compatible `lean-mcp/v1` capability envelopes shared directly with [`stepbot`](https://github.com/yaniguan/stepbot):

1. **Explicit Key Policy (`mcp_hmac_authentic` / `mcp_signature_authentic`)**: Rejects missing keys and the public development key (`DEFAULT_MCP_SECRET_KEY`) by default unless `--allow-insecure-dev-key` (`allow_insecure_dev_key=True`) is explicitly passed. Supports canonical HMAC-SHA256 or asymmetric Ed25519 (`auth_mode="ed25519"`).
2. **Mandatory Payload & Volume Binding (`mcp_payload_binding` / `mcp_bounds_exceeded`)**: `verify_mcp_envelope` and `lab-verify mcp-verify` require `--protocol` (`actual_protocol`) or `--protocol-sha256` (`actual_protocol_sha256`) unless `--no-payload-binding` is explicitly passed for dry-run inspection. Opentrons scripts starting with `from opentrons import protocol_api` are supported, and extracted liquid-handling volumes (`transfer`, `aspirate`, `dispense`, `distribute`, `mix`) are checked against pipette ceilings and `envelope_bounds["max_transfer_ul"]` (`<= 1,000 uL` in routine mode).
3. **Meaning of `static_check_passed` and `lean_proof_valid`**:
   - `static_check_passed` (exposed on `LeanMcpEnvelope.static_check_passed`, `autolab_wire.py` `verification["static_check_passed"]`, and `mcp-verify --json`): `True` if and only if a concrete protocol script or IR was supplied and passed static AST safety, entrypoint (`def run(protocol)`), and `max_transfer_ul` volume-bound checks. Never `True` when no protocol is given.
   - `lean_proof_valid` (the canonical 11-key `lean-mcp/v1` wire field consumed by `stepbot.StepbotMcpExecutor`): `True` strictly when `static_check_passed` holds, upstream rehearsal did not fail (`rehearsal_passed is not False`), and any supplied `--lean-proof` Lean 4 proof source compiled cleanly under the Lean 4 kernel using only `{propext, Classical.choice, Quot.sound}`. There is no CLI `--lean-proof-valid` override, and missing protocols always receive `lean_proof_valid: false`.
4. **Role-Separated Supervisor Co-Signatures (`mcp_proof_or_cosigned_exception`)**: `human_supervisor_signed` is accepted only when verified against either a distinct `--supervisor-secret-key` HMAC (`supervisor_secret_key != secret_key`) or a distinct Ed25519 `--supervisor-public-key`. Self-declared co-signatures are rejected.
5. **Epoch, Single-Use Nonce, TTL, and Kernel Cross-Check**: Enforces active `key_epoch`, monotonic `token_epoch == current_deck_epoch`, atomic persistent nonce anti-replay (`--state <path.json>`), bounded TTL windows, and fail-closed `lab-verify-lean --batch-tsv` cross-checking when `--check-lean-kernel` (`check_lean_kernel=True`) is enabled.

```bash
# Requires non-empty LEAN_MCP_SECRET_KEY (and distinct LEAN_MCP_SUPERVISOR_SECRET_KEY for frontier co-signs)
lab-verify mcp-mint --protocol run_script.py --state mcp_state.json --secret-key "$LEAN_MCP_SECRET_KEY" -o envelope.json
lab-verify mcp-verify envelope.json --protocol run_script.py --state mcp_state.json --mutates-deck-state --secret-key "$LEAN_MCP_SECRET_KEY" --json
```

## 15-Repository Auto-Lab Wire Contract (`autolab-wire/v1`)

`autolab_wire.py` (`REPO_ID = "lab-verify"`, `LAYER = "L4"`) connects `lab-verify` into the closed-loop 15-repository [Auto-Lab](https://github.com/yaniguan/auto-lab) wire pipeline (`autolab-wire/v1`):

- **Upstream Pre-Execution Flow (`L6` / `L5` / `L4`)**: Consumes candidate SQL queries (against either a custom read-only SQLite `db_path` or the synthetic lab schema) and rehearsed 96-well protocol IR (`rehearsal.protocol_yaml_dict`) or compiled Opentrons Python (`stepbot_compiled.python_code`) downstream of [`lab-ears`](https://github.com/yaniguan/lab-ears), [`lab-ask-why`](https://github.com/yaniguan/lab-ask-why), [`lab-decide`](https://github.com/yaniguan/lab-decide), [`assayfold`](https://github.com/yaniguan/assayfold), [`lab-automation-atlas`](https://github.com/yaniguan/lab-automation-atlas), [`buy-or-make`](https://github.com/yaniguan/buy-or-make), [`labshift`](https://github.com/yaniguan/labshift), and [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal).
- **Fail-Closed SQL & `lean-mcp/v1` Minting (`L4` -> `L1` `stepbot`)**: `process_packet(packet, db_path=...)` blocks mutating/invalid SQL (`L4_VERIFY_SQL_BLOCK`), blocks packets carrying no protocol or lacking an explicit non-dev signing key (`L4_VERIFY_PROTOCOL_BLOCK`), ignores unverified packet-level `human_supervisor_signed` flags unless backed by a distinct cryptographic supervisor signature, and mints wire-compatible `lean-mcp/v1` envelopes for [`stepbot`](https://github.com/yaniguan/stepbot) (`StepbotMcpExecutor`), [`lab-hands`](https://github.com/yaniguan/lab-hands) (`L1`), and [`lab-feet`](https://github.com/yaniguan/lab-feet) (`L0`).
- **Sibling `L4` Post-Run Partner ([`lab-attrib`](https://github.com/yaniguan/lab-attrib))**: Pairs pre-execution default-deny gates (`lab-rehearsal` + `lab-verify`) with post-execution causal blame, NNLS XRD precursor deconvolution, and SHA-256 certified ledger quarantine in [`lab-attrib`](https://github.com/yaniguan/lab-attrib) before verified runs reach [`twinstep`](https://github.com/yaniguan/twinstep), [`labfill`](https://github.com/yaniguan/labfill), and [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain) (`L3`).

## 2024–2026 Open SQL & Lean 4 Benchmark Adapters

`lab_verify.open_benchmarks` and `scripts/fetch_open_benchmarks.py` load open-source clinical, scientific, and enterprise Text-to-SQL items directly into the 4-layer read-only `sql_gate` (`mode=ro` SQLite + `PRAGMA query_only` + clinical abstention checks on unanswerable `EHRSQL` queries) and formal mathematics items into `lean_gate` (enforcing exact benchmark theorem-signature preservation and live Lean 4 `#print axioms` verification when Lean is installed, or reporting `"static_only"` in offline smoke mode). Every dataset entry in `catalog/sources.json` records exact SPDX licensing plus `eval_only` and `training_allowed` flags so evaluation-only suites are never mixed into `L3` post-training.

```bash
python scripts/fetch_open_benchmarks.py --list
python scripts/fetch_open_benchmarks.py --offline-demo
python scripts/fetch_open_benchmarks.py --dataset bird-mini-dev-hf --max-items 25 --verify
```

## Datasets

| Dataset | Domain | Year | What | License | Eval-Only |
|---|---|---:|---|---|---|
| [Spider](https://yale-lily.github.io/spider) | SQL | 2018 | Cross-domain text-to-SQL | CC BY-SA 4.0 | No |
| [BIRD](https://bird-bench.github.io/) | SQL | 2023 | Large database-grounded text-to-SQL | CC BY-SA 4.0 | No |
| [Spider 2.0](https://spider2-sql.github.io/) | SQL | 2025 | Enterprise text-to-SQL workflows | MIT | Yes |
| [Spider 2.0-Lite](https://huggingface.co/datasets/xlangai/spider2-lite) | SQL | 2025 | Self-contained enterprise & local SQLite (`local*`) text-to-SQL | MIT | Yes |
| [BIRD Mini-Dev](https://huggingface.co/datasets/birdsql/bird_mini_dev) | SQL | 2024 | 500 curated SQLite/PostgreSQL/MySQL queries with domain evidence | CC BY-SA 4.0 | Yes |
| [EHRSQL-2024](https://github.com/glee4810/ehrsql-2024) | SQL | 2024 | Clinical MIMIC-IV read-only SQLite queries + unanswerable abstention | CC BY 4.0 | No |
| [BIRD-CRITIC 1.0 SQLite](https://huggingface.co/datasets/birdsql/bird-critic-1.0-sqlite) | SQL | 2025 | Real-world SQLite diagnostic and user SQL issue repair (`SWE-SQL`) | CC BY-SA 4.0 | Yes |
| [LiveSQLBench Base-Lite SQLite](https://huggingface.co/datasets/birdsql/livesqlbench-base-lite-sqlite) | SQL | 2025 | Contamination-free dynamic SQLite text-to-SQL with hierarchical KBs | CC BY-SA 4.0 | Yes |
| [miniF2F](https://github.com/facebookresearch/miniF2F) | Lean 4 | 2022 | Formal olympiad math statements | MIT | Yes |
| [LeanDojo Benchmark](https://leandojo.org/) | Lean 4 | 2023 | Theorems and proofs extracted from mathlib | See project site | No |
| [Lean-Workbook](https://huggingface.co/datasets/internlm/Lean-Workbook) | Lean 4 | 2024 | 57K+ Lean 4 formal-informal math problem pairs and verified tactics | Apache-2.0 | No |
| [PutnamBench (Lean 4)](https://github.com/trishullab/PutnamBench) | Lean 4 | 2024 | William Lowell Putnam competition problems formalized in Lean 4 | Apache-2.0 | Yes |
| [ProofNet-Lean4](https://github.com/rahul3613/ProofNet-lean4) | Lean 4 | 2024 | Undergraduate pure mathematics benchmark ported to Lean 4 + Mathlib4 | MIT | Yes |
| [MiniF2F-Lean4](https://huggingface.co/datasets/cat-searcher/minif2f-lean4) | Lean 4 | 2024 | Lean 4 + Mathlib4 port of the 488-problem Olympiad benchmark | MIT | Yes |
| [FormalMATH-Lite](https://huggingface.co/datasets/SphereLab/FormalMATH-Lite) | Lean 4 | 2025 | Verified Lean 4 Olympiad and undergraduate theorem benchmark | MIT | Yes |
| [NuminaMath-LEAN](https://huggingface.co/datasets/AI-MO/NuminaMath-LEAN) | Lean 4 | 2025 | 104K competition math problems formalized in Lean 4 with RLVR proofs | Apache-2.0 | No |

## Open-source repos

Stars as of 2026-11-25.

| Repo | What | Stars | License |
|---|---|---:|---|
| [leanprover/lean4](https://github.com/leanprover/lean4) | Lean 4 programming language and theorem prover | 10,046 | Apache-2.0 |
| [tobymao/sqlglot](https://github.com/tobymao/sqlglot) | Python SQL Parser and Transpiler | 9,800 | MIT |
| [leanprover-community/mathlib4](https://github.com/leanprover-community/mathlib4) | The math library of Lean 4 | 4,498 | Apache-2.0 |
| [deepseek-ai/DeepSeek-Prover-V2](https://github.com/deepseek-ai/DeepSeek-Prover-V2) | Lean 4 subgoal-decomposition theorem prover | 1,330 | custom (see repo) |
| [bird-bench/BIRD-CRITIC-1](https://github.com/bird-bench/BIRD-CRITIC-1) | BIRD-CRITIC (`SWE-SQL`) SQL diagnostic and repair harness | 1,107 | MIT |
| [xlang-ai/Spider2](https://github.com/xlang-ai/Spider2) | [ICLR 2025 Oral] Spider 2.0: Evaluating Language Models on Real-World Enterprise... | 893 | MIT |
| [lean-dojo/LeanDojo](https://github.com/lean-dojo/LeanDojo) | Tool for data extraction and interacting with Lean programmatically. | 853 | MIT |
| [leanprover-community/physlib](https://github.com/leanprover-community/physlib) | A project to digitalise results from physics into Lean. | 840 | Apache-2.0 |
| [InternLM/InternLM-Math](https://github.com/InternLM/InternLM-Math) | Lean 4 formal math models and `Lean-Workbook` autoformalization tools | 553 | Apache-2.0 |
| [bird-bench/mini_dev](https://github.com/bird-bench/mini_dev) | Compact evaluation code for BIRD Mini-Dev | 197 | no license file |
| [autoprotocol/autoprotocol-python](https://github.com/autoprotocol/autoprotocol-python) | Python library for generating Autoprotocol | 126 | custom (see repo) |
| [glee4810/EHRSQL](https://github.com/glee4810/EHRSQL) | Practical clinical Electronic Health Record text-to-SQL benchmark | 117 | CC BY 4.0 |
| [facebookresearch/miniF2F](https://github.com/facebookresearch/miniF2F) | An updated version of miniF2F with lots of fixes and informal statements / solutions. | 108 | MIT |
| [Sphere-AI-Lab/FormalMATH-Bench](https://github.com/Sphere-AI-Lab/FormalMATH-Bench) | Evaluation harness for the `FormalMATH` Lean 4 benchmark | 76 | Apache-2.0 |
| [Bioprotocols/labop](https://github.com/Bioprotocols/labop) | Laboratory Open Protocol (LabOP) Language | 55 | MIT |

## Papers

| Paper | Venue | Link |
|---|---|---|
| LeanDojo: Theorem Proving with Retrieval-Augmented Language Models | NeurIPS 2023 D&B | [arXiv:2306.15626](https://arxiv.org/abs/2306.15626) |
| MiniF2F: a cross-system benchmark for formal Olympiad-level mathematics | ICLR 2022 | [arXiv:2109.00110](https://arxiv.org/abs/2109.00110) |
| DeepSeek-Prover-V2: Advancing Formal Mathematical Reasoning via Reinforcement Learning for Subgoal Decomposition | arXiv 2025 | [arXiv:2504.21801](https://arxiv.org/abs/2504.21801) |
| Autoformalizing Euclidean Geometry | ICML 2024 | [arXiv:2405.17216](https://arxiv.org/abs/2405.17216) |
| Spider: A Large-Scale Human-Labeled Dataset for Complex and Cross-Domain Semantic Parsing and Text-to-SQL Task | EMNLP 2018 | [arXiv:1809.08887](https://arxiv.org/abs/1809.08887) |
| Can LLM Already Serve as A Database Interface? A BIg Bench for Large-Scale Database Grounded Text-to-SQLs | NeurIPS 2023 | [arXiv:2305.03111](https://arxiv.org/abs/2305.03111) |
| Spider 2.0: Evaluating Language Models on Real-World Enterprise Text-to-SQL Workflows | ICLR 2025 | [arXiv:2411.07763](https://arxiv.org/abs/2411.07763) |

## Conferences and workshops

- [Lean Together 2026](https://leanprover-community.github.io/lt2026/)
- [ITP - Interactive Theorem Proving](https://itp-conference.github.io/)
- [ICLR](https://iclr.cc/)
- [NeurIPS (main track, Datasets and Benchmarks, workshops)](https://neurips.cc/)
- [ACL 2026](https://2026.aclweb.org/)

## Progress

Recent results, newest first. Date = first arXiv version; each line is a short summary of the abstract.

| Date | Paper | In one line |
|---|---|---|
| 2026-11-03 | [Text-to-SQL Models Make Choices Without Saying So](https://arxiv.org/abs/2611.04318) | Text-to-SQL models settle open choices (count rows or distinct entities) without saying so; single-reference benchmarks miss it. |
| 2026-10-30 | [Post-SQLFix: Property-Guided Repair of LLM-Generated SQL with Runtime Verification](https://arxiv.org/abs/2610.41472) | Post-SQLFix: repairs generated SQL by checking required properties in layers, instead of trusting a model to judge its own fix. |
| 2026-10-24 | [Numina Fuse: Interactive Autoformalization in Lean 4](https://arxiv.org/abs/2610.33860) | Numina Fuse: interactive Lean 4 autoformalization built around human supervision of agent work. |
| 2026-10-14 | [Beyond LLM Judge: Mechanical Verification for Agentic Autoformalization](https://arxiv.org/abs/2610.20573) | Beyond LLM Judge: adds mechanical numerical and vacuity checks to catch faulty Lean formalizations. |

## Contributing

Found a broken link or a missing dataset, repo or paper? Open an issue or a pull request.

## License

Code in this repo: MIT. Listed datasets, repos and papers keep their own licenses.
