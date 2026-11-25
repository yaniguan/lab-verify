# lab-verify

Trust nothing a model writes until a *strict checker* says yes: Lean for logic, SQL for data, protocol rules for the bench.

> **Auto-Lab Ecosystem**: Layer `L4 · Digital-Twin Rehearsal & Default-Deny Verification` in [auto-lab](https://github.com/yaniguan/auto-lab) · [Project Studio](https://yaniguan.github.io/auto-lab/)

## Where it fits

In the [Auto-Lab](https://github.com/yaniguan/auto-lab) system ([yaniguan.github.io/auto-lab](https://yaniguan.github.io/auto-lab/)), the body (a bounded harness around every job) puts a default-deny gate on each job. This repo collects checkers and benchmarks for three kinds of model output: Lean proofs, SQL queries over lab data, and machine-readable protocols. A Lean 4 protocol language is being built separately in [YLM](https://github.com/yaniguan/YLM) (`lean/`), so it is linked, not copied, here. The first attempt is a layered SQL gate.

## System Profile: Object · Data · Model · Training · History · Unique Properties

Full architectural documentation, verification-layer semantics, commit history, and sibling-repository contracts are maintained in [`docs/ARCHITECTURE_AND_HISTORY.md`](docs/ARCHITECTURE_AND_HISTORY.md):

- **Object**: Default-deny mechanical verification gate (`L4`) auditing LLM-generated SQL queries, formal Lean 4 proofs (`YLM/lean`), and laboratory protocol outputs before database execution or benchtop dispatch.
- **Data**: Deterministic 30-row **synthetic** in-memory SQLite lab database (`12` experiments, `14` samples, `4` instruments), `12` analytics questions with gold SQL and `22` labeled candidate queries (`8` correct, `14` error cases in `demo/candidates.json`), plus curated links to 5 text-to-SQL/Lean benchmarks and 11 open-source verification repos.
- **Model**: Four-layer sequential fail-fast SQL gate (`demo/sql_gate.py`): Layer 1 syntax parse (`sqlglot`), Layer 2 AST + SQLite `PRAGMA query_only` read-only enforcement, Layer 3 static table/column schema resolution, and Layer 4 execution multiset equivalence (`22/22` label agreement; catches `7/14` semantic errors missed by static layers 1–3). No neural model is trained here.
- **Training**: Zero parametric training; deterministic symbolic/execution checker designed to gate runtime inference and supply verifiable pass/fail feedback to `L3` post-training (`labbench-posttrain`, `twinstep`).
- **History**: Initialized in `3255ec7` (`2026-11-18`) with the 4-layer SQLite gate, 22-candidate benchmark suite, reference output, CI workflow, and formal/SQL literature map.
- **Unique Properties**: Dual AST + engine-level read-only isolation, explicit quantification of static vs. semantic error catch rates (`50%` static-pass error rate among wrong SQL queries), and non-duplicated linkage to the sound-and-complete Lean 4 `LabLean` checker in `YLM`.

## Repository Layout

```text
lab-verify/
├── .github/workflows/
│   └── demo.yml                          # CI matrix (Python 3.10-3.12): pytest, 22/22 parity, catalog check
├── catalog/
│   └── sources.json                      # SPDX, ShareAlike, and commercial-use manifest for benchmarks/repos
├── demo/
│   ├── candidates.json                   # Core 12 lab SQL questions, gold queries, and 22 candidates (22/22)
│   ├── candidates_extended.json          # Extended CTE, multi-row ORDER BY, and NULL-aware benchmark suite
│   ├── output.txt                        # Reference 4-layer gate evaluation table and summary
│   └── sql_gate.py                       # CLI / benchmark wrapper around lab_verify
├── docs/
│   └── ARCHITECTURE_AND_HISTORY.md       # Deep technical profile (Object, Data, Model, History)
├── schema/
│   └── candidates.schema.json            # Strict JSON Schema for SQL candidate benchmarks
├── scripts/
│   └── check_catalog.py                  # Automated SPDX license & markdown URL validator
├── src/lab_verify/
│   ├── __init__.py                       # Unified verify() entry point and public API
│   ├── cli.py                            # CLI (--sql, --lean, --protocol, mcp-mint, mcp-verify)
│   ├── lean_gate.py                      # Lean 4 vacuity/sorry/axiom detector and lake toolchain runner
│   ├── mcp_gate.py                       # Wire-compatible lean-mcp/v1 capability minting & stateful gate
│   ├── properties.py                     # Runtime semantic property checks (fanout, ranges, uniqueness)
│   ├── protocol_gate.py                  # Benchtop protocol verifier compatible with lab-rehearsal/twinstep
│   ├── sql_gate.py                       # Hardened 4-layer SQL gate + SQLite authorizer & progress timeout
│   └── verdict.py                        # Common VerifyVerdict / Verdict dataclass
├── tests/
│   ├── test_autolab_wire.py              # Auto-Lab 15-repo wire node (autolab-wire/v1) test suite
│   ├── test_community_extensions.py      # Firewall & mutant-SQL counterexample benchmark tests
│   ├── test_mcp_runtime_gate.py          # Zero-trust lean-mcp/v1 envelope, deferral & CLI test suite
│   └── test_sql_gate.py                  # 54-case unit & adversarial SQL/Lean/protocol red-team test suite
├── autolab_wire.py                       # Layer L4 autolab-wire/v1 node & stepbot capability minter
├── LICENSE                               # MIT License
├── pyproject.toml                        # Package metadata and lab-verify console script
├── README.md                             # Overview, SQL gate results, and verification catalog
└── requirements.txt                      # Pinned runtime dependency (sqlglot>=25.0,<31.0)
```

## First attempt

An in-memory SQLite database with **synthetic** experiments, samples and instruments (typed with `PRIMARY KEY` / `FOREIGN KEY` constraints, `PRAGMA query_only = ON`, strict `sqlite3.set_authorizer`, VM instruction step budget, and multi-seed counterexample perturbations). 12 questions with gold SQL and 22 hand-written candidates (8 correct, 14 with typical model errors: wrong column, missing filter, COUNT vs COUNT DISTINCT, wrong join, syntax error, DELETE/UPDATE/DROP). The gate has four layers and stops at the first failure: 1 parse (sqlglot), 2 read-only, 3 lexical schema, 4 execution match against gold (or runtime property checks when no gold query exists).

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
 4  correct                  PASS                 match
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
  layer 4 execution  7
  passed all     8

Gate verdict agrees with hand label: 22/22
Wrong candidates: 14; wrong ones passing the full gate: 0
Wrong candidates that would pass with layers 1-3 only: 7/14
```

Parse, read-only and schema checks catch the loud errors, but half of the wrong queries (7 of 14) look fine to them and only the execution match catches them. A real gate needs a reference answer or a property test, not just a parser.

## Lean-MCP Runtime Gate (`lean-mcp/v1`)

`lab_verify.mcp_gate` implements wire-compatible `lean-mcp/v1` zero-trust capability envelopes shared directly with [`stepbot`](https://github.com/yaniguan/stepbot). Every hardware capability token binds:
1. Canonical HMAC-SHA256 (`mcp_hmac_authentic`, default wire-compatible mode) or asymmetric Ed25519 role-separated signatures (`mcp_signature_authentic`, `auth_mode="ed25519"`) over sorted JSON metadata and deck/volume bounds;
2. Deterministic `protocol_sha256` payload binding (`mcp_payload_binding`);
3. Active cryptographic key-rotation epoch (`mcp_key_epoch_active`), monotonic physical `token_epoch == current_deck_epoch` freshness (`mcp_epoch_freshness`), and bounded wall-clock TTL / co-signature expiration (`mcp_ttl_unexpired`);
4. Single-use `nonce` tracking (`mcp_nonce_single_use`) persisted atomically across CLI invocations via `--state <path.json>` (`McpStateStore` OS lockfile + `fsync` + `os.replace`);
5. Zero-click autonomous execution inside the Lean-certified regime (`lean_proof_valid and not is_frontier_exception`), while parking unsigned `is_frontier_exception` calls in `LeanMcpGate.deferred_daytime_queue` (`L4_VERIFY_FRONTIER_DEFERRED`) for daytime human co-signature (`cosign_deferred_packet` / `mcp_proof_or_cosigned_exception`).

```bash
lab-verify mcp-mint --protocol run_script.py --state mcp_state.json --secret-key "$LEAN_MCP_SECRET_KEY" -o envelope.json
lab-verify mcp-verify envelope.json --protocol run_script.py --state mcp_state.json --mutates-deck-state --secret-key "$LEAN_MCP_SECRET_KEY" --json
```

## 15-Repository Auto-Lab Wire Contract (`autolab-wire/v1`)

`autolab_wire.py` (`REPO_ID = "lab-verify"`, `LAYER = "L4"`) connects `lab-verify` into the closed-loop 15-repository [Auto-Lab](https://github.com/yaniguan/auto-lab) wire pipeline (`autolab-wire/v1`):

- **Upstream Pre-Execution Flow (`L6` / `L5` / `L4`)**: Consumes candidate SQL queries and rehearsed 96-well protocol IR (`rehearsal.protocol_yaml_dict`) from [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal) downstream of [`lab-ears`](https://github.com/yaniguan/lab-ears), [`lab-ask-why`](https://github.com/yaniguan/lab-ask-why), [`lab-decide`](https://github.com/yaniguan/lab-decide), [`assayfold`](https://github.com/yaniguan/assayfold), [`lab-automation-atlas`](https://github.com/yaniguan/lab-automation-atlas), [`buy-or-make`](https://github.com/yaniguan/buy-or-make), and [`labshift`](https://github.com/yaniguan/labshift).
- **Default-Deny SQL & `lean-mcp/v1` Minting (`L4` -> `L1` `stepbot`)**: `process_packet(packet)` runs the 4-layer read-only SQLite gate (`L4_VERIFY_SQL_BLOCK` on mutating or invalid SQL) and mints an HMAC-authenticated `lean-mcp/v1` capability envelope (`invariant="autonomous_wire_envelope_soundness"`). `mint_for_compiled_stepbot(packet)` binds `verification.mcp_envelope` to the exact compiled Opentrons Python SHA-256 and bounds emitted by [`stepbot`](https://github.com/yaniguan/stepbot) (`StepbotMcpExecutor`), gating physical actuation across [`stepbot`](https://github.com/yaniguan/stepbot), [`lab-hands`](https://github.com/yaniguan/lab-hands) (`L1`), and [`lab-feet`](https://github.com/yaniguan/lab-feet) (`L0`).
- **Sibling `L4` Post-Run Partner ([`lab-attrib`](https://github.com/yaniguan/lab-attrib))**: Pairs pre-execution default-deny gates (`lab-rehearsal` + `lab-verify`) with post-execution causal blame, NNLS XRD precursor deconvolution, and SHA-256 certified ledger quarantine in [`lab-attrib`](https://github.com/yaniguan/lab-attrib) before verified runs reach [`twinstep`](https://github.com/yaniguan/twinstep), [`labfill`](https://github.com/yaniguan/labfill), and [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain) (`L3`).

## Datasets

| Dataset | What | License |
|---|---|---|
| [Spider](https://yale-lily.github.io/spider) | Cross-domain text-to-SQL | CC BY-SA 4.0 |
| [BIRD](https://bird-bench.github.io/) | Large database-grounded text-to-SQL | CC BY-SA 4.0 |
| [Spider 2.0](https://spider2-sql.github.io/) | Enterprise text-to-SQL workflows | MIT (code) |
| [miniF2F](https://github.com/facebookresearch/miniF2F) | Formal olympiad math statements | MIT |
| [LeanDojo Benchmark](https://leandojo.org/) | Theorems and proofs from mathlib | See project site |

## Open-source repos

Stars as of 2026-11-18.

| Repo | What | Stars | License |
|---|---|---:|---|
| [leanprover/lean4](https://github.com/leanprover/lean4) | Lean 4 programming language and theorem prover | 10,046 | Apache-2.0 |
| [tobymao/sqlglot](https://github.com/tobymao/sqlglot) | Python SQL Parser and Transpiler | 9,800 | MIT |
| [leanprover-community/mathlib4](https://github.com/leanprover-community/mathlib4) | The math library of Lean 4 | 4,498 | Apache-2.0 |
| [deepseek-ai/DeepSeek-Prover-V2](https://github.com/deepseek-ai/DeepSeek-Prover-V2) | - | 1,330 | custom (see repo) |
| [xlang-ai/Spider2](https://github.com/xlang-ai/Spider2) | [ICLR 2025 Oral] Spider 2.0: Evaluating Language Models on Real-World Enterprise... | 889 | MIT |
| [lean-dojo/LeanDojo](https://github.com/lean-dojo/LeanDojo) | Tool for data extraction and interacting with Lean programmatically. | 853 | MIT |
| [leanprover-community/physlib](https://github.com/leanprover-community/physlib) | A project to digitalise results from physics into Lean. | 840 | Apache-2.0 |
| [bird-bench/mini_dev](https://github.com/bird-bench/mini_dev) | - | 195 | no license file |
| [autoprotocol/autoprotocol-python](https://github.com/autoprotocol/autoprotocol-python) | Python library for generating Autoprotocol | 126 | custom (see repo) |
| [facebookresearch/miniF2F](https://github.com/facebookresearch/miniF2F) | An updated version of miniF2F with lots of fixes and informal statements / solutions. | 108 | MIT |
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
