# Architecture and History — `lab-verify`

> **Auto-Lab Ecosystem Role**: Layer `L4 · Digital-Twin Rehearsal & Default-Deny Verification` in [Robot AI Auto-Lab (`auto-lab`)](https://github.com/yaniguan/auto-lab) ([Project Studio](https://yaniguan.github.io/auto-lab/)).

---

## 1. Object

### Problem Statement
Language models and agentic planners routinely generate syntactically valid or plausible-looking outputs—SQL queries over laboratory and clinical records, formal proofs, or benchtop protocol specifications—that contain silent semantic defects (missing `WHERE` filters, NULL-unsafe `SUM(x)/COUNT(*)` averages, `COUNT` vs. `COUNT(DISTINCT)`, inverted sort directions, wrong join keys, custom Lean tactics calling `admitGoal`, or unauthenticated capability tokens) or destructive side effects (`DELETE`, `UPDATE`, stacked `DROP TABLE`, arbitrary Python imports). Relying on LLM self-critique or syntax-only parsing lets subtle errors corrupt scientific analyses and physical laboratory runs.

`lab-verify` defines the **strict mechanical default-deny verification gate** for Auto-Lab outputs across three target domains:
1. **SQL over lab and clinical databases** (`src/lab_verify/sql_gate.py`: 4-layer fail-fast AST, read-only SQLite authorizer, join-connectivity, and tie-aware Hopcroft-Karp `math.isclose` execution gate),
2. **Lean 4 formal specifications and proofs** (`src/lab_verify/lean_gate.py` & `lean/`: live Lean 4.36.0 compilation with `#print axioms` auditing and optional `leanchecker` replay, plus linkage to `LabLean` in [`YLM`](https://github.com/yaniguan/YLM)), and
3. **Machine-readable benchtop protocols and `lean-mcp/v1` hardware capability envelopes** (`src/lab_verify/protocol_gate.py`, `src/lab_verify/mcp_gate.py`, and `autolab_wire.py`, complementing [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal), [`stepbot`](https://github.com/yaniguan/stepbot), and [`twinstep`](https://github.com/yaniguan/twinstep)).

### Role in the Auto-Lab `L0`–`L6` Hierarchy
Within the [Auto-Lab](https://github.com/yaniguan/auto-lab) Brain/Body architecture (`L0`–`L6`), `lab-verify` resides in **`L4 · Digital-Twin Rehearsal & Default-Deny Verification`**:
- **Upstream (`L6` / `L5` / `L3` Brain)**: Intercepts structured queries, formalizations, and candidate artifacts emitted by scientific reasoning and post-trained language models ([`lab-ask-why`](https://github.com/yaniguan/lab-ask-why), [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain), [`lab-decide`](https://github.com/yaniguan/lab-decide)).
- **Peer (`L4`)**: Operates alongside [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal) (pre-execution 96-well deck-state rehearsal and episodic memory), [`lab-attrib`](https://github.com/yaniguan/lab-attrib) (post-execution causal blame, NNLS XRD precursor deconvolution, and SHA-256 certified ledger quarantine), and [`YLM`](https://github.com/yaniguan/YLM) (`lean/LabLean`, sound-and-complete Lean 4 bio-protocol checker).
- **Downstream (`L1`–`L2` Body / `L0` Ledger)**: Mints fail-closed `lean-mcp/v1` hardware capability envelopes consumed by [`stepbot`](https://github.com/yaniguan/stepbot) (`StepbotMcpExecutor`) ahead of [`lab-hands`](https://github.com/yaniguan/lab-hands) (`L1`) and [`lab-feet`](https://github.com/yaniguan/lab-feet) (`L0`), and protects structured experiment ledgers ([`assayfold`](https://github.com/yaniguan/assayfold)) from destructive writes and silent query miscalculations before post-run attribution in [`lab-attrib`](https://github.com/yaniguan/lab-attrib) feeds back into closed-loop decision making.

---

## 2. Data

### Synthetic In-Memory Laboratory Database (`src/lab_verify/sql_gate.py`)
`build_db()` constructs a deterministic, purely **synthetic** 30-row SQLite database (`:memory:`) locked with `PRAGMA query_only = ON` and `sqlite3.set_authorizer` across three tables, paired with `3` counterexample perturbation DBs (`build_counterexample_dbs()`):
- **`experiments`** (`12` rows): `id`, `date` (`2026-02-10`..`2026-04-22`, enforced via `CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')`), `operator` (`Kim`, `Patel`, `Novak`), `protocol` (`PCR`, `ELISA`, `Western`), `temperature_c`, `yield_pct`, `status` (`done`, `failed`, `running`), `instrument_id`.
- **`samples`** (`14` rows): `id` (`101`..`114`), `experiment_id`, `well`, `reagent` (`Taq`, `Antibody-X`, `Antibody-Y`, `Polymerase-Q`, `Blocking buffer`), `volume_ul`.
- **`instruments`** (`4` rows): `id` (`1`..`4`), `name` (`Thermocycler T1`, `Plate reader P2`, `Imager G3`, `Pipette robot R4`), `last_calibrated` (enforced via ISO `YYYY-MM-DD` `CHECK`).
- **Counterexample Perturbation DBs (`3` DBs)**: Perturbation #1 shifts highest-yield protocol to `ELISA` (`96.5%`) and adds a 6th distinct reagent; Perturbation #2 shifts highest-yield protocol to `Western` (`94.0%`); Perturbation #3 adds an in-progress `ELISA` run with `yield_pct = NULL` to expose `SUM(yield_pct) / COUNT(*)` NULL-denominator bugs (`qid 4`).

### Candidate Evaluation Suite (`demo/candidates.json`)
Contains `12` laboratory analytics questions (`qid = 1..12`), each with a verified `gold` SQL query and `1`–`2` hand-authored candidate queries totaling **`22` candidates** (`7` semantically equivalent `correct` reformulations and `15` realistic LLM error modes):
- **Syntax failure (`1`)**: unclosed parenthesis in `AVG(yield_pct ...` (`qid 4`).
- **Write / multi-statement attacks (`3`)**: `DELETE` (`qid 5`), stacked `SELECT ...; DROP TABLE samples` (`qid 5`), `UPDATE` (`qid 9`).
- **Schema hallucinations (`3`)**: nonexistent column `scientist` (`qid 2`), nonexistent column `calibrated_on` (`qid 7`), wrong table `well FROM experiments` (`qid 10`).
- **Semantic / execution errors (`8`)**: missing `WHERE` filter (`qid 1`, `qid 12`), NULL-unsafe `SUM(yield_pct) / COUNT(*)` average (`qid 4`), `COUNT` vs. `COUNT(DISTINCT)` (`qid 3`, `qid 8`), wrong join predicate `s.id = e.id` (`qid 6`), inverted inequality `>` vs. `<` (`qid 7`), inverted `ORDER BY ... ASC LIMIT 1` (`qid 9`).

### Real Clinical EHRSQL-2024 & Open Benchmark Evaluation (`results/ehrsql_2024_real.json`)
`scripts/run_ehrsql_real.py` downloads the open **MIMIC-IV Clinical Database Demo v2.2** (`ODbL-1.0`, `17` tables, `317,875` rows) and **EHRSQL-2024** (`CC-BY-4.0`, `1,163` validation items) into gitignored `data/ehrsql_2024/`, builds the clinical SQLite database in pure Python, and evaluates the full validation suite:
- **EHRSQL-2024 answerable gold-vs-gold**: **`931 / 931` passed** (`0` failures).
- **EHRSQL-2024 unanswerable abstention**: **`232 / 232` passed**.
- **BIRD Mini-Dev SQLite (`CC-BY-SA-4.0`, `500` items)**: **`500 / 500` passed** static parse, read-only, and join-connectivity audit.

---

## 3. Model

`lab-verify` trains **no neural model**. Its verification engines are deterministic mechanical gates:

### A. 4-Layer SQL Gate (`src/lab_verify/sql_gate.py`)
1. **Layer 1 — Syntax Parse (`check_parse`)**: Strict SQLite `sqlglot.parse(..., error_level=RAISE)`, rejecting empty/comment-only SQL and syntax errors.
2. **Layer 2 — Read-Only & Function Gate (`check_read_only`)**: Allows strictly one `Select` or `SetOperation`, blocking `DELETE`/`UPDATE`/`INSERT`/`DROP`/`PRAGMA`/`ATTACH` and memory-amplifying functions (`randomblob`, `zeroblob`, `printf`, `format`, `load_extension`), backed by SQLite `PRAGMA query_only = ON` and `set_authorizer`.
3. **Layer 3 — Lexical Schema & Join-Connectivity Validator (`check_schema`)**: Validates per-scope tables, CTEs, aliases, and columns; accepts comma joins (`FROM a, b WHERE a.id = b.a_id`) when `WHERE` links joined sources and `CROSS JOIN` with bounded/scalar CTEs while rejecting unconstrained Cartesian joins and exponential recursive CTE string bombs.
4. **Layer 4 — Execution Equivalence (`run_query` + `compare_results`)**: Enforces configurable `max_vm_steps`, `timeout_s`, `max_rows`, and `max_value_bytes` budgets; compares unordered results via Hopcroft-Karp bipartite matching under type-safe `math.isclose(rel_tol=1e-6, abs_tol=1e-6)` (`cells_equal`); and evaluates `ORDER BY` queries with tie-aware sort-key block matching (accepting valid tie-breakers within equal gold sort keys and marking `LIMIT`-cut ties `"ambiguous_gold"`).

### Empirical Gate Baseline (`demo/output.txt`)
On the 22-candidate suite:
- **Layer 1 (`parse`)** stops `1` candidate; **Layer 2 (`read-only`)** stops `3`; **Layer 3 (`schema`)** stops `3`; **Layer 4 (`execution`)** stops `8`; **`7` pass all 4 layers**.
- Gate verdict matches ground-truth hand labels on **`22 / 22` (`100%`)** candidates, with `0` false accepts, while **`8 / 15` (`53.3%`)** of wrong candidates pass static Layers 1–3 and are caught only by Layer 4 execution and counterexample DBs.

### B. Live Lean 4 Proof & Axiom Gate (`src/lab_verify/lean_gate.py`)
Compiles every candidate `.lean` file or proof string in a temporary module with `#print axioms <decl>` appended for every `theorem`, `lemma`, `def`, and `abbrev`, invokes `lean` or `lake env lean` (with absolute paths), optionally replays `.olean` files through `leanchecker`, and enforces `axioms <= {propext, Classical.choice, Quot.sound}`—failing closed whenever `lean`/`lake` is missing unless `static_only=True` is explicitly requested.

### C. Fail-Closed `lean-mcp/v1` & Wire Gate (`src/lab_verify/mcp_gate.py`, `autolab_wire.py`)
Rejects `DEFAULT_MCP_SECRET_KEY` unless `allow_insecure_dev_key=True`, requires `actual_protocol` / `actual_protocol_sha256` payload binding unless `require_payload_binding=False`, verifies `human_supervisor_signed` strictly via a distinct `supervisor_secret_key` HMAC or distinct Ed25519 supervisor key, checks Opentrons transfer volumes against `max_transfer_ul`, fails closed when `check_lean_kernel=True` and `lab-verify-lean` is missing, blocks protocol-less wire packets, and supports custom read-only `db_path` schemas.

---

## 4. Training

- **Zero Parametric Training**: `lab-verify` is a purely symbolic, compiler-backed, and execution-grounded verification harness. No weights are trained, fine-tuned, or loaded.
- **Role in Closed-Loop Post-Training (`L3`)**: Supplies verifiable reward/rejection signals and layer-attributed diagnostics for [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain) and [`twinstep`](https://github.com/yaniguan/twinstep).

---

## 5. History

| Commit / Ref | Date | Author | Branch / Ref | Summary |
|---|---|---|---|---|
| `3255ec7` | `2026-11-18` | Yani Guan | `main` | Initial commit: 4-layer SQL default-deny gate (`demo/sql_gate.py`), 12-question / 22-candidate benchmark, CI, and formal/SQL catalog. |
| `a5f9aec` | `2026-11-25` | Yani Guan | `main` | Phase-2 audit hardening (`PR #30`): Ed25519 role-separated co-signatures, bounded TTL/key-epoch checks, recursive CTE guards, and `autolab_wire.py`. |
| `0c29ffc` | `2026-11-26` | Yani Guan | `main` | Open 2024–2026 SQL/Lean benchmark adapters (`catalog/sources.json` `v1.1.0`) and Hopcroft-Karp unordered float matching (`PR #31`). |
| `feat/frontier-lean-ehrsql-and-failclosed-mcp` | `2026-11-27` | Yani Guan | `main` | Resolved Issues `#32`, `#33`, `#34`, `#35`: live Lean 4.36.0 compilation + `#print axioms` + CI job, tie-aware `ORDER BY` + comma/scalar-CTE joins + configurable limits + real MIMIC-IV Demo v2.2 EHRSQL-2024 (`931/931` + `232/232`), fail-closed `lean-mcp/v1` & wire defaults, and NULL-safe `q4` + ISO date `CHECK` + 14 non-identical mutant SQL rewrites. |

---

## 6. Unique Properties

1. **Defense-in-Depth Read-Only Isolation**: Enforces read-only safety statically (`sqlglot` AST) and dynamically (`mode=ro` URI, `PRAGMA query_only = ON`, `sqlite3.set_authorizer`, opcode/time/row/byte caps).
2. **Compiler-Backed Axiom Auditing**: Invokes Lean 4.36.0 (`lean` / `lake env lean` + `#print axioms` + optional `leanchecker`) to catch custom tactic `admitGoal` (`sorryAx`), unproved `rfl`, and custom `axiom` declarations.
3. **Auto-Lab Sibling Contracts (`autolab-wire/v1`)**: Pairs pre-execution default-deny SQL, Lean, and `lean-mcp/v1` capability gates with [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal), [`stepbot`](https://github.com/yaniguan/stepbot), and post-execution causal attribution in [`lab-attrib`](https://github.com/yaniguan/lab-attrib).
