# Architecture and History — `lab-verify`

> **Auto-Lab Ecosystem Role**: Layer `L4 · Digital-Twin Rehearsal & Default-Deny Verification` in [Robot AI Auto-Lab (`auto-lab`)](https://github.com/yaniguan/auto-lab) ([Project Studio](https://yaniguan.github.io/auto-lab/)).

---

## 1. Object

### Problem Statement
Language models and agentic planners routinely generate syntactically valid or plausible-looking outputs—SQL queries over laboratory records, formal proofs, or benchtop protocol specifications—that contain silent semantic defects (missing `WHERE` filters, `COUNT` vs. `COUNT(DISTINCT)`, inverted sort directions, wrong join keys) or destructive side effects (`DELETE`, `UPDATE`, stacked `DROP TABLE`). Relying on LLM self-critique or syntax-only parsing lets subtle errors corrupt scientific analyses and laboratory databases.

`lab-verify` defines the **strict mechanical verification gate** for Auto-Lab outputs across three target domains:
1. **SQL over lab databases** (implemented in `demo/sql_gate.py` as a 4-layer fail-fast AST + execution gate),
2. **Lean 4 formal specifications and proofs** (linked without duplication to `LabLean` in [`YLM`](https://github.com/yaniguan/YLM) `lean/`), and
3. **Machine-readable benchtop protocols** (complementing [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal), [`stepbot`](https://github.com/yaniguan/stepbot), and [`twinstep`](https://github.com/yaniguan/twinstep)).

### Role in the Auto-Lab `L0`–`L6` Hierarchy
Within the [Auto-Lab](https://github.com/yaniguan/auto-lab) Brain/Body architecture (`L0`–`L6`), `lab-verify` resides in **`L4 · Digital-Twin Rehearsal & Default-Deny Verification`**:
- **Upstream (`L6` / `L5` / `L3` Brain)**: Intercepts structured queries, formalizations, and candidate artifacts emitted by scientific reasoning and post-trained language models ([`lab-ask-why`](https://github.com/yaniguan/lab-ask-why), [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain), [`lab-decide`](https://github.com/yaniguan/lab-decide)).
- **Peer (`L4`)**: Operates alongside [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal) (deck-state rehearsal and episodic memory) and [`YLM`](https://github.com/yaniguan/YLM) (`lean/LabLean`, sound-and-complete Lean 4 bio-protocol checker).
- **Downstream (`L0` Ledger / `L1`–`L2` Body)**: Protects structured experiment ledgers ([`assayfold`](https://github.com/yaniguan/assayfold)) from destructive writes and silent query miscalculations before results feed back into closed-loop decision making.

### Inputs, Outputs, and Scope Boundaries
- **Inputs**:
  - Natural-language lab data questions paired with gold reference SQL and candidate SQL strings (`demo/candidates.json`).
  - Target relational database schema (`SCHEMA`) and read-only SQLite connection (`build_db()`).
- **Outputs**:
  - Per-candidate tuple `(failed_layer_index: int | None, reason: str)` identifying either `PASS` (`None, "match"`) or the exact first layer (`1 parse`, `2 read-only`, `3 schema`, `4 execution`) and diagnostic message where the candidate was rejected.
  - Aggregate funnel metrics across layers and static-only (`layers 1–3`) vs. full-gate (`layers 1–4`) false-acceptance rates (`demo/output.txt`).
- **Scope Boundaries**:
  - `demo/sql_gate.py` currently evaluates SQLite-dialect queries against an in-memory synthetic database with gold reference queries. Lean 4 proof/protocol checking lives in [`YLM`](https://github.com/yaniguan/YLM) (`lean/`) rather than being duplicated in this repository.

---

## 2. Data

### Synthetic In-Memory Laboratory Database (`demo/sql_gate.py`)
`demo/sql_gate.py` constructs a deterministic, purely **synthetic** 30-row SQLite database (`:memory:`) locked with `PRAGMA query_only = ON` across three tables:
- **`experiments`** (`12` rows): `id`, `date` (`2026-02-10`..`2026-04-22`), `operator` (`Kim`, `Patel`, `Novak`), `protocol` (`PCR`, `ELISA`, `Western`), `temperature_c`, `yield_pct`, `status` (`done`, `failed`, `running`).
- **`samples`** (`14` rows): `id` (`101`..`114`), `experiment_id`, `well`, `reagent` (`Taq`, `Antibody-X`, `Antibody-Y`, `Polymerase-Q`, `Blocking buffer`), `volume_ul`.
- **`instruments`** (`4` rows): `id` (`1`..`4`), `name` (`Thermocycler T1`, `Plate reader P2`, `Imager G3`, `Pipette robot R4`), `last_calibrated`.

### Candidate Evaluation Suite (`demo/candidates.json`)
Contains `12` laboratory analytics questions (`qid = 1..12`), each with a verified `gold` SQL query and `1`–`2` hand-authored candidate queries totaling **`22` candidates** (`8` semantically equivalent `correct` reformulations and `14` realistic LLM error modes):
- **Syntax failure (`1`)**: unclosed parenthesis in `AVG(yield_pct ...` (`qid 4`).
- **Write / multi-statement attacks (`3`)**: `DELETE` (`qid 5`), stacked `SELECT ...; DROP TABLE samples` (`qid 5`), `UPDATE` (`qid 9`).
- **Schema hallucinations (`3`)**: nonexistent column `scientist` (`qid 2`), nonexistent column `calibrated_on` (`qid 7`), wrong table `well FROM experiments` (`qid 10`).
- **Semantic / execution errors (`7`)**: missing `WHERE` filter (`qid 1`, `qid 12`), `COUNT` vs. `COUNT(DISTINCT)` (`qid 3`, `qid 8`), wrong join predicate `s.id = e.id` (`qid 6`), inverted inequality `>` vs. `<` (`qid 7`), inverted `ORDER BY ... ASC LIMIT 1` (`qid 9`).

### Curated External Benchmarks and License Posture
`README.md` catalogs 5 external text-to-SQL and formal-reasoning benchmarks (`Spider` CC BY-SA 4.0, `BIRD` CC BY-SA 4.0, `Spider 2.0` MIT code, `miniF2F` MIT, `LeanDojo Benchmark`), 11 open-source tools (`lean4`, `sqlglot`, `mathlib4`, `DeepSeek-Prover-V2`, `Spider2`, `LeanDojo`, `physlib`, `bird-bench/mini_dev`, `autoprotocol-python`, `miniF2F`, `labop`), and 11 research papers (`2018`–`2026`). No external benchmark files are redistributed in the repository; custom or missing upstream licenses (`DeepSeek-Prover-V2`, `bird-bench/mini_dev`, `autoprotocol-python`) are explicitly annotated.

---

## 3. Model

`lab-verify` trains **no neural model**. Its core verification engine (`demo/sql_gate.py`) is a deterministic **4-layer sequential default-deny filter** (`LAYERS = ["parse", "read-only", "schema", "execution"]`) using `sqlglot` AST analysis and read-only SQLite execution:

1. **Layer 1 — Syntax Parse (`check_parse`)**:
   - Parses candidate SQL under the SQLite dialect via `sqlglot.parse(sql, read="sqlite")`. Rejects malformed SQL on `sqlglot.errors.ParseError`.
2. **Layer 2 — Read-Only Statement Gate (`check_read_only`)**:
   - Enforces `len(stmts) == 1` (blocking stacked multi-statement injection) and `isinstance(stmts[0], (exp.Select, exp.SetOperation))` (blocking `DELETE`, `UPDATE`, `INSERT`, `DROP`, `ALTER`, `PRAGMA`). Backed at the database engine level by SQLite `PRAGMA query_only = ON`.
3. **Layer 3 — Static Schema Resolution (`check_schema`)**:
   - Traverses `exp.Table`, `exp.Alias`, and `exp.Column` nodes in the AST. Verifies every referenced table exists in `SCHEMA`, resolves table aliases, and checks qualified (`table.col`) and unqualified (`col`) column references against `SCHEMA` and projection aliases.
4. **Layer 4 — Execution Multiset Equivalence (`run` + `gate`)**:
   - Executes both candidate and gold queries on the in-memory SQLite database, normalizes floating-point cells via `round(v, 6)`, and compares result multisets (`collections.Counter` of row tuples).

### Empirical Gate Baseline (`demo/output.txt`)
On the 22-candidate suite:
- **Layer 1 (`parse`)** stops `1` candidate; **Layer 2 (`read-only`)** stops `3`; **Layer 3 (`schema`)** stops `3`; **Layer 4 (`execution`)** stops `7`; **`8` pass all 4 layers**.
- Gate verdict matches ground-truth hand labels on **`22 / 22` (`100%`)** candidates, with `0` false accepts.
- Crucially, **`7 / 14` (`50%`)** of wrong candidates pass static checks (Layers 1–3) cleanly and are caught *only* by Layer 4 execution verification—demonstrating empirically why parser-and-schema guardrails alone are insufficient for scientific agents.

---

## 4. Training

- **Zero Parametric Training**: `lab-verify` is a purely symbolic, rule-based, and execution-grounded verification harness (`sqlglot` + Python `sqlite3`). No weights are trained, fine-tuned, or loaded.
- **Role in Closed-Loop Post-Training (`L3`)**: Within the broader Auto-Lab architecture, deterministic pass/fail signals and layer-attributed error diagnostics from `lab-verify` provide verifiable reward/rejection signals (RLVR / property-guided repair) for downstream training and evaluation pipelines such as [`labbench-posttrain`](https://github.com/yaniguan/labbench-posttrain) and [`twinstep`](https://github.com/yaniguan/twinstep).

---

## 5. History

| Commit | Date | Author | Branch / Ref | Summary |
|---|---|---|---|---|
| `3255ec7` (`3255ec79775bb4127b0ffaead188147c6ac79229`) | `2026-11-18` | Yani Guan | `main` | Initial commit (`Add curated resources and first demo`): implemented the 4-layer SQL default-deny gate (`demo/sql_gate.py`) over a 30-row synthetic SQLite lab database, authored the 12-question / 22-candidate benchmark (`demo/candidates.json`, `demo/output.txt`), added CI (`.github/workflows/demo.yml`), linked `YLM` (`lean/`), and curated formal-verification and text-to-SQL benchmarks, repos, and papers (`2018`–`2026`). |

---

## 6. Unique Properties

1. **Defense-in-Depth Read-Only Isolation**: Enforces read-only safety twice—statically at the AST level (`len(stmts) == 1` and `Select | SetOperation`) and dynamically at the SQLite engine level (`PRAGMA query_only = ON`)—before comparing execution results.
2. **Quantified Static-vs.-Semantic Failure Decomposition**: Explicitly measures the gap between syntactic/schema validity (Layers 1–3, catching 7/14 errors) and semantic execution correctness (Layer 4, catching the remaining 7/14 errors).
3. **Zero-Duplication Formal Verification Link**: Delegates Lean 4 bio-protocol formalization (`Spec.lean`, `Checker.lean`, `Theorems.lean` proving `check s l = true ↔ ValidProtocol s l` with zero `sorry`) to [`YLM`](https://github.com/yaniguan/YLM) (`lean/LabLean`), maintaining a single source of truth for formal protocol semantics.
4. **Auto-Lab Sibling Contracts**:
   - Pairs with [`lab-rehearsal`](https://github.com/yaniguan/lab-rehearsal) in `L4` to cover both symbolic/database queries (`lab-verify`) and stateful deck execution (`lab-rehearsal`).
   - Protects structured experiment schemas shared with [`assayfold`](https://github.com/yaniguan/assayfold) (`L0`) and [`buy-or-make`](https://github.com/yaniguan/buy-or-make) (`L5`).
