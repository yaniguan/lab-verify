# lab-verify

Trust nothing a model writes until a *strict checker* says yes: Lean for logic, SQL for data, protocol rules for the bench.

## Where it fits

In the lab agent on [yaniguan.github.io](https://yaniguan.github.io/), the body (a bounded harness around every job) puts a default-deny gate on each job. This repo collects checkers and benchmarks for three kinds of model output: Lean proofs, SQL queries over lab data, and machine-readable protocols. A Lean 4 protocol language is being built separately in [YLM](https://github.com/yaniguan/YLM) (`lean/`), so it is linked, not copied, here. The first attempt is a layered SQL gate.

## First attempt

An in-memory SQLite database with **synthetic** experiments, samples and instruments. 12 questions with gold SQL and 22 hand-written candidates (8 correct, 14 with typical model errors: wrong column, missing filter, COUNT vs COUNT DISTINCT, wrong join, syntax error, DELETE/UPDATE/DROP). The gate has four layers and stops at the first failure: 1 parse (sqlglot), 2 read-only, 3 schema, 4 execution match against gold.

```bash
pip install sqlglot
python demo/sql_gate.py
```

Output (Linux, CPU only, 2026-11-18):

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
 7  wrong comparison         4 execution          2 rows vs 2 gold rows
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
