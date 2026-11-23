"""Command-line interface for `lab-verify` (`--db`, `--sql`, `--candidates`, `--lean`, `--protocol`, `--json`)."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any, Sequence

from .lean_gate import verify_lean
from .protocol_gate import verify_protocol
from .sql_gate import (
    EXPERIMENTS,
    INSTRUMENTS,
    LAYERS,
    SAMPLES,
    SCHEMA,
    BatchGateEvaluator,
    build_counterexample_dbs,
    build_db,
    open_readonly_db,
    validate_candidates_schema,
    verify_sql,
)


def evaluate_benchmark_file(
    candidates_path: Path,
    *,
    db_path: Path | None = None,
    as_json: bool = False,
    allow_cross_join: bool = False,
) -> int:
    items = json.loads(candidates_path.read_text(encoding="utf-8"))
    schema_errors = validate_candidates_schema(items)
    if schema_errors:
        if as_json:
            print(json.dumps({"passed": False, "schema_errors": schema_errors}, indent=2))
        else:
            for e in schema_errors:
                print(f"SCHEMA ERROR: {e}")
        return 1

    if db_path is not None:
        con, db_schema = open_readonly_db(db_path)
        ce_cons = []
    else:
        con = build_db()
        db_schema = SCHEMA
        ce_cons = build_counterexample_dbs()

    evaluator = BatchGateEvaluator(
        con,
        counterexample_cons=ce_cons,
        schema=db_schema,
        strict_joins=True,
        allow_cross_join=allow_cross_join,
    )

    if not as_json and db_path is None:
        print(
            "Toy lab database with SYNTHETIC data: "
            f"{len(EXPERIMENTS)} experiments, {len(SAMPLES)} samples, {len(INSTRUMENTS)} instruments."
        )
        print(f"{len(items)} questions, {sum(len(i['candidates']) for i in items)} candidates\n")
        print(f"{'q':>2}  {'label':<24} {'first failed layer':<20} reason")
        print("-" * 96)

    fails: Counter[int] = Counter()
    wrong = passed = passed_wrong = passed_static_wrong = agree = 0
    rows_json: list[dict[str, Any]] = []

    for item in items:
        try:
            evaluator.get_validated_gold(item["gold"])
        except ValueError as exc:
            if as_json:
                print(json.dumps({"passed": False, "gold_error": str(exc), "qid": item["qid"]}, indent=2))
            else:
                print(f"GOLD VALIDATION ERROR on qid {item['qid']}: {exc}")
            return 1

        for cand in item["candidates"]:
            layer, reason = evaluator.evaluate_candidate(cand["sql"], item["gold"])
            is_wrong = cand["label"] != "correct"
            shown = "PASS" if layer is None else f"{layer + 1} {LAYERS[layer]}"
            if not as_json:
                print(f"{item['qid']:>2}  {cand['label']:<24} {shown:<20} {reason[:48]}")
            rows_json.append(
                {
                    "qid": item["qid"],
                    "label": cand["label"],
                    "sql": cand["sql"],
                    "passed": layer is None,
                    "failed_layer": None if layer is None else LAYERS[layer],
                    "failed_layer_index": layer,
                    "reason": reason,
                    "agrees_with_label": bool(is_wrong == (layer is not None)),
                }
            )
            wrong += int(is_wrong)
            agree += int(is_wrong == (layer is not None))
            if layer is None:
                passed += 1
                passed_wrong += int(is_wrong)
            else:
                fails[layer] += 1
            if is_wrong and (layer is None or layer == 3):
                passed_static_wrong += 1

    total = sum(len(i["candidates"]) for i in items)
    if as_json:
        summary = {
            "total": total,
            "agree": agree,
            "wrong": wrong,
            "passed": passed,
            "passed_wrong": passed_wrong,
            "passed_static_wrong": passed_static_wrong,
            "stopped_by_layer": {LAYERS[i]: fails[i] for i in range(len(LAYERS))},
            "cache_hits": evaluator.cache_hits,
            "results": rows_json,
        }
        print(json.dumps(summary, indent=2))
    else:
        print("\nCandidates stopped at each layer:")
        for i, name in enumerate(LAYERS):
            print(f"  layer {i + 1} {name:<10} {fails[i]}")
        print(f"  passed all     {passed}")
        print(f"\nGate verdict agrees with hand label: {agree}/{total}")
        print(f"Wrong candidates: {wrong}; wrong ones passing the full gate: {passed_wrong}")
        print(f"Wrong candidates that would pass with layers 1-3 only: {passed_static_wrong}/{wrong}")

    if passed_wrong > 0 or agree != total:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab-verify",
        description="Default-deny verification gate for SQL queries, Lean 4 proofs, and lab protocols.",
    )
    parser.add_argument("--db", type=Path, default=None, help="Path to read-only SQLite database file.")
    parser.add_argument("--sql", type=str, default=None, help="Candidate SQL query to verify.")
    parser.add_argument("--gold", type=str, default=None, help="Optional reference gold SQL query.")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=None,
        help="Benchmark candidates JSON file (defaults to demo/candidates.json).",
    )
    parser.add_argument("--lean", type=Path, default=None, help="Lean 4 source file to audit.")
    parser.add_argument("--protocol", type=Path, default=None, help="Benchtop protocol JSON file to verify.")
    parser.add_argument(
        "--allow-cross-join",
        action="store_true",
        help="Allow explicit SQL CROSS JOIN in Layer 3.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit untruncated machine-readable JSON verdict output.",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, default_candidates: Path | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[2]

    if args.lean is not None:
        verdict = verify_lean(args.lean, run_toolchain=True)
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            print(f"{'PASS' if verdict.passed else 'FAIL'}: {verdict.reason}")
        return 0 if verdict.passed else 1

    if args.protocol is not None:
        verdict = verify_protocol(args.protocol)
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            print(f"{'PASS' if verdict.passed else 'FAIL'}: {verdict.reason}")
        return 0 if verdict.passed else 1

    if args.sql is not None:
        if args.db is not None:
            con, db_schema = open_readonly_db(args.db)
            ce_cons = []
        else:
            con = build_db()
            db_schema = SCHEMA
            ce_cons = build_counterexample_dbs() if args.gold else []

        verdict = verify_sql(
            con,
            args.sql,
            gold_sql=args.gold,
            counterexample_cons=ce_cons,
            schema=db_schema,
            allow_cross_join=args.allow_cross_join,
        )
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            status = "PASS" if verdict.passed else f"FAIL ({verdict.layer})"
            print(f"{status}: {verdict.reason}")
        return 0 if verdict.passed else 1

    cand_file = args.candidates or default_candidates or (repo_root / "demo" / "candidates.json")
    return evaluate_benchmark_file(
        cand_file,
        db_path=args.db,
        as_json=args.json,
        allow_cross_join=args.allow_cross_join,
    )


if __name__ == "__main__":
    raise SystemExit(main())
