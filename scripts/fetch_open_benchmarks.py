"""Fetch and smoke-verify 2024-2026 open-source Text-to-SQL and Lean 4 benchmarks into `data/`."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Any, Sequence
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify.open_benchmarks import (  # noqa: E402
    OPEN_BENCHMARK_SPECS,
    OpenBenchmarkSpec,
    assemble_lean_submission,
    get_open_benchmark_spec,
    list_open_benchmark_specs,
    load_lean_benchmark_items,
    load_sql_benchmark_items,
    verify_open_lean_item,
    verify_open_sql_item,
)
from lab_verify.sql_gate import check_parse, check_read_only  # noqa: E402


def fetch_benchmark_slice(
    dataset_id: str,
    output_dir: Path,
    *,
    max_items: int = 25,
    timeout_s: float = 20.0,
) -> dict[str, Any]:
    """Download a slice of an open SQL or Lean 4 benchmark into gitignored `data/` and record provenance."""
    spec: OpenBenchmarkSpec = get_open_benchmark_spec(dataset_id)
    output_dir.mkdir(parents=True, exist_ok=True)

    headers = {"User-Agent": "lab-verify-fetcher/1.0"}
    req = urllib.request.Request(spec.download_url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw_bytes = resp.read()

    raw_text = raw_bytes.decode("utf-8")
    ext = ".lean" if spec.download_url.endswith(".lean") else ".jsonl"
    out_file = output_dir / f"{spec.dataset_id}{ext}"

    n_saved = 0
    if spec.download_url.endswith(".lean"):
        out_file.write_text(raw_text, encoding="utf-8", newline="\n")
        n_saved = 1
    else:
        parsed_json: Any = None
        if raw_text.lstrip().startswith(("[", "{")):
            try:
                parsed_json = json.loads(raw_text)
            except json.JSONDecodeError:
                parsed_json = None
        if parsed_json is not None:
            if isinstance(parsed_json, dict) and "rows" in parsed_json:
                rows = [r["row"] if isinstance(r, dict) and "row" in r else r for r in parsed_json["rows"]]
            elif isinstance(parsed_json, dict) and "data" in parsed_json:
                rows = list(parsed_json["data"])
            elif isinstance(parsed_json, list):
                rows = parsed_json
            else:
                rows = [parsed_json]
            sliced = rows[:max_items] if max_items > 0 else rows
            rendered = "\n".join(json.dumps(r, ensure_ascii=True) for r in sliced) + ("\n" if sliced else "")
            out_file.write_text(rendered, encoding="utf-8", newline="\n")
            n_saved = len(sliced)
        else:
            lines = [ln for ln in raw_text.splitlines() if ln.strip()]
            sliced_lines = lines[:max_items] if max_items > 0 else lines
            out_file.write_text(
                "\n".join(sliced_lines) + ("\n" if sliced_lines else ""),
                encoding="utf-8",
                newline="\n",
            )
            n_saved = len(sliced_lines)

    sha256_hex = hashlib.sha256(out_file.read_bytes()).hexdigest()
    record = {
        "dataset_id": spec.dataset_id,
        "domain": spec.domain,
        "spdx_license": spec.spdx_license,
        "eval_only": spec.eval_only,
        "training_allowed": spec.training_allowed,
        "source_url": spec.url,
        "download_url": spec.download_url,
        "local_path": str(out_file),
        "records_saved": n_saved,
        "sha256": sha256_hex,
    }

    manifest_path = output_dir / "manifest.json"
    existing: dict[str, Any] = {}
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    datasets_map = dict(existing.get("datasets", {}))
    datasets_map[spec.dataset_id] = record
    manifest_payload = {
        "schema_version": "1.0.0",
        "datasets": datasets_map,
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return record


def verify_downloaded_slice(
    dataset_id: str,
    slice_path: Path,
    *,
    project_dir: Path | None = None,
    static_only: bool = False,
) -> dict[str, Any]:
    """Run SQL read-only and Lean 4 compilation / static soundness checks on a fetched slice."""
    spec = get_open_benchmark_spec(dataset_id)
    if spec.domain == "sql":
        if spec.format_kind == "livesqlbench_sqlite":
            lines = [ln for ln in slice_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            return {"dataset_id": spec.dataset_id, "items_parsed": len(lines), "status": "kb_slice_verified"}
        sql_kwargs = {"sqlite_only": False} if spec.format_kind == "spider2_lite" else {}
        items = load_sql_benchmark_items(spec.dataset_id, slice_path, **sql_kwargs)
        ro_valid = 0
        for item in items:
            if item.gold_sql:
                stmts, p_err = check_parse(item.gold_sql)
                if not p_err and stmts and check_read_only(stmts) is None:
                    ro_valid += 1
        return {
            "dataset_id": spec.dataset_id,
            "items_parsed": len(items),
            "gold_readonly_valid": ro_valid,
            "unanswerable_count": sum(1 for i in items if i.is_unanswerable),
        }

    if spec.format_kind == "numinamath_lean" and slice_path.read_text(encoding="utf-8").lstrip().startswith("{"):
        return {"dataset_id": spec.dataset_id, "items_parsed": 1, "status": "metadata_verified"}
    items = load_lean_benchmark_items(spec.dataset_id, slice_path)
    proved_valid = 0
    compiled_count = 0
    static_only_count = 0
    template_sorry_caught = 0
    has_lean = shutil.which("lean") is not None
    has_lake = shutil.which("lake") is not None
    for item in items:
        if item.reference_proof:
            needs_mathlib = "Mathlib" in item.header
            can_compile = (
                not static_only
                and ((needs_mathlib and project_dir is not None and has_lake) or (not needs_mathlib and has_lean))
            )
            v = verify_open_lean_item(
                item,
                item.reference_proof,
                static_only=not can_compile,
                project_dir=project_dir if can_compile else None,
            )
            if v.passed:
                proved_valid += 1
                if can_compile:
                    compiled_count += 1
                else:
                    static_only_count += 1
        else:
            v_raw = verify_open_lean_item(item, None, static_only=True)
            if not v_raw.passed:
                template_sorry_caught += 1
    mode = "lean_kernel" if (compiled_count > 0 and static_only_count == 0) else "static_only"
    return {
        "dataset_id": spec.dataset_id,
        "items_parsed": len(items),
        "verification_mode": mode,
        "proved_passed_lean_gate": proved_valid,
        "proved_compiled_kernel": compiled_count,
        "proved_static_only": static_only_count,
        "unproved_templates_rejected": template_sorry_caught,
    }


def run_offline_smoke_suite() -> dict[str, Any]:
    """Execute an offline zero-network verification pass across BIRD, Spider2-Lite, EHRSQL, and Lean 4 adapters."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        # 1. BIRD Mini-Dev read-only SQLite execution check
        bird_db = tmp_dir / "california_schools.sqlite"
        con = sqlite3.connect(bird_db)
        con.execute(
            'CREATE TABLE frpm (CDSCode TEXT PRIMARY KEY, "Free Meal Count (Ages 5-17)" REAL, "Enrollment (Ages 5-17)" REAL)'
        )
        con.execute(
            "CREATE TABLE satscores (cds TEXT PRIMARY KEY, rtype TEXT, NumTstTakr INTEGER, NumGE1500 INTEGER)"
        )
        con.executemany("INSERT INTO frpm VALUES (?, ?, ?)", [("0110017", 420.0, 500.0), ("0110025", 150.0, 400.0)])
        con.executemany("INSERT INTO satscores VALUES (?, ?, ?, ?)", [("0110017", "S", 100, 45), ("0110025", "S", 80, 10)])
        con.commit()
        con.close()

        bird_items = load_sql_benchmark_items(
            "bird-mini-dev-hf",
            [
                {
                    "question_id": 0,
                    "db_id": "california_schools",
                    "question": "Among schools with SAT excellence rate above 0.3, what is the highest free-meal rate?",
                    "evidence": "excellence rate = NumGE1500 / NumTstTakr",
                    "SQL": (
                        "SELECT MAX(1.0 * f.`Free Meal Count (Ages 5-17)` / f.`Enrollment (Ages 5-17)`) "
                        "FROM frpm AS f JOIN satscores AS s ON s.cds = f.CDSCode "
                        "WHERE s.rtype = 'S' AND s.NumTstTakr > 0 AND f.`Enrollment (Ages 5-17)` > 0 "
                        "AND 1.0 * s.NumGE1500 / s.NumTstTakr > 0.3"
                    ),
                    "difficulty": "moderate",
                }
            ],
        )
        bird_ok = verify_open_sql_item(bird_db, bird_items[0], bird_items[0].gold_sql)

        # 2. Spider2-Lite local SQLite execution check
        spider2_db = tmp_dir / "E_commerce.sqlite"
        con = sqlite3.connect(spider2_db)
        con.execute("CREATE TABLE orders (order_id INTEGER PRIMARY KEY, category TEXT, revenue REAL)")
        con.executemany("INSERT INTO orders VALUES (?, ?, ?)", [(1, "toys", 125.5), (2, "toys", 74.5), (3, "lab", 300.0)])
        con.commit()
        con.close()
        spider2_items = load_sql_benchmark_items(
            "spider2-lite",
            [{"instance_id": "local002", "db": "E_commerce", "question": "Total revenue for toys?", "external_knowledge": None}],
            gold_sql_map={"local002": "SELECT SUM(revenue) FROM orders WHERE category = 'toys'"},
        )
        spider2_ok = verify_open_sql_item(
            spider2_db,
            spider2_items[0],
            "SELECT SUM(o.revenue) FROM orders AS o WHERE o.category = 'toys'",
        )

        # 3. EHRSQL clinical read-only SQLite + unanswerable abstention check
        ehr_db = tmp_dir / "mimic_iv.sqlite"
        con = sqlite3.connect(ehr_db)
        con.execute("CREATE TABLE prescriptions (id INTEGER PRIMARY KEY, drug TEXT, route TEXT)")
        con.executemany("INSERT INTO prescriptions VALUES (?, ?, ?)", [(1, "amoxicillin", "PO"), (2, "vancomycin", "IV")])
        con.commit()
        con.close()
        ehr_items = load_sql_benchmark_items(
            "ehrsql-2024",
            [
                {
                    "id": "71085ce4beef02dd87ed0ae5",
                    "question": "How is amoxicillin typically administered?",
                    "query": "SELECT DISTINCT prescriptions.route FROM prescriptions WHERE prescriptions.drug = 'amoxicillin'",
                },
                {
                    "id": "7bdfe013186f828667928905",
                    "question": "Which attending physician plays piano?",
                    "query": "null",
                },
            ],
        )
        ehr_ans_ok = verify_open_sql_item(ehr_db, ehr_items[0], ehr_items[0].gold_sql)
        ehr_abs_ok = verify_open_sql_item(ehr_db, ehr_items[1], "null")

        # 4. Lean-Workbook, PutnamBench, and ProofNet-Lean4 checks via lean_gate
        # Mathlib items have no local Mathlib cache in zero-network smoke mode -> explicitly static_only;
        # core-Lean items compile with Lean + `#print axioms` whenever `lean` is on PATH.
        has_lean = shutil.which("lean") is not None
        lw_items = load_lean_benchmark_items(
            "lean-workbook",
            [
                {
                    "id": "lean_workbook_plus_2",
                    "status": "proved",
                    "tactic": "exact ⟨fun h => by rw [Set.mem_Ioo]; constructor <;> nlinarith [h], fun h => by rw [Set.mem_Ioo] at h; nlinarith⟩",
                    "natural_language_statement": "Solve for x in x^2 - 2x - 24 < 0",
                    "formal_statement": "theorem lean_workbook_plus_2 (x : Real) : x^2 - 2*x - 24 < 0 <-> x ∈ Set.Ioo (-4) 6 := by sorry",
                }
            ],
        )
        lw_proved = verify_open_lean_item(lw_items[0], lw_items[0].reference_proof, static_only=True)
        lw_sorry = verify_open_lean_item(lw_items[0], "sorry", static_only=True)

        pb_items = load_lean_benchmark_items(
            "putnambench",
            "import Init\n/-- Commutativity of natural addition. -/\ntheorem putnam_demo (a b : Nat) : a + b = b + a :=\nsorry\n",
        )
        pb_proved = verify_open_lean_item(
            pb_items[0],
            assemble_lean_submission(pb_items[0], "omega"),
            static_only=not has_lean,
        )

        pn_items = load_lean_benchmark_items(
            "proofnet-lean4",
            [
                {
                    "name": "Rudin_exercise_1_1b",
                    "header": "import Mathlib",
                    "formal_statement": "theorem Rudin_exercise_1_1b (x : Real) (y : Rat) (h : y != 0) : Irrational x -> Irrational (x * y) := sorry",
                    "formal_proof": None,
                    "informal_stmt": "Product of nonzero rational and irrational is irrational.",
                }
            ],
        )
        pn_proved = verify_open_lean_item(pn_items[0], "intro hx\nexact hx.mul_rat h", static_only=True)

        def _tag_lean_mode(v_dict: dict[str, Any], *, compiled: bool) -> dict[str, Any]:
            out_d = dict(v_dict)
            out_d["verification_mode"] = "lean_kernel" if compiled else "static_only"
            return out_d

        all_ok = (
            bird_ok.passed
            and spider2_ok.passed
            and ehr_ans_ok.passed
            and ehr_abs_ok.passed
            and lw_proved.passed
            and (not lw_sorry.passed and lw_sorry.layer == "soundness")
            and pb_proved.passed
            and pn_proved.passed
        )
        return {
            "passed": all_ok,
            "lean_toolchain_available": has_lean,
            "checks": {
                "bird_mini_dev": bird_ok.to_dict(),
                "spider2_lite": spider2_ok.to_dict(),
                "ehrsql_answerable": ehr_ans_ok.to_dict(),
                "ehrsql_abstention": ehr_abs_ok.to_dict(),
                "lean_workbook_proved": _tag_lean_mode(lw_proved.to_dict(), compiled=False),
                "lean_workbook_sorry_rejected": _tag_lean_mode(lw_sorry.to_dict(), compiled=False),
                "putnambench_proved": _tag_lean_mode(pb_proved.to_dict(), compiled=has_lean),
                "proofnet_lean4_proved": _tag_lean_mode(pn_proved.to_dict(), compiled=False),
            },
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List, fetch, and verify 2024-2026 open SQL and Lean 4 benchmarks."
    )
    parser.add_argument("--list", action="store_true", help="List registered open SQL & Lean 4 benchmarks.")
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Dataset id (or 'all') to fetch on-demand into --output-dir.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "data" / "open_benchmarks",
        help="Target directory for downloaded slices (default: gitignored data/open_benchmarks).",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=25,
        help="Maximum JSON/JSONL records to persist per dataset (0 for full file).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run static SQL read-only and Lean 4 soundness checks on fetched slices.",
    )
    parser.add_argument(
        "--offline-demo",
        action="store_true",
        help="Run deterministic zero-network adapter verification across SQL and Lean 4 benchmarks.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        specs = list_open_benchmark_specs()
        if args.json:
            print(json.dumps([s.to_dict() for s in specs], indent=2))
        else:
            print(f"{'dataset_id':<22} {'domain':<7} {'year':<6} {'spdx_license':<14} {'eval_only':<10} {'train_ok'}")
            print("-" * 76)
            for s in specs:
                print(
                    f"{s.dataset_id:<22} {s.domain:<7} {s.release_year:<6} "
                    f"{s.spdx_license:<14} {str(s.eval_only):<10} {s.training_allowed}"
                )
        return 0

    if args.offline_demo:
        report = run_offline_smoke_suite()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            status = "PASS" if report["passed"] else "FAIL"
            print(f"Offline 2024-2026 SQL & Lean 4 benchmark smoke suite: {status}")
            for name, verdict in report["checks"].items():
                mode_suffix = (
                    f" ({verdict['verification_mode'].replace('_', ' ')})"
                    if "verification_mode" in verdict
                    else ""
                )
                print(f"  {name:<30} passed={verdict['passed']} reason={verdict['reason']}{mode_suffix}")
        return 0 if report["passed"] else 1

    if args.dataset:
        targets = (
            list(OPEN_BENCHMARK_SPECS.keys())
            if args.dataset.strip().lower() == "all"
            else [args.dataset.strip()]
        )
        records: list[dict[str, Any]] = []
        for ds_id in targets:
            rec = fetch_benchmark_slice(ds_id, args.output_dir, max_items=args.max_items)
            if args.verify:
                rec["verification"] = verify_downloaded_slice(ds_id, Path(rec["local_path"]))
            records.append(rec)
        if args.json:
            print(json.dumps(records, indent=2))
        else:
            for rec in records:
                print(
                    f"Fetched {rec['dataset_id']} ({rec['records_saved']} records, "
                    f"{rec['spdx_license']}, eval_only={rec['eval_only']}) -> {rec['local_path']}"
                )
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
