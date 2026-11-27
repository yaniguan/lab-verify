"""Tests for 2024-2026 open-source Text-to-SQL and Lean 4 benchmark catalog and gate adapters."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
from unittest.mock import patch

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify import (  # noqa: E402
    OPEN_BENCHMARK_SPECS,
    assemble_lean_submission,
    canonicalize_lean_statement,
    evaluate_open_lean_batch,
    evaluate_open_sql_batch,
    get_open_benchmark_spec,
    list_open_benchmark_specs,
    load_catalog_datasets,
    load_lean_benchmark_items,
    load_sql_benchmark_items,
    non_empty,
    to_candidates_benchmark,
    verify_open_lean_item,
    verify_open_sql_item,
)


def _load_script_module(module_name: str, rel_path: str):
    script_path = REPO_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


check_catalog_mod = _load_script_module("check_catalog_mod", "scripts/check_catalog.py")
fetch_benchmarks_mod = _load_script_module("fetch_benchmarks_mod", "scripts/fetch_open_benchmarks.py")


# ---------------------------------------------------------------------------
# 1. Catalog Validation, SPDX / Eval-Only Flags, and Pure-English Hygiene
# ---------------------------------------------------------------------------


def test_catalog_validates_cleanly_and_covers_2024_2026_benchmarks():
    errors = check_catalog_mod.validate_catalog(REPO_ROOT, online=False)
    assert errors == [], f"catalog validation failed: {errors}"

    datasets = load_catalog_datasets(REPO_ROOT / "catalog" / "sources.json")
    by_id = {d["id"]: d for d in datasets}

    expected_recent = {
        "spider2",
        "spider2-lite",
        "bird-mini-dev-hf",
        "ehrsql-2024",
        "bird-critic-sqlite",
        "livesqlbench-sqlite",
        "lean-workbook",
        "putnambench",
        "proofnet-lean4",
        "minif2f-lean4",
        "formalmath-lite",
        "numinamath-lean",
    }
    assert expected_recent.issubset(by_id.keys())

    for ds_id, spec in OPEN_BENCHMARK_SPECS.items():
        assert ds_id in by_id
        cat = by_id[ds_id]
        assert cat["domain"] == spec.domain
        assert cat["spdx_license"] == spec.spdx_license
        assert cat["url"] == spec.url
        assert cat["eval_only"] is spec.eval_only
        assert cat["training_allowed"] is spec.training_allowed
        assert cat["release_year"] == spec.release_year
        if cat["eval_only"]:
            assert cat["training_allowed"] is False


def test_catalog_validator_rejects_contamination_and_license_violations(tmp_path: Path):
    (tmp_path / "catalog").mkdir()
    (tmp_path / "docs").mkdir()
    bad_catalog = {
        "schema_version": "1.1.0",
        "updated_at": "2026-11-25",
        "datasets": [
            {
                "id": "bad-eval-train",
                "name": "Contaminated Eval Set",
                "domain": "sql",
                "release_year": 2025,
                "url": "https://example.org/bad-eval",
                "spdx_license": "MIT",
                "license_status": "verified_open",
                "commercial_use_ok": True,
                "redistribution_ok": True,
                "share_alike": False,
                "eval_only": True,
                "training_allowed": True,
            },
            {
                "id": "bad-cc-by",
                "name": "Wrong ShareAlike Flag",
                "domain": "sql",
                "release_year": 2024,
                "url": "https://example.org/bad-cc",
                "spdx_license": "CC-BY-4.0",
                "license_status": "verified_open",
                "commercial_use_ok": True,
                "redistribution_ok": True,
                "share_alike": True,
                "eval_only": False,
                "training_allowed": True,
            },
        ],
        "repositories": [],
    }
    (tmp_path / "catalog" / "sources.json").write_text(json.dumps(bad_catalog), encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Links: https://example.org/bad-eval and https://example.org/bad-cc\n",
        encoding="utf-8",
    )

    errs = check_catalog_mod.validate_catalog(tmp_path, online=False)
    assert any("eval_only=true dataset must set training_allowed=false" in e for e in errs)
    assert any("CC-BY-4.0 entry must set share_alike=false" in e for e in errs)


def test_open_benchmark_registry_filters_and_aliases():
    sql_specs = list_open_benchmark_specs(domain="sql")
    lean_specs = list_open_benchmark_specs(domain="lean4")
    train_specs = list_open_benchmark_specs(training_only=True)

    assert len(sql_specs) >= 5
    assert len(lean_specs) >= 6
    assert {s.dataset_id for s in train_specs} == {"ehrsql-2024", "lean-workbook", "numinamath-lean"}

    assert get_open_benchmark_spec("bird_mini_dev").dataset_id == "bird-mini-dev-hf"
    assert get_open_benchmark_spec("spider2_lite").dataset_id == "spider2-lite"
    assert get_open_benchmark_spec("ehrsql").dataset_id == "ehrsql-2024"
    assert get_open_benchmark_spec("leanworkbook").dataset_id == "lean-workbook"
    assert get_open_benchmark_spec("putnam").dataset_id == "putnambench"
    assert get_open_benchmark_spec("proofnet").dataset_id == "proofnet-lean4"

    with pytest.raises(KeyError, match="unknown open benchmark dataset"):
        get_open_benchmark_spec("nonexistent_benchmark_2099")


def test_repository_maintains_zero_cjk_characters():
    cjk_re = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
    checked = 0
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT).parts
        if any(p in {".git", "__pycache__", ".pytest_cache", "data", ".lake"} for p in rel):
            continue
        if path.suffix.lower() in {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".lean", ".txt"}:
            text = path.read_text(encoding="utf-8")
            match = cjk_re.search(text)
            assert match is None, f"found CJK character {match.group(0)!r} in {path}"
            checked += 1
    assert checked >= 20


# ---------------------------------------------------------------------------
# 2. SQL Benchmark Adapters (`BIRD Mini-Dev`, `Spider 2.0-Lite`, `EHRSQL`, `BIRD-CRITIC`)
# ---------------------------------------------------------------------------


def test_bird_mini_dev_sqlite_adapter_and_gate_layers(tmp_path: Path):
    db_path = tmp_path / "california_schools.sqlite"
    con = sqlite3.connect(db_path)
    con.execute(
        'CREATE TABLE frpm (CDSCode TEXT PRIMARY KEY, "Free Meal Count (Ages 5-17)" REAL, "Enrollment (Ages 5-17)" REAL)'
    )
    con.execute(
        "CREATE TABLE satscores (cds TEXT PRIMARY KEY, rtype TEXT, NumTstTakr INTEGER, NumGE1500 INTEGER)"
    )
    con.executemany(
        "INSERT INTO frpm VALUES (?, ?, ?)",
        [("0110017", 420.0, 500.0), ("0110025", 390.0, 400.0), ("0110033", 100.0, 400.0)],
    )
    con.executemany(
        "INSERT INTO satscores VALUES (?, ?, ?, ?)",
        [("0110017", "S", 100, 45), ("0110025", "S", 100, 15), ("0110033", "S", 80, 40)],
    )
    con.commit()
    con.close()

    jsonl_payload = json.dumps(
        {
            "question_id": 0,
            "db_id": "california_schools",
            "question": "Among schools with a school-level SAT excellence rate above 0.3, what is the highest ages-5-17 free-meal eligibility rate?",
            "evidence": "SAT excellence rate = NumGE1500 / NumTstTakr",
            "SQL": (
                "SELECT MAX(1.0 * f.`Free Meal Count (Ages 5-17)` / f.`Enrollment (Ages 5-17)`) "
                "FROM frpm AS f JOIN satscores AS s ON s.cds = f.CDSCode "
                "WHERE s.rtype = 'S' AND s.NumTstTakr > 0 AND f.`Enrollment (Ages 5-17)` > 0 "
                "AND 1.0 * s.NumGE1500 / s.NumTstTakr > 0.3"
            ),
            "difficulty": "moderate",
        }
    )
    items = load_sql_benchmark_items("bird_mini_dev", jsonl_payload)
    assert len(items) == 1
    item = items[0]

    # Equivalent CTE candidate passes all 4 layers
    cand_ok = (
        "WITH eligible AS ("
        "  SELECT f.`Free Meal Count (Ages 5-17)` * 1.0 / f.`Enrollment (Ages 5-17)` AS rate "
        "  FROM frpm f INNER JOIN satscores s ON f.CDSCode = s.cds "
        "  WHERE s.rtype = 'S' AND s.NumTstTakr > 0 AND f.`Enrollment (Ages 5-17)` > 0 "
        "  AND (1.0 * s.NumGE1500 / s.NumTstTakr) > 0.3"
        ") SELECT MAX(rate) FROM eligible"
    )
    v_ok = verify_open_sql_item(db_path, item, cand_ok)
    assert v_ok.passed is True

    # Missing excellence-rate filter picks school 0110025 (0.975 vs gold 0.84) -> Layer 4 rejection
    cand_missing_filter = (
        "SELECT MAX(1.0 * f.`Free Meal Count (Ages 5-17)` / f.`Enrollment (Ages 5-17)`) "
        "FROM frpm AS f JOIN satscores AS s ON s.cds = f.CDSCode WHERE s.rtype = 'S'"
    )
    v_sem = verify_open_sql_item(db_path, item, cand_missing_filter)
    assert v_sem.passed is False and v_sem.layer == "execution"

    # Destructive write attempt stopped at Layer 2 (`read-only`)
    v_ro = verify_open_sql_item(db_path, item, "DELETE FROM frpm WHERE CDSCode = '0110017'")
    assert v_ro.passed is False and v_ro.layer == "read-only"


def test_spider2_lite_sqlite_filtering_gold_dir_and_schema_export(tmp_path: Path):
    gold_dir = tmp_path / "gold_sql"
    gold_dir.mkdir()
    (gold_dir / "local002.sql").write_text(
        "SELECT category, ROUND(SUM(amount), 2) AS total_sales FROM sales GROUP BY category ORDER BY total_sales DESC",
        encoding="utf-8",
    )

    spider2_rows = [
        {
            "instance_id": "bq011",
            "db": "ga4",
            "question": "BigQuery pseudo users question",
            "external_knowledge": "ga4_events.md",
        },
        {
            "instance_id": "local002",
            "db": "E_commerce",
            "question": "Compute total sales per category sorted from highest to lowest.",
            "external_knowledge": "sales_definitions.md",
        },
    ]

    sqlite_items = load_sql_benchmark_items("spider2-lite", spider2_rows, gold_sql_dir=gold_dir, sqlite_only=True)
    assert len(sqlite_items) == 1
    assert sqlite_items[0].item_id == "local002"
    assert sqlite_items[0].dialect == "sqlite"
    assert sqlite_items[0].gold_sql is not None

    db_path = tmp_path / "E_commerce.sqlite"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE sales (id INTEGER PRIMARY KEY, category TEXT, amount REAL)")
    con.executemany(
        "INSERT INTO sales VALUES (?, ?, ?)",
        [(1, "reagents", 180.25), (2, "reagents", 19.75), (3, "plates", 95.5)],
    )
    con.commit()
    con.close()

    verdict = verify_open_sql_item(
        db_path,
        sqlite_items[0],
        "SELECT s.category, ROUND(SUM(s.amount), 2) AS total_sales FROM sales s GROUP BY s.category ORDER BY total_sales DESC",
    )
    assert verdict.passed is True

    # Verify export to schema/candidates.schema.json
    cand_bench = to_candidates_benchmark(
        sqlite_items,
        {
            "local002": [
                {
                    "label": "correct",
                    "sql": "SELECT category, ROUND(SUM(amount), 2) AS total_sales FROM sales GROUP BY category ORDER BY total_sales DESC",
                }
            ]
        },
    )
    schema = json.loads((REPO_ROOT / "schema" / "candidates.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(cand_bench, schema)


def test_ehrsql_clinical_readonly_execution_and_unanswerable_abstention(tmp_path: Path):
    db_path = tmp_path / "mimic_iv.sqlite"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE prescriptions (id INTEGER PRIMARY KEY, subject_id INTEGER, drug TEXT, route TEXT)")
    con.executemany(
        "INSERT INTO prescriptions VALUES (?, ?, ?, ?)",
        [
            (1, 1001, "amoxicillin", "PO"),
            (2, 1002, "amoxicillin", "PO"),
            (3, 1003, "potassium chl 40 meq / 1000 ml d5ns", "IV"),
        ],
    )
    con.commit()
    con.close()

    data_json = {
        "version": "valid_v1.1.2",
        "data": [
            {"id": "71085ce4beef02dd87ed0ae5", "question": "How is amoxicillin typically administered?"},
            {"id": "7bdfe013186f828667928905", "question": "What is the patient's favorite hobby outside the hospital?"},
        ],
    }
    label_json = {
        "71085ce4beef02dd87ed0ae5": "SELECT DISTINCT prescriptions.route FROM prescriptions WHERE prescriptions.drug = 'amoxicillin'",
        "7bdfe013186f828667928905": "null",
    }

    items = load_sql_benchmark_items("ehrsql-2024", data_json, labels=label_json)
    assert len(items) == 2
    ans_item, unans_item = items[0], items[1]
    assert ans_item.is_unanswerable is False
    assert unans_item.is_unanswerable is True and unans_item.gold_sql is None

    # Answerable item passes on matching read-only SQL, fails if model abstains
    assert verify_open_sql_item(db_path, ans_item, "SELECT DISTINCT route FROM prescriptions WHERE drug = 'amoxicillin'").passed
    v_bad_abstain = verify_open_sql_item(db_path, ans_item, "null")
    assert not v_bad_abstain.passed and v_bad_abstain.layer == "parse"

    # Unanswerable item passes on abstention, rejects hallucinated SELECT, and stops DROP at Layer 2
    assert verify_open_sql_item(db_path, unans_item, "null").passed
    assert verify_open_sql_item(db_path, unans_item, None).passed

    v_halluc = verify_open_sql_item(db_path, unans_item, "SELECT route FROM prescriptions LIMIT 1")
    assert not v_halluc.passed and v_halluc.layer == "execution"
    assert "unanswerable" in v_halluc.reason

    v_drop = verify_open_sql_item(db_path, unans_item, "DROP TABLE prescriptions")
    assert not v_drop.passed and v_drop.layer == "read-only"


def test_bird_critic_sqlite_and_batch_sql_evaluator(tmp_path: Path):
    db_path = tmp_path / "codebase_community.sqlite"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, CreationDate TEXT)")
    con.executemany(
        "INSERT INTO comments VALUES (?, ?)",
        [(1, "2025-04-01 14:35:20"), (2, "2025-04-01 09:05:00")],
    )
    con.commit()
    con.close()

    critic_items = load_sql_benchmark_items(
        "bird-critic-sqlite",
        [
            {
                "dialect": "SQLite",
                "version": "3",
                "instance_id": "SQLite_0",
                "db_id": "codebase_community",
                "query": "Extract HH:MM time portion from CreationDate in comments.",
                "issue_sql": ["SELECT CAST(CreationDate AS TIME) FROM comments"],
                "category": "Query",
            }
        ],
        gold_sql_map={"SQLite_0": "SELECT strftime('%H:%M', CreationDate) FROM comments"},
    )
    assert critic_items[0].issue_sql == ("SELECT CAST(CreationDate AS TIME) FROM comments",)

    # Issue SQL (`CAST(... AS TIME)` returns integer year 2025 in SQLite!) fails Layer 4 against gold `strftime`
    v_buggy = verify_open_sql_item(db_path, critic_items[0], critic_items[0].issue_sql[0])
    assert not v_buggy.passed and v_buggy.layer == "execution"

    # Repaired query passes; batch evaluator tracks database map cleanly
    summary = evaluate_open_sql_batch(
        {"codebase_community": db_path},
        critic_items,
        {"SQLite_0": "SELECT substr(CreationDate, 12, 5) FROM comments"},
    )
    assert summary == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "stopped_by_layer": {"parse": 0, "read-only": 0, "schema": 0, "execution": 0},
        "results": [
            {
                "dataset_id": "bird-critic-sqlite",
                "item_id": "SQLite_0",
                "db_id": "codebase_community",
                "is_unanswerable": False,
                "passed": True,
                "layer": None,
                "reason": "match",
            }
        ],
    }

    # Property-only verification when no gold SQL is attached
    no_gold_item = load_sql_benchmark_items(
        "bird-critic-sqlite",
        [{"instance_id": "SQLite_1", "db_id": "codebase_community", "query": "Non-empty comments", "issue_sql": []}],
    )[0]
    assert verify_open_sql_item(db_path, no_gold_item, "SELECT id FROM comments", properties=[non_empty()]).passed


# ---------------------------------------------------------------------------
# 3. Lean 4 Benchmark Adapters (`Lean-Workbook`, `PutnamBench`, `ProofNet`, `MiniF2F`, `FormalMATH`, `NuminaMath`)
# ---------------------------------------------------------------------------


def test_lean_workbook_adapter_enforces_zero_sorry_axiom_and_signature_integrity():
    hf_rows_wrapper = {
        "rows": [
            {
                "row": {
                    "id": "lean_workbook_plus_2",
                    "status": "proved",
                    "tactic": "exact ⟨fun h => by rw [Set.mem_Ioo]; constructor <;> nlinarith [h], fun h => by rw [Set.mem_Ioo] at h; nlinarith⟩",
                    "natural_language_statement": "Solve for x in x^2 - 2x - 24 < 0",
                    "formal_statement": "theorem lean_workbook_plus_2 (x : Real) : x^2 - 2*x - 24 < 0 <-> x ∈ Set.Ioo (-4) 6   :=  by sorry",
                }
            }
        ]
    }
    items = load_lean_benchmark_items("lean-workbook", hf_rows_wrapper)
    assert len(items) == 1
    item = items[0]
    assert canonicalize_lean_statement(item.formal_statement) == (
        "theorem lean_workbook_plus_2 (x : Real) : x^2 - 2*x - 24 < 0 <-> x ∈ Set.Ioo (-4) 6"
    )

    # Verified tactic passes static `lean_gate` soundness checks when static_only=True is explicit
    v_ok = verify_open_lean_item(item, item.reference_proof, static_only=True)
    assert v_ok.passed is True

    # Raw `sorry` proof fails at `soundness`
    v_sorry = verify_open_lean_item(item, "sorry", static_only=True)
    assert not v_sorry.passed and v_sorry.layer == "soundness" and "sorry" in v_sorry.reason

    # Custom `axiom` smuggling fails at `soundness`
    axiom_bypass = (
        "import Mathlib\n"
        "axiom magic_ineq (x : Real) : x^2 - 2*x - 24 < 0 <-> x ∈ Set.Ioo (-4) 6\n"
        "theorem lean_workbook_plus_2 (x : Real) : x^2 - 2*x - 24 < 0 <-> x ∈ Set.Ioo (-4) 6 := magic_ineq x\n"
    )
    v_axiom = verify_open_lean_item(item, axiom_bypass, static_only=True)
    assert not v_axiom.passed and v_axiom.layer == "soundness" and "axiom" in v_axiom.reason

    # `#exit` directive bypass fails at `soundness`
    exit_bypass = assemble_lean_submission(item, "nlinarith") + "\n#exit\n"
    v_exit = verify_open_lean_item(item, exit_bypass, static_only=True)
    assert not v_exit.passed and v_exit.layer == "soundness" and "#exit" in v_exit.reason

    # Goal-swapping / altering the benchmark theorem statement fails at `schema`
    tampered_stmt = "import Mathlib\ntheorem lean_workbook_plus_2 (x : Real) : x = x := rfl\n"
    v_tamper = verify_open_lean_item(item, tampered_stmt, static_only=True)
    assert not v_tamper.passed and v_tamper.layer == "schema"
    assert "signature" in v_tamper.reason


def test_putnambench_proofnet_minif2f_formalmath_and_numinamath_lean4_adapters(tmp_path: Path):
    putnam_file = tmp_path / "putnam_1962_a1.lean"
    putnam_file.write_text(
        "import Mathlib\n\nopen MeasureTheory\n\n"
        "/--\nGiven five points in a plane with no three collinear, four form a convex quadrilateral.\n-/\n"
        "theorem putnam_1962_a1\n"
        "(S : Set (Real × Real))\n"
        "(hS : S.ncard = 5)\n"
        ": ∃ T ⊆ S, T.ncard = 4 :=\n"
        "sorry\n",
        encoding="utf-8",
    )
    pb_items = load_lean_benchmark_items("putnambench", tmp_path)
    assert len(pb_items) == 1
    assert pb_items[0].item_id == "putnam_1962_a1"
    assert "convex quadrilateral" in pb_items[0].informal_statement
    assert not verify_open_lean_item(pb_items[0], None, static_only=True).passed
    assert verify_open_lean_item(
        pb_items[0],
        "obtain ⟨x, hx⟩ := hS.nonempty\nexact ⟨S.erase x, Set.erase_subset x S, by simpa using hS⟩",
        static_only=True,
    ).passed

    pn_items = load_lean_benchmark_items(
        "proofnet-lean4",
        [
            {
                "name": "Shakarchi_exercise_1_13a",
                "header": "import Mathlib\nopen Complex",
                "formal_statement": "theorem Shakarchi_exercise_1_13a (a b : Complex) (h : a = b) : f a = f b := sorry",
                "formal_proof": None,
                "informal_stmt": "Holomorphic function with constant real part is constant.",
            }
        ],
    )
    mf_items = load_lean_benchmark_items(
        "minif2f-lean4",
        [
            {
                "id": "mathd_algebra_478",
                "split": "test",
                "header": "import Mathlib",
                "formal_statement": "theorem mathd_algebra_478 (b h v : Real) (h1 : v = 1 / 3 * (b * h)) (h2 : b = 30) (h3 : h = 13 / 2) : v = 65 := sorry",
                "informal_stmt": "Volume of a cone with base 30 and height 6.5 is 65.",
            }
        ],
    )
    fm_items = load_lean_benchmark_items(
        "formalmath-lite",
        [
            {
                "theorem_names": "algebra_569189",
                "autoformalization": "import Mathlib\nopen Real\ntheorem algebra_569189 (x : Real) : x^2 + 1 > 0 := ",
                "domain": "Mathematics -> Algebra",
            }
        ],
    )
    nm_items = load_lean_benchmark_items(
        "numinamath-lean",
        [
            {
                "uuid": "nm-001",
                "problem": "Show that (a + b)^2 >= 4ab for real a, b.",
                "formal_statement": "import Mathlib\ntheorem nm_sq_ineq (a b : Real) : (a + b)^2 >= 4 * a * b := by sorry",
                "formal_proof": "nlinarith [sq_nonneg (a - b)]",
                "source": "olympiad",
            }
        ],
    )

    batch_report = evaluate_open_lean_batch(
        [pn_items[0], mf_items[0], fm_items[0], nm_items[0]],
        {
            "Shakarchi_exercise_1_13a": "rw [h]",
            "mathd_algebra_478": "linarith",
            "algebra_569189": "positivity",
            "nm-001": nm_items[0].reference_proof,
        },
        static_only=True,
    )
    assert batch_report["total"] == 4
    assert batch_report["passed"] == 4
    assert batch_report["failed"] == 0
    assert all(r["reason"] == "static_only" for r in batch_report["results"])


# ---------------------------------------------------------------------------
# 4. Fetcher CLI (`scripts/fetch_open_benchmarks.py`) Offline & Mocked Download
# ---------------------------------------------------------------------------


def test_fetch_open_benchmarks_offline_smoke_and_mocked_fetch(tmp_path: Path, capsys):
    rc_list = fetch_benchmarks_mod.main(["--list", "--json"])
    assert rc_list == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == len(OPEN_BENCHMARK_SPECS)

    rc_demo = fetch_benchmarks_mod.main(["--offline-demo", "--json"])
    assert rc_demo == 0
    demo_report = json.loads(capsys.readouterr().out)
    assert demo_report["passed"] is True

    fake_bird_jsonl = (
        "\n".join(
            [
                json.dumps(
                    {
                        "question_id": 7,
                        "db_id": "california_schools",
                        "question": "Count schools.",
                        "evidence": "",
                        "SQL": "SELECT COUNT(*) FROM schools",
                        "difficulty": "simple",
                    }
                ),
                json.dumps(
                    {
                        "question_id": 8,
                        "db_id": "california_schools",
                        "question": "List school names.",
                        "evidence": "",
                        "SQL": "SELECT School FROM schools",
                        "difficulty": "simple",
                    }
                ),
            ]
        )
        + "\n"
    ).encode("utf-8")

    class _FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    with patch("urllib.request.urlopen", return_value=_FakeResp(fake_bird_jsonl)):
        rc_fetch = fetch_benchmarks_mod.main(
            ["--dataset", "bird-mini-dev-hf", "--output-dir", str(tmp_path), "--max-items", "5", "--verify", "--json"]
        )
    assert rc_fetch == 0
    fetched = json.loads(capsys.readouterr().out)
    assert fetched[0]["dataset_id"] == "bird-mini-dev-hf"
    assert fetched[0]["records_saved"] == 2
    assert fetched[0]["verification"]["gold_readonly_valid"] == 2
    assert (tmp_path / "manifest.json").exists()
    assert demo_report["checks"]["lean_workbook_proved"]["verification_mode"] == "static_only"
    assert demo_report["checks"]["proofnet_lean4_proved"]["verification_mode"] == "static_only"


# ---------------------------------------------------------------------------
# 5. Issue #32 & Issue #33 Live Lean 4 Compilation, Fail-Closed CLI, & EHRSQL Real Report
# ---------------------------------------------------------------------------


def test_issue_32_missing_lean_fails_closed_unless_static_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from lab_verify.cli import main as cli_main
    from lab_verify.lean_gate import verify_lean

    wrong_file = tmp_path / "wrong_rfl.lean"
    wrong_file.write_text("theorem bad_comm (a b : Nat) : a + b = b + a := rfl\n", encoding="utf-8")

    monkeypatch.setenv("PATH", "")
    verdict = verify_lean(wrong_file)
    assert verdict.passed is False
    assert verdict.layer == "execution"

    rc = cli_main(["--lean", str(wrong_file)])
    assert rc == 1

    # Explicit static_only=True returns "static_only" reason instead of claiming kernel verification
    v_static = verify_lean(wrong_file, static_only=True)
    assert v_static.passed is True
    assert v_static.reason == "static_only"


def test_issue_32_live_lean4_compilation_axioms_and_relative_cli_path(tmp_path: Path):
    import os
    import shutil
    from lab_verify.cli import main as cli_main
    from lab_verify.lean_gate import verify_lean
    from lab_verify.open_benchmarks import OpenLeanBenchmarkItem

    lean_bin = shutil.which("lean")
    if os.environ.get("REQUIRE_LIVE_LEAN") == "1":
        assert lean_bin is not None, "REQUIRE_LIVE_LEAN=1 set in CI, so lean must be installed on PATH"
    if lean_bin is None:
        pytest.skip("Lean 4 compiler not on PATH in Python-only test environment")

    comm_item = OpenLeanBenchmarkItem(
        dataset_id="lean-workbook",
        item_id="core_nat_add_comm",
        header="",
        formal_statement="theorem core_nat_add_comm (a b : Nat) : a + b = b + a := by sorry",
    )

    # 1. Unproved `rfl` on `a + b = b + a` MUST FAIL live compilation
    v_rfl = verify_open_lean_item(comm_item, "rfl")
    assert v_rfl.passed is False
    assert v_rfl.layer == "execution"

    # 2. Custom tactic calling `mkSorry` (`sorryAx` without spelling `sorry` or `admit`) MUST FAIL axiom check
    sneaky_admit = (
        "import Lean.Elab.Tactic.Basic\n"
        "open Lean Meta Elab Tactic in\n"
        'elab "trust_me" : tactic => do\n'
        "  let g <- getMainGoal\n"
        "  let t <- g.getType\n"
        "  let e <- mkSorry t false\n"
        "  g.assign e\n"
        "theorem core_nat_add_comm (a b : Nat) : a + b = b + a := by trust_me\n"
    )
    assert verify_lean(sneaky_admit, static_only=True).passed is True
    v_admit = verify_open_lean_item(comm_item, sneaky_admit)
    assert v_admit.passed is False
    assert "sorryAx" in " ".join([v_admit.reason, *v_admit.diagnostics])

    # 3. Custom `axiom` smuggling MUST FAIL
    v_ax = verify_lean(
        "axiom fake_comm (a b : Nat) : a + b = b + a\n"
        "theorem t (a b : Nat) : a + b = b + a := fake_comm a b\n"
    )
    assert v_ax.passed is False

    # 4. Valid `omega` proof PASSES both `verify_open_lean_item` and `verify_lean(..., run_leanchecker=True)`
    v_omega = verify_open_lean_item(comm_item, "omega")
    assert v_omega.passed is True
    v_checker = verify_lean(
        "theorem add_comm_ok (a b : Nat) : a + b = b + a := by omega\n"
        "theorem em_ok (p : Prop) : p ∨ ¬ p := Classical.em p\n",
        run_leanchecker=(shutil.which("leanchecker") is not None),
    )
    assert v_checker.passed is True

    # 5. `lab-verify --lean lean/LabVerifyLean.lean` works with relative path from repo root
    old_cwd = Path.cwd()
    try:
        os.chdir(REPO_ROOT)
        assert cli_main(["--lean", "lean/LabVerifyLean.lean"]) == 0
    finally:
        os.chdir(old_cwd)


def test_issue_33_committed_ehrsql_2024_real_results_and_readme_sync():
    report_path = REPO_ROOT / "results" / "ehrsql_2024_real.json"
    assert report_path.exists(), "results/ehrsql_2024_real.json must be committed"
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["licenses"]["database"]["spdx_license"] == "ODbL-1.0"
    assert report["licenses"]["questions_and_sql"]["spdx_license"] == "CC-BY-4.0"
    assert report["database_summary"]["num_tables"] == 17
    assert report["database_summary"]["total_rows"] > 300_000

    ehr = report["ehrsql_2024_valid"]
    assert ehr["total_items"] == 1163
    assert ehr["answerable_total"] == 931
    assert ehr["gold_vs_gold_passed"] == 931
    assert ehr["unanswerable_total"] == 232
    assert ehr["abstention_passed"] == 232
    assert ehr["gold_vs_gold_failed"] == 0
    assert ehr["abstention_failed"] == 0
    assert ehr["failures"] == []

    bird = report["bird_mini_dev_sqlite"]
    assert bird["total_items"] == 500
    assert bird["strict_join_and_cte_passed"] == 500

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "931/931" in readme
    assert "232/232" in readme
    assert "scripts/run_ehrsql_real.py" in readme
