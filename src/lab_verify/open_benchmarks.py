"""2024-2026 open-source Text-to-SQL and Lean 4 benchmark adapters for `sql_gate` and `lean_gate`."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable, Mapping, Sequence

from .lean_gate import strip_lean_comments, verify_lean
from .sql_gate import (
    LAYERS,
    QueryResult,
    check_parse,
    check_read_only,
    introspect_sqlite_schema,
    lock_connection_readonly,
    open_readonly_db,
    validate_candidates_schema,
    verify_sql,
)
from .verdict import VerifyVerdict

ABSTENTION_TOKENS: frozenset[str] = frozenset(
    {"", "null", "none", "abstain", "unanswerable", "not_answerable"}
)

_TRAILING_SORRY_RE = re.compile(r":=\s*(?:by\s+)?(?:sorry\s*)?$", flags=re.DOTALL)
_PREAMBLE_LINE_RE = re.compile(
    r"^\s*(?:import\b|open\b|set_option\b|universe\b|variable\b|noncomputable\s+(?:section|theory)\b|section\b|namespace\b)"
)
_THEOREM_DECL_RE = re.compile(r"\b(?:theorem|lemma)\s+([^\s({:\[]+)")
_FORBIDDEN_BENCHMARK_DIRECTIVES: tuple[tuple[str, str], ...] = (
    (r"#exit\b", "early file termination directive '#exit' is forbidden"),
    (r"\bopaque\b", "uninterpreted 'opaque' declaration is forbidden in benchmark proofs"),
)


@dataclass(frozen=True)
class OpenBenchmarkSpec:
    """Verified metadata and fetch configuration for an open SQL or Lean 4 benchmark."""

    dataset_id: str
    name: str
    domain: str
    release_year: int
    url: str
    download_url: str
    spdx_license: str
    commercial_use_ok: bool
    redistribution_ok: bool
    share_alike: bool
    eval_only: bool
    training_allowed: bool
    format_kind: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "name": self.name,
            "domain": self.domain,
            "release_year": self.release_year,
            "url": self.url,
            "download_url": self.download_url,
            "spdx_license": self.spdx_license,
            "commercial_use_ok": self.commercial_use_ok,
            "redistribution_ok": self.redistribution_ok,
            "share_alike": self.share_alike,
            "eval_only": self.eval_only,
            "training_allowed": self.training_allowed,
            "format_kind": self.format_kind,
            "description": self.description,
        }


OPEN_BENCHMARK_SPECS: dict[str, OpenBenchmarkSpec] = {
    "spider2-lite": OpenBenchmarkSpec(
        dataset_id="spider2-lite",
        name="Spider 2.0-Lite",
        domain="sql",
        release_year=2025,
        url="https://huggingface.co/datasets/xlangai/spider2-lite",
        download_url="https://huggingface.co/datasets/xlangai/spider2-lite/resolve/main/spider2-lite.jsonl",
        spdx_license="MIT",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=True,
        training_allowed=False,
        format_kind="spider2_lite",
        description="ICLR 2025 enterprise and local SQLite ('local*') Text-to-SQL benchmark.",
    ),
    "bird-mini-dev-hf": OpenBenchmarkSpec(
        dataset_id="bird-mini-dev-hf",
        name="BIRD Mini-Dev",
        domain="sql",
        release_year=2024,
        url="https://huggingface.co/datasets/birdsql/bird_mini_dev",
        download_url="https://huggingface.co/datasets/birdsql/bird_mini_dev/resolve/main/data/mini_dev_sqlite.jsonl",
        spdx_license="CC-BY-SA-4.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=True,
        eval_only=True,
        training_allowed=False,
        format_kind="bird_mini_dev",
        description="500 database-grounded SQLite Text-to-SQL items with domain evidence formulas.",
    ),
    "ehrsql-2024": OpenBenchmarkSpec(
        dataset_id="ehrsql-2024",
        name="EHRSQL-2024 Clinical Text-to-SQL",
        domain="sql",
        release_year=2024,
        url="https://github.com/glee4810/ehrsql-2024",
        download_url="https://raw.githubusercontent.com/glee4810/ehrsql-2024/master/data/mimic_iv/valid/annotated.json",
        spdx_license="CC-BY-4.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=False,
        training_allowed=True,
        format_kind="ehrsql",
        description="Clinical MIMIC-IV read-only SQLite benchmark with unanswerable abstention gating.",
    ),
    "bird-critic-sqlite": OpenBenchmarkSpec(
        dataset_id="bird-critic-sqlite",
        name="BIRD-CRITIC 1.0 SQLite (SWE-SQL)",
        domain="sql",
        release_year=2025,
        url="https://huggingface.co/datasets/birdsql/bird-critic-1.0-sqlite",
        download_url="https://huggingface.co/datasets/birdsql/bird-critic-1.0-sqlite/resolve/main/sqlite-00000-of-00001.jsonl",
        spdx_license="CC-BY-SA-4.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=True,
        eval_only=True,
        training_allowed=False,
        format_kind="bird_critic_sqlite",
        description="SQLite SQL debugging and user issue repair evaluation benchmark.",
    ),
    "livesqlbench-sqlite": OpenBenchmarkSpec(
        dataset_id="livesqlbench-sqlite",
        name="LiveSQLBench Base-Lite SQLite",
        domain="sql",
        release_year=2025,
        url="https://huggingface.co/datasets/birdsql/livesqlbench-base-lite-sqlite",
        download_url="https://huggingface.co/datasets/birdsql/livesqlbench-base-lite-sqlite/resolve/main/alien/alien_kb.jsonl",
        spdx_license="CC-BY-SA-4.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=True,
        eval_only=True,
        training_allowed=False,
        format_kind="livesqlbench_sqlite",
        description="Dynamic contamination-free SQLite Text-to-SQL benchmark with hierarchical KBs.",
    ),
    "lean-workbook": OpenBenchmarkSpec(
        dataset_id="lean-workbook",
        name="Lean-Workbook",
        domain="lean4",
        release_year=2024,
        url="https://huggingface.co/datasets/internlm/Lean-Workbook",
        download_url="https://datasets-server.huggingface.co/rows?dataset=internlm/Lean-Workbook&config=default&split=train&offset=0&length=50",
        spdx_license="Apache-2.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=False,
        training_allowed=True,
        format_kind="lean_workbook",
        description="NeurIPS 2024 collection of 57K+ Lean 4 formal-informal math pairs and tactics.",
    ),
    "putnambench": OpenBenchmarkSpec(
        dataset_id="putnambench",
        name="PutnamBench (Lean 4)",
        domain="lean4",
        release_year=2024,
        url="https://github.com/trishullab/PutnamBench",
        download_url="https://raw.githubusercontent.com/trishullab/PutnamBench/main/lean4/src/putnam_1962_a1.lean",
        spdx_license="Apache-2.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=True,
        training_allowed=False,
        format_kind="putnambench",
        description="NeurIPS 2024 Putnam Mathematical Competition problems formalized in Lean 4.",
    ),
    "proofnet-lean4": OpenBenchmarkSpec(
        dataset_id="proofnet-lean4",
        name="ProofNet-Lean4",
        domain="lean4",
        release_year=2024,
        url="https://github.com/rahul3613/ProofNet-lean4",
        download_url="https://raw.githubusercontent.com/rahul3613/ProofNet-lean4/main/proofnet_lean4.jsonl",
        spdx_license="MIT",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=True,
        training_allowed=False,
        format_kind="proofnet_lean4",
        description="Undergraduate pure mathematics theorem-proving benchmark ported to Lean 4.",
    ),
    "minif2f-lean4": OpenBenchmarkSpec(
        dataset_id="minif2f-lean4",
        name="MiniF2F-Lean4",
        domain="lean4",
        release_year=2024,
        url="https://huggingface.co/datasets/cat-searcher/minif2f-lean4",
        download_url="https://huggingface.co/datasets/cat-searcher/minif2f-lean4/resolve/main/test.jsonl",
        spdx_license="MIT",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=True,
        training_allowed=False,
        format_kind="minif2f_lean4",
        description="Lean 4 + Mathlib4 Olympiad mathematics evaluation suite (valid + test splits).",
    ),
    "formalmath-lite": OpenBenchmarkSpec(
        dataset_id="formalmath-lite",
        name="FormalMATH-Lite",
        domain="lean4",
        release_year=2025,
        url="https://huggingface.co/datasets/SphereLab/FormalMATH-Lite",
        download_url="https://huggingface.co/datasets/SphereLab/FormalMATH-Lite/resolve/main/FormalMATH_lite.json",
        spdx_license="MIT",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=True,
        training_allowed=False,
        format_kind="formalmath_lite",
        description="Human-in-the-loop verified Lean 4 Olympiad and undergraduate math benchmark.",
    ),
    "numinamath-lean": OpenBenchmarkSpec(
        dataset_id="numinamath-lean",
        name="NuminaMath-LEAN",
        domain="lean4",
        release_year=2025,
        url="https://huggingface.co/datasets/AI-MO/NuminaMath-LEAN",
        download_url="https://huggingface.co/api/datasets/AI-MO/NuminaMath-LEAN",
        spdx_license="Apache-2.0",
        commercial_use_ok=True,
        redistribution_ok=True,
        share_alike=False,
        eval_only=False,
        training_allowed=True,
        format_kind="numinamath_lean",
        description="104K competition math problems formalized in Lean 4 with RLVR proof traces.",
    ),
}

_DATASET_ALIASES: dict[str, str] = {
    "spider2": "spider2-lite",
    "spider2_lite": "spider2-lite",
    "bird": "bird-mini-dev-hf",
    "bird_mini_dev": "bird-mini-dev-hf",
    "bird-mini-dev": "bird-mini-dev-hf",
    "ehrsql": "ehrsql-2024",
    "ehrsql_2024": "ehrsql-2024",
    "bird_critic": "bird-critic-sqlite",
    "bird_critic_sqlite": "bird-critic-sqlite",
    "livesqlbench": "livesqlbench-sqlite",
    "leanworkbook": "lean-workbook",
    "lean_workbook": "lean-workbook",
    "putnam": "putnambench",
    "proofnet": "proofnet-lean4",
    "proofnet_lean4": "proofnet-lean4",
    "minif2f": "minif2f-lean4",
    "minif2f_lean4": "minif2f-lean4",
    "formalmath": "formalmath-lite",
    "formalmath_lite": "formalmath-lite",
    "numinamath": "numinamath-lean",
    "numinamath_lean": "numinamath-lean",
}


def resolve_dataset_id(dataset_id: str) -> str:
    norm = dataset_id.strip().lower()
    resolved = _DATASET_ALIASES.get(norm, norm)
    if resolved not in OPEN_BENCHMARK_SPECS:
        raise KeyError(
            f"unknown open benchmark dataset {dataset_id!r}; "
            f"available: {sorted(OPEN_BENCHMARK_SPECS)}"
        )
    return resolved


def get_open_benchmark_spec(dataset_id: str) -> OpenBenchmarkSpec:
    return OPEN_BENCHMARK_SPECS[resolve_dataset_id(dataset_id)]


def list_open_benchmark_specs(
    *,
    domain: str | None = None,
    training_only: bool = False,
) -> list[OpenBenchmarkSpec]:
    specs = list(OPEN_BENCHMARK_SPECS.values())
    if domain is not None:
        dom = domain.strip().lower()
        specs = [s for s in specs if s.domain == dom]
    if training_only:
        specs = [s for s in specs if s.training_allowed and not s.eval_only]
    return specs


def load_catalog_datasets(catalog_path: str | Path | None = None) -> list[dict[str, Any]]:
    if catalog_path is None:
        catalog_path = Path(__file__).resolve().parents[2] / "catalog" / "sources.json"
    p = Path(catalog_path)
    payload = json.loads(p.read_text(encoding="utf-8"))
    return list(payload.get("datasets", []))


def _read_records(
    payload_or_path: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(payload_or_path, Mapping):
        if "rows" in payload_or_path and isinstance(payload_or_path["rows"], list):
            # HuggingFace datasets-server `/rows` response wrapper
            return [
                dict(r["row"]) if isinstance(r, Mapping) and "row" in r else dict(r)
                for r in payload_or_path["rows"]
            ]
        if "data" in payload_or_path and isinstance(payload_or_path["data"], list):
            return [dict(x) for x in payload_or_path["data"]]
        return [dict(payload_or_path)]

    if isinstance(payload_or_path, Sequence) and not isinstance(payload_or_path, (str, bytes, bytearray)):
        return [dict(x) for x in payload_or_path]

    if isinstance(payload_or_path, Path):
        raw_text = payload_or_path.read_text(encoding="utf-8")
    else:
        s = str(payload_or_path)
        if "\n" not in s and len(s) < 260:
            candidate_path = Path(s)
            if candidate_path.exists() and candidate_path.is_file():
                raw_text = candidate_path.read_text(encoding="utf-8")
            else:
                raw_text = s
        else:
            raw_text = s

    stripped = raw_text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        arr = json.loads(stripped)
        return [dict(x) for x in arr]
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            return _read_records(obj)
        except json.JSONDecodeError:
            pass
    records: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        ln = line.strip()
        if ln:
            records.append(dict(json.loads(ln)))
    return records


# ---------------------------------------------------------------------------
# Open Text-to-SQL Benchmark Items & `sql_gate` Adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenSqlBenchmarkItem:
    """Normalized read-only SQLite benchmark item across BIRD, Spider 2.0-Lite, EHRSQL, and BIRD-CRITIC."""

    dataset_id: str
    item_id: str
    db_id: str
    question: str
    gold_sql: str | None
    evidence: str = ""
    difficulty: str = ""
    is_unanswerable: bool = False
    dialect: str = "sqlite"
    issue_sql: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "item_id": self.item_id,
            "db_id": self.db_id,
            "question": self.question,
            "gold_sql": self.gold_sql,
            "evidence": self.evidence,
            "difficulty": self.difficulty,
            "is_unanswerable": self.is_unanswerable,
            "dialect": self.dialect,
            "issue_sql": list(self.issue_sql),
        }


def parse_bird_mini_dev_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenSqlBenchmarkItem]:
    """Parse `birdsql/bird_mini_dev` (`question_id`, `db_id`, `question`, `evidence`, `SQL`, `difficulty`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenSqlBenchmarkItem] = []
    for idx, row in enumerate(rows):
        qid = str(row.get("question_id", idx))
        db_id = str(row.get("db_id", "")).strip()
        question = str(row.get("question", "")).strip()
        sql = str(row.get("SQL") or row.get("sql") or row.get("query") or "").strip()
        if not db_id or not question or not sql:
            raise ValueError(f"BIRD Mini-Dev item {qid!r} missing required db_id/question/SQL fields")
        out.append(
            OpenSqlBenchmarkItem(
                dataset_id="bird-mini-dev-hf",
                item_id=qid,
                db_id=db_id,
                question=question,
                gold_sql=sql,
                evidence=str(row.get("evidence") or "").strip(),
                difficulty=str(row.get("difficulty") or "").strip(),
                is_unanswerable=False,
                dialect="sqlite",
            )
        )
    return out


def parse_spider2_lite_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
    *,
    gold_sql_dir: str | Path | None = None,
    gold_sql_map: Mapping[str, str] | None = None,
    sqlite_only: bool = True,
) -> list[OpenSqlBenchmarkItem]:
    """Parse `xlangai/spider2-lite` (`instance_id`, `db`, `question`, `external_knowledge`)."""
    rows = _read_records(payload_or_path)
    gold_dir = Path(gold_sql_dir) if gold_sql_dir is not None else None
    out: list[OpenSqlBenchmarkItem] = []

    for idx, row in enumerate(rows):
        inst_id = str(row.get("instance_id") or row.get("id") or f"item_{idx}").strip()
        is_local_sqlite = inst_id.lower().startswith("local") or str(row.get("dialect", "")).lower() == "sqlite"
        if sqlite_only and not is_local_sqlite:
            continue
        db_id = str(row.get("db") or row.get("db_id") or "").strip()
        question = str(row.get("question") or "").strip()
        if not db_id or not question:
            raise ValueError(f"Spider2-Lite item {inst_id!r} missing required db/question fields")

        gold_sql: str | None = None
        if gold_sql_map and inst_id in gold_sql_map:
            gold_sql = gold_sql_map[inst_id].strip()
        elif gold_dir is not None and (gold_dir / f"{inst_id}.sql").exists():
            gold_sql = (gold_dir / f"{inst_id}.sql").read_text(encoding="utf-8").strip()
        elif row.get("SQL") or row.get("gold_sql") or row.get("sql"):
            gold_sql = str(row.get("SQL") or row.get("gold_sql") or row.get("sql")).strip()

        dialect = "sqlite" if is_local_sqlite else (
            "bigquery" if inst_id.lower().startswith("bq") or inst_id.lower().startswith("ga") else "snowflake"
        )
        ext_know = str(row.get("external_knowledge") or "").strip()
        out.append(
            OpenSqlBenchmarkItem(
                dataset_id="spider2-lite",
                item_id=inst_id,
                db_id=db_id,
                question=question,
                gold_sql=gold_sql,
                evidence=ext_know,
                is_unanswerable=False,
                dialect=dialect,
            )
        )
    return out


_EHRSQL_MACRO_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bcurrent_time\b", flags=re.IGNORECASE), "'2100-12-31 23:59:00'"),
    (re.compile(r"\bcurrent_date\b", flags=re.IGNORECASE), "'2100-12-31'"),
    (re.compile(r"\btemperature_lower\b"), "35.5"),
    (re.compile(r"\btemperature_upper\b"), "38.1"),
    (re.compile(r"\bsao2_lower\b"), "95.0"),
    (re.compile(r"\bsao2_upper\b"), "100.0"),
    (re.compile(r"\bheart_rate_lower\b"), "60.0"),
    (re.compile(r"\bheart_rate_upper\b"), "100.0"),
    (re.compile(r"\brespiration_lower\b"), "12.0"),
    (re.compile(r"\brespiration_upper\b"), "18.0"),
    (re.compile(r"\bsystolic_bp_lower\b"), "90.0"),
    (re.compile(r"\bsystolic_bp_upper\b"), "120.0"),
    (re.compile(r"\bdiastolic_bp_lower\b"), "60.0"),
    (re.compile(r"\bdiastolic_bp_upper\b"), "90.0"),
    (re.compile(r"\bmean_bp_lower\b"), "60.0"),
    (re.compile(r"\bmean_bp_upper\b"), "110.0"),
)


def postprocess_ehrsql_sql(sql: str, *, expand_current_time: bool = True) -> str:
    """Apply official EHRSQL-2024 clinical vital-range and `2100-12-31 23:59:00` time-anchor macros."""
    parts = re.split(r"('(?:''|[^'])*')", sql)
    out_parts: list[str] = []
    for idx, chunk in enumerate(parts):
        if idx % 2 == 1:
            out_parts.append(chunk)
            continue
        updated = chunk
        for pattern, replacement in _EHRSQL_MACRO_REPLACEMENTS:
            if not expand_current_time and replacement.startswith("'2100-"):
                continue
            updated = pattern.sub(replacement, updated)
        out_parts.append(updated)
    return "".join(out_parts)


def parse_ehrsql_items(
    data_or_annotated: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    labels: str | Path | Mapping[str, Any] | None = None,
    db_id: str = "mimic_iv",
    postprocess_sql: bool = True,
) -> list[OpenSqlBenchmarkItem]:
    """Parse `glee4810/ehrsql-2024` (`annotated.json` or paired `data.json` + `label.json`)."""
    rows = _read_records(data_or_annotated)
    label_map: dict[str, Any] = {}
    if labels is not None:
        if isinstance(labels, Mapping):
            label_map = dict(labels)
        elif isinstance(labels, Path):
            label_map = dict(json.loads(labels.read_text(encoding="utf-8")))
        else:
            s = str(labels)
            p = Path(s) if "\n" not in s and len(s) < 260 else None
            if p is not None and p.exists():
                label_map = dict(json.loads(p.read_text(encoding="utf-8")))
            else:
                label_map = dict(json.loads(s))

    out: list[OpenSqlBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("id", f"ehrsql_{idx}")).strip()
        question = str(row.get("question") or "").strip()
        if not question:
            raise ValueError(f"EHRSQL item {item_id!r} has empty question")
        raw_sql = label_map.get(item_id) if item_id in label_map else row.get("query", row.get("SQL", row.get("label")))
        sql_str = "" if raw_sql is None else str(raw_sql).strip()
        is_unans = sql_str.lower() in ABSTENTION_TOKENS or bool(row.get("is_impossible", False))
        resolved_gold = (
            None
            if is_unans
            else (postprocess_ehrsql_sql(sql_str) if postprocess_sql else sql_str)
        )
        item_db = str(row.get("db_id") or db_id).strip()
        out.append(
            OpenSqlBenchmarkItem(
                dataset_id="ehrsql-2024",
                item_id=item_id,
                db_id=item_db,
                question=question,
                gold_sql=resolved_gold,
                evidence=str(row.get("template") or "").strip(),
                is_unanswerable=is_unans,
                dialect="sqlite",
            )
        )
    return out


def parse_bird_critic_sqlite_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
    *,
    gold_sql_map: Mapping[str, str] | None = None,
) -> list[OpenSqlBenchmarkItem]:
    """Parse `birdsql/bird-critic-1.0-sqlite` (`instance_id`, `db_id`, `query`, `issue_sql`, `category`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenSqlBenchmarkItem] = []
    for idx, row in enumerate(rows):
        inst_id = str(row.get("instance_id", f"SQLite_{idx}")).strip()
        db_id = str(row.get("db_id") or "").strip()
        question = str(row.get("query") or row.get("question") or "").strip()
        if not db_id or not question:
            raise ValueError(f"BIRD-CRITIC item {inst_id!r} missing required db_id/query fields")
        raw_issues = row.get("issue_sql") or ()
        issues = (str(raw_issues),) if isinstance(raw_issues, str) else tuple(str(x) for x in raw_issues)
        gold_sql: str | None = None
        if gold_sql_map and inst_id in gold_sql_map:
            gold_sql = gold_sql_map[inst_id].strip()
        elif row.get("sol_sql") or row.get("gold_sql") or row.get("SQL"):
            raw_sol = row.get("sol_sql") or row.get("gold_sql") or row.get("SQL")
            gold_sql = str(raw_sol[0] if isinstance(raw_sol, list) and raw_sol else raw_sol).strip()
        out.append(
            OpenSqlBenchmarkItem(
                dataset_id="bird-critic-sqlite",
                item_id=inst_id,
                db_id=db_id,
                question=question,
                gold_sql=gold_sql,
                difficulty=str(row.get("category") or "").strip(),
                is_unanswerable=False,
                dialect=str(row.get("dialect") or "sqlite").lower(),
                issue_sql=issues,
            )
        )
    return out


def load_sql_benchmark_items(
    dataset_id: str,
    source: Any,
    **kwargs: Any,
) -> list[OpenSqlBenchmarkItem]:
    """Dispatch dataset-specific SQL benchmark loading into `OpenSqlBenchmarkItem` records."""
    resolved = resolve_dataset_id(dataset_id)
    spec = OPEN_BENCHMARK_SPECS[resolved]
    if spec.domain != "sql":
        raise ValueError(f"dataset {resolved!r} has domain {spec.domain!r}, expected 'sql'")
    if spec.format_kind == "bird_mini_dev":
        return parse_bird_mini_dev_items(source)
    if spec.format_kind == "spider2_lite":
        return parse_spider2_lite_items(source, **kwargs)
    if spec.format_kind == "ehrsql":
        return parse_ehrsql_items(source, **kwargs)
    if spec.format_kind == "bird_critic_sqlite":
        return parse_bird_critic_sqlite_items(source, **kwargs)
    raise ValueError(f"no SQL item parser registered for format_kind={spec.format_kind!r}")


def to_candidates_benchmark(
    items: Sequence[OpenSqlBenchmarkItem],
    candidates_by_item_id: Mapping[str, Sequence[Mapping[str, str]]],
) -> list[dict[str, Any]]:
    """Convert answerable `OpenSqlBenchmarkItem` items + candidate SQL lists into `candidates.schema.json` format."""
    converted: list[dict[str, Any]] = []
    qid = 1
    for item in items:
        if item.is_unanswerable or not item.gold_sql:
            continue
        cands = candidates_by_item_id.get(item.item_id)
        if not cands:
            continue
        converted.append(
            {
                "qid": qid,
                "question": (
                    f"{item.question} [Evidence: {item.evidence}]"
                    if item.evidence
                    else item.question
                ),
                "gold": item.gold_sql,
                "candidates": [
                    {"label": str(c["label"]), "sql": str(c["sql"])}
                    for c in cands
                ],
            }
        )
        qid += 1
    errs = validate_candidates_schema(converted)
    if errs:
        raise ValueError(f"converted benchmark failed candidates schema validation: {errs}")
    return converted


def _is_abstention(candidate_sql: str | None) -> bool:
    if candidate_sql is None:
        return True
    return candidate_sql.strip().lower() in ABSTENTION_TOKENS


def verify_open_sql_item(
    db_or_path: sqlite3.Connection | str | Path,
    item: OpenSqlBenchmarkItem,
    candidate_sql: str | None,
    *,
    counterexample_cons: Sequence[sqlite3.Connection] | None = None,
    properties: Sequence[Callable[[QueryResult], str | None]] | None = None,
    schema: Mapping[str, Sequence[str]] | None = None,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
    allow_recursive_cte: bool = True,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> VerifyVerdict:
    """Verify a candidate response on an `OpenSqlBenchmarkItem` through the 4-layer read-only `sql_gate`."""
    abstained = _is_abstention(candidate_sql)
    if item.is_unanswerable:
        if abstained:
            return VerifyVerdict(
                passed=True,
                layer=None,
                reason="abstained on unanswerable query",
                diagnostics=[],
            )
        assert candidate_sql is not None
        stmts, parse_err = check_parse(candidate_sql)
        if parse_err or stmts is None:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[0],
                reason=parse_err or "parse error",
                diagnostics=[f"layer 1 parse: {parse_err}"],
            )
        ro_err = check_read_only(stmts)
        if ro_err:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[1],
                reason=ro_err,
                diagnostics=[f"layer 2 read-only: {ro_err}"],
            )
        return VerifyVerdict(
            passed=False,
            layer=LAYERS[3],
            reason="hallucinated SQL on unanswerable clinical question",
            diagnostics=[
                f"item {item.item_id!r} ({item.dataset_id}) is unanswerable; expected abstention"
            ],
        )

    if abstained:
        return VerifyVerdict(
            passed=False,
            layer=LAYERS[0],
            reason="unexpected abstention on answerable SQL benchmark item",
            diagnostics=[f"item {item.item_id!r} requires a read-only SELECT query"],
        )

    owns_con = False
    if isinstance(db_or_path, (str, Path)):
        con, inferred_schema = open_readonly_db(db_or_path)
        owns_con = True
        effective_schema = inferred_schema if schema is None else schema
    else:
        con = db_or_path
        effective_schema = introspect_sqlite_schema(con) if schema is None else schema
        lock_connection_readonly(con)

    try:
        return verify_sql(
            con,
            candidate_sql,
            gold_sql=item.gold_sql,
            counterexample_cons=counterexample_cons,
            properties=properties,
            schema=effective_schema,
            strict_joins=strict_joins,
            allow_cross_join=allow_cross_join,
            allow_recursive_cte=allow_recursive_cte,
            max_vm_steps=max_vm_steps,
            timeout_s=timeout_s,
            max_rows=max_rows,
            max_value_bytes=max_value_bytes,
        )
    finally:
        if owns_con:
            con.close()


def evaluate_open_sql_batch(
    db_or_map: sqlite3.Connection | str | Path | Mapping[str, sqlite3.Connection | str | Path],
    items: Sequence[OpenSqlBenchmarkItem],
    candidates_by_item_id: Mapping[str, str | None],
    *,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
    allow_recursive_cte: bool = True,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Batch-verify candidate outputs across open SQL benchmark items and summarize per-layer rejections."""
    layer_counts: dict[str, int] = {name: 0 for name in LAYERS}
    passed = 0
    results: list[dict[str, Any]] = []

    opened_cons: dict[str, tuple[sqlite3.Connection, dict[str, list[str]]]] = {}
    single_con_info: tuple[sqlite3.Connection, dict[str, list[str]], bool] | None = None
    if isinstance(db_or_map, (str, Path)):
        db_str = str(db_or_map)
        if db_str != ":memory:" and any(not i.is_unanswerable for i in items):
            c, sch = open_readonly_db(db_or_map)
            single_con_info = (c, sch, True)
    elif isinstance(db_or_map, sqlite3.Connection):
        sch = introspect_sqlite_schema(db_or_map)
        lock_connection_readonly(db_or_map)
        single_con_info = (db_or_map, sch, False)

    try:
        for item in items:
            cand = candidates_by_item_id.get(item.item_id)
            target_schema: Mapping[str, Sequence[str]] | None = None
            if isinstance(db_or_map, Mapping):
                if item.db_id not in db_or_map and not item.is_unanswerable:
                    raise KeyError(f"missing SQLite database connection/path for db_id={item.db_id!r}")
                raw_target = db_or_map.get(item.db_id, ":memory:")
                if not item.is_unanswerable and isinstance(raw_target, (str, Path)) and str(raw_target) != ":memory:":
                    if item.db_id not in opened_cons:
                        opened_cons[item.db_id] = open_readonly_db(raw_target)
                    target_db: Any = opened_cons[item.db_id][0]
                    target_schema = opened_cons[item.db_id][1]
                else:
                    target_db = raw_target
            elif single_con_info is not None:
                target_db = single_con_info[0]
                target_schema = single_con_info[1]
            else:
                target_db = db_or_map

            verdict = verify_open_sql_item(
                target_db,
                item,
                cand,
                schema=target_schema,
                strict_joins=strict_joins,
                allow_cross_join=allow_cross_join,
                allow_recursive_cte=allow_recursive_cte,
                max_vm_steps=max_vm_steps,
                timeout_s=timeout_s,
                max_rows=max_rows,
                max_value_bytes=max_value_bytes,
            )
            if verdict.passed:
                passed += 1
            elif verdict.layer in layer_counts:
                layer_counts[verdict.layer] += 1

            results.append(
                {
                    "dataset_id": item.dataset_id,
                    "item_id": item.item_id,
                    "db_id": item.db_id,
                    "is_unanswerable": item.is_unanswerable,
                    "passed": verdict.passed,
                    "layer": verdict.layer,
                    "reason": verdict.reason,
                }
            )
    finally:
        if single_con_info is not None and single_con_info[2]:
            single_con_info[0].close()
        for c, _ in opened_cons.values():
            c.close()

    total = len(items)
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "stopped_by_layer": layer_counts,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Open Lean 4 Formal Theorem-Proving Benchmark Items & `lean_gate` Adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenLeanBenchmarkItem:
    """Normalized Lean 4 theorem-proving item across Lean-Workbook, PutnamBench, ProofNet, MiniF2F, FormalMATH."""

    dataset_id: str
    item_id: str
    header: str
    formal_statement: str
    informal_statement: str = ""
    reference_proof: str | None = None
    status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "item_id": self.item_id,
            "header": self.header,
            "formal_statement": self.formal_statement,
            "informal_statement": self.informal_statement,
            "reference_proof": self.reference_proof,
            "status": self.status,
        }


def _split_lean_preamble_and_decl(source: str) -> tuple[str, str]:
    """Separate leading `import`/`open` header lines from the `theorem`/`lemma` declaration."""
    lines = source.splitlines()
    header_lines: list[str] = []
    decl_start = 0
    in_block_comment = 0

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if in_block_comment > 0:
            in_block_comment += line.count("/-") - line.count("-/")
            continue
        if stripped.startswith("/-"):
            delta = line.count("/-") - line.count("-/")
            if delta > 0:
                in_block_comment = delta
            continue
        if not stripped or stripped.startswith("--") or _PREAMBLE_LINE_RE.match(line):
            header_lines.append(line)
            decl_start = idx + 1
            continue
        decl_start = idx
        break

    header = "\n".join(header_lines).strip()
    decl = "\n".join(lines[decl_start:]).strip()
    return header, decl


def canonicalize_lean_statement(formal_statement: str) -> str:
    """Extract comment-free, whitespace-normalized `theorem`/`lemma` signature before `:= [by] [sorry]`."""
    no_comments = strip_lean_comments(formal_statement)
    _, decl = _split_lean_preamble_and_decl(no_comments)
    target = decl if decl else no_comments.strip()
    without_rhs = _TRAILING_SORRY_RE.sub("", target).strip()
    return re.sub(r"\s+", " ", without_rhs).strip()


def parse_lean_workbook_items(
    payload_or_path: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    default_header: str = "import Mathlib\n\nopen BigOperators Real Nat Topology",
) -> list[OpenLeanBenchmarkItem]:
    """Parse `internlm/Lean-Workbook` (`id`, `status`, `tactic`, `natural_language_statement`, `formal_statement`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("id", f"lean_workbook_{idx}")).strip()
        stmt = str(row.get("formal_statement") or "").strip()
        if not stmt:
            raise ValueError(f"Lean-Workbook item {item_id!r} has empty formal_statement")
        hdr, clean_stmt = _split_lean_preamble_and_decl(stmt)
        tactic_raw = str(row.get("tactic") or "").strip()
        status = str(row.get("status") or "").strip()
        ref_proof = tactic_raw if tactic_raw and "sorry" not in tactic_raw else None
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="lean-workbook",
                item_id=item_id,
                header=str(row.get("header") or hdr or default_header).strip(),
                formal_statement=clean_stmt or stmt,
                informal_statement=str(row.get("natural_language_statement") or "").strip(),
                reference_proof=ref_proof,
                status=status,
            )
        )
    return out


def parse_putnambench_items(
    source_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenLeanBenchmarkItem]:
    """Parse `trishullab/PutnamBench` Lean 4 `.lean` source files, directory, or JSONL records."""
    if isinstance(source_or_path, Path) and source_or_path.is_dir():
        items: list[OpenLeanBenchmarkItem] = []
        for lean_file in sorted(source_or_path.glob("*.lean")):
            items.extend(parse_putnambench_items(lean_file))
        return items

    is_lean_file = isinstance(source_or_path, Path) and source_or_path.suffix == ".lean"
    if is_lean_file or (
        isinstance(source_or_path, str)
        and not source_or_path.lstrip().startswith(("{", "["))
        and _THEOREM_DECL_RE.search(source_or_path) is not None
    ):
        raw_text = (
            source_or_path.read_text(encoding="utf-8")
            if isinstance(source_or_path, Path)
            else source_or_path
        )
        doc_matches = re.findall(r"/--(.*?)-/", raw_text, flags=re.DOTALL)
        informal = doc_matches[-1].strip() if doc_matches else ""
        header, decl = _split_lean_preamble_and_decl(strip_lean_comments(raw_text))
        m = _THEOREM_DECL_RE.search(decl)
        if m is None:
            raise ValueError("PutnamBench Lean 4 input contains no theorem/lemma declaration")
        thm_name = m.group(1)
        return [
            OpenLeanBenchmarkItem(
                dataset_id="putnambench",
                item_id=thm_name,
                header=header or "import Mathlib",
                formal_statement=decl,
                informal_statement=informal,
            )
        ]

    rows = _read_records(source_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("name") or row.get("id") or f"putnam_{idx}").strip()
        stmt = str(row.get("formal_statement") or row.get("lean4_statement") or "").strip()
        if not stmt:
            raise ValueError(f"PutnamBench item {item_id!r} missing formal_statement")
        hdr, clean_stmt = _split_lean_preamble_and_decl(stmt)
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="putnambench",
                item_id=item_id,
                header=str(row.get("header") or hdr or "import Mathlib").strip(),
                formal_statement=clean_stmt or stmt,
                informal_statement=str(row.get("informal_statement") or row.get("informal_stmt") or "").strip(),
                reference_proof=str(row.get("formal_proof")).strip() if row.get("formal_proof") else None,
            )
        )
    return out


def parse_proofnet_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenLeanBenchmarkItem]:
    """Parse `rahul3613/ProofNet-lean4` or `hoskinson-center/proofnet` JSONL items."""
    rows = _read_records(payload_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("name") or row.get("id") or f"proofnet_{idx}").strip()
        stmt = str(row.get("formal_statement") or "").strip()
        if not stmt:
            raise ValueError(f"ProofNet item {item_id!r} missing formal_statement")
        header = str(row.get("header") or row.get("src_header") or "import Mathlib").strip()
        informal = str(row.get("informal_stmt") or row.get("nl_statement") or "").strip()
        fproof = str(row["formal_proof"]).strip() if row.get("formal_proof") else None
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="proofnet-lean4",
                item_id=item_id,
                header=header,
                formal_statement=stmt,
                informal_statement=informal,
                reference_proof=fproof,
            )
        )
    return out


def parse_minif2f_lean4_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenLeanBenchmarkItem]:
    """Parse `cat-searcher/minif2f-lean4` (`id`, `split`, `header`, `formal_statement`, `informal_stmt`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("id") or row.get("name") or f"minif2f_{idx}").strip()
        stmt = str(row.get("formal_statement") or "").strip()
        if not stmt:
            raise ValueError(f"MiniF2F-Lean4 item {item_id!r} missing formal_statement")
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="minif2f-lean4",
                item_id=item_id,
                header=str(row.get("header") or "import Mathlib").strip(),
                formal_statement=stmt,
                informal_statement=str(row.get("informal_stmt") or "").strip(),
                reference_proof=str(row["formal_proof"]).strip() if row.get("formal_proof") else None,
                status=str(row.get("split") or "").strip(),
            )
        )
    return out


def parse_formalmath_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenLeanBenchmarkItem]:
    """Parse `SphereLab/FormalMATH-Lite` (`theorem_names`, `autoformalization`, `domain`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("theorem_names") or row.get("id") or f"formalmath_{idx}").strip()
        auto_src = str(row.get("autoformalization") or row.get("formal_statement") or "").strip()
        if not auto_src:
            raise ValueError(f"FormalMATH item {item_id!r} missing autoformalization/formal_statement")
        hdr, decl = _split_lean_preamble_and_decl(auto_src)
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="formalmath-lite",
                item_id=item_id,
                header=str(row.get("header") or hdr or "import Mathlib").strip(),
                formal_statement=decl or auto_src,
                informal_statement=str(row.get("informal_statement") or "").strip(),
                status=str(row.get("domain") or "").strip(),
            )
        )
    return out


def parse_numinamath_lean_items(
    payload_or_path: str | Path | Sequence[Mapping[str, Any]],
) -> list[OpenLeanBenchmarkItem]:
    """Parse `AI-MO/NuminaMath-LEAN` (`uuid`, `problem`, `formal_statement`, `formal_proof`)."""
    rows = _read_records(payload_or_path)
    out: list[OpenLeanBenchmarkItem] = []
    for idx, row in enumerate(rows):
        item_id = str(row.get("uuid") or row.get("id") or f"numinamath_{idx}").strip()
        raw_stmt = str(row.get("formal_statement") or "").strip()
        if not raw_stmt:
            raise ValueError(f"NuminaMath-LEAN item {item_id!r} missing formal_statement")
        hdr, decl = _split_lean_preamble_and_decl(raw_stmt)
        fproof = str(row["formal_proof"]).strip() if row.get("formal_proof") else None
        out.append(
            OpenLeanBenchmarkItem(
                dataset_id="numinamath-lean",
                item_id=item_id,
                header=str(row.get("header") or hdr or "import Mathlib").strip(),
                formal_statement=decl or raw_stmt,
                informal_statement=str(row.get("problem") or "").strip(),
                reference_proof=fproof,
                status=str(row.get("source") or "").strip(),
            )
        )
    return out


def load_lean_benchmark_items(dataset_id: str, source: Any, **kwargs: Any) -> list[OpenLeanBenchmarkItem]:
    """Dispatch dataset-specific Lean 4 benchmark loading into `OpenLeanBenchmarkItem` records."""
    resolved = resolve_dataset_id(dataset_id)
    spec = OPEN_BENCHMARK_SPECS[resolved]
    if spec.domain != "lean4":
        raise ValueError(f"dataset {resolved!r} has domain {spec.domain!r}, expected 'lean4'")
    if spec.format_kind == "lean_workbook":
        return parse_lean_workbook_items(source, **kwargs)
    if spec.format_kind == "putnambench":
        return parse_putnambench_items(source)
    if spec.format_kind == "proofnet_lean4":
        return parse_proofnet_items(source)
    if spec.format_kind == "minif2f_lean4":
        return parse_minif2f_lean4_items(source)
    if spec.format_kind == "formalmath_lite":
        return parse_formalmath_items(source)
    if spec.format_kind == "numinamath_lean":
        return parse_numinamath_lean_items(source)
    raise ValueError(f"no Lean 4 item parser registered for format_kind={spec.format_kind!r}")


def assemble_lean_submission(
    item: OpenLeanBenchmarkItem,
    tactic_or_proof_body: str,
    *,
    include_header: bool = True,
) -> str:
    """Splice a tactic block or term proof onto `item.formal_statement` without altering the statement."""
    stmt_prefix = _TRAILING_SORRY_RE.sub("", item.formal_statement.strip()).strip()
    body = tactic_or_proof_body.strip()
    if not body:
        rendered_decl = f"{stmt_prefix} :="
    elif body.startswith(":="):
        rendered_decl = f"{stmt_prefix} {body}"
    elif body.startswith("by ") or body.startswith("by\n") or body == "by":
        rendered_decl = f"{stmt_prefix} := {body}"
    else:
        indented = "\n".join(f"  {ln}" if ln.strip() else "" for ln in body.splitlines())
        rendered_decl = f"{stmt_prefix} := by\n{indented}"

    if include_header and item.header.strip():
        return f"{item.header.strip()}\n\n{rendered_decl}\n"
    return f"{rendered_decl}\n"


def verify_open_lean_item(
    item: OpenLeanBenchmarkItem,
    candidate_proof_or_source: str | None = None,
    *,
    run_toolchain: bool | None = None,
    static_only: bool = False,
    project_dir: str | Path | None = None,
    run_leanchecker: bool = False,
    timeout_s: float = 60.0,
) -> VerifyVerdict:
    """Verify a candidate Lean 4 proof against an `OpenLeanBenchmarkItem` via `lean_gate` (live compile + `#print axioms`)."""
    raw_cand = item.reference_proof if candidate_proof_or_source is None else candidate_proof_or_source
    if raw_cand is None or not str(raw_cand).strip():
        # Fall back to auditing the raw benchmark statement itself (which typically fails on `sorry`)
        full_source = (
            f"{item.header.strip()}\n\n{item.formal_statement.strip()}\n"
            if item.header.strip()
            else item.formal_statement
        )
    else:
        cand_str = str(raw_cand).strip()
        cand_stripped = strip_lean_comments(cand_str)
        if _THEOREM_DECL_RE.search(cand_stripped) is not None:
            full_source = cand_str
        else:
            full_source = assemble_lean_submission(item, cand_str, include_header=True)

    stripped_full = strip_lean_comments(full_source)
    for pattern, msg in _FORBIDDEN_BENCHMARK_DIRECTIVES:
        if re.search(pattern, stripped_full):
            return VerifyVerdict(
                passed=False,
                layer="soundness",
                reason=msg,
                diagnostics=[msg],
            )

    expected_sig = canonicalize_lean_statement(item.formal_statement)
    norm_full = re.sub(r"\s+", " ", stripped_full).strip()
    if expected_sig and f"{expected_sig} :=" not in norm_full and not norm_full.endswith(expected_sig):
        return VerifyVerdict(
            passed=False,
            layer="schema",
            reason="candidate altered or omitted benchmark theorem signature",
            diagnostics=[
                f"expected exact theorem signature: {expected_sig}",
            ],
        )

    stmt_no_comments = strip_lean_comments(item.formal_statement)
    thm_m = _THEOREM_DECL_RE.search(stmt_no_comments)
    expected_decls = [thm_m.group(1)] if thm_m is not None else None

    return verify_lean(
        full_source,
        run_toolchain=run_toolchain,
        static_only=static_only,
        project_dir=project_dir,
        run_leanchecker=run_leanchecker,
        expected_decls=expected_decls,
        timeout_s=timeout_s,
    )


def evaluate_open_lean_batch(
    items: Sequence[OpenLeanBenchmarkItem],
    candidates_by_item_id: Mapping[str, str | None] | None = None,
    *,
    run_toolchain: bool | None = None,
    static_only: bool = False,
    project_dir: str | Path | None = None,
    run_leanchecker: bool = False,
    timeout_s: float = 60.0,
) -> dict[str, Any]:
    """Batch-audit Lean 4 benchmark proofs enforcing signature integrity, live kernel compilation, and `#print axioms`."""
    passed = 0
    layer_counts: dict[str, int] = {"parse": 0, "schema": 0, "soundness": 0, "execution": 0}
    results: list[dict[str, Any]] = []

    for item in items:
        cand = candidates_by_item_id.get(item.item_id) if candidates_by_item_id is not None else None
        verdict = verify_open_lean_item(
            item,
            cand,
            run_toolchain=run_toolchain,
            static_only=static_only,
            project_dir=project_dir,
            run_leanchecker=run_leanchecker,
            timeout_s=timeout_s,
        )
        if verdict.passed:
            passed += 1
        elif verdict.layer is not None:
            layer_counts[verdict.layer] = layer_counts.get(verdict.layer, 0) + 1
        results.append(
            {
                "dataset_id": item.dataset_id,
                "item_id": item.item_id,
                "passed": verdict.passed,
                "layer": verdict.layer,
                "reason": verdict.reason,
            }
        )

    total = len(items)
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "stopped_by_layer": layer_counts,
        "results": results,
    }
