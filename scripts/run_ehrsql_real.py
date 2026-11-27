"""Build real EHRSQL-2024 MIMIC-IV Demo v2.2 SQLite DB and run `lab-verify` across all 1,163 validation items.

Downloads:
1. Open MIMIC-IV Clinical Database Demo v2.2 (`ODbL-1.0`) from PhysioNet into gitignored `data/ehrsql_2024/`.
2. Official `glee4810/ehrsql-2024` schema (`mimic_iv.sql`) and `valid/annotated.json` (`CC-BY-4.0`,
   931 answerable SQL items + 232 unanswerable abstention items).
3. `birdsql/bird_mini_dev` `mini_dev_sqlite.jsonl` (`CC-BY-SA-4.0`, 500 SQLite items, optional static/DB check).

Implements a pure-Python cross-platform equivalent of `glee4810/ehrsql-2024/preprocess/preprocess.sh`
(running cleanly on Windows and Linux CPU without `sh` or `dask`), executes every answerable validation
query gold-vs-gold and every unanswerable item with abstention through `lab_verify`, and writes
`results/ehrsql_2024_real.json`.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta
import gzip
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import sys
import time
from typing import Any, Iterator, Sequence
import urllib.request
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify.open_benchmarks import (  # noqa: E402
    evaluate_open_sql_batch,
    load_sql_benchmark_items,
)
from lab_verify.sql_gate import (  # noqa: E402
    check_parse,
    check_read_only,
    check_schema,
)

MIMIC_IV_DEMO_URL = (
    "https://physionet.org/static/published-projects/mimic-iv-demo/"
    "mimic-iv-clinical-database-demo-2.2.zip"
)
EHRSQL_SCHEMA_URL = (
    "https://raw.githubusercontent.com/glee4810/ehrsql-2024/master/data/mimic_iv/mimic_iv.sql"
)
EHRSQL_VALID_ANNOTATED_URL = (
    "https://raw.githubusercontent.com/glee4810/ehrsql-2024/master/data/mimic_iv/valid/annotated.json"
)
BIRD_MINI_DEV_URL = (
    "https://huggingface.co/datasets/birdsql/bird_mini_dev/resolve/main/data/mini_dev_sqlite.jsonl"
)

CHARTEVENT_ITEMIDS: frozenset[int] = frozenset(
    {
        223762,  # Temperature Celsius
        220277,  # O2 saturation pulseoxymetry
        220045,  # Heart Rate
        220210,  # Respiratory Rate
        220050,  # Arterial Blood Pressure systolic
        220051,  # Arterial Blood Pressure diastolic
        220052,  # Arterial Blood Pressure mean
        224639,  # Daily Weight
        226730,  # Height (cm)
    }
)

# Exact disambiguation map from `glee4810/ehrsql-2024/preprocess/preprocess_db_mimic_iv.py`
LABEL_MAPPER: dict[str, str] = {
    "micafungin": "inputevents",
    "propofol": "inputevents",
    "progesterone": "prescriptions",
    "lr": "inputevents",
    "ambisome": "inputevents",
    "ceftaroline": "inputevents",
    "epinephrine": "inputevents",
    "magnesium sulfate": "inputevents",
    "albumin 25%": "inputevents",
    "caspofungin": "inputevents",
    "ciprofloxacin": "inputevents",
    "atropine": "inputevents",
    "fentanyl": "inputevents",
    "dextrose 50%": "inputevents",
    "atovaquone": "inputevents",
    "penicillin g potassium": "inputevents",
    "heparin": "prescriptions",
    "diltiazem": "inputevents",
    "dilantin": "inputevents",
    "esmolol": "inputevents",
    "testosterone": "labevents",
    "dopamine": "inputevents",
    "potassium phosphate": "inputevents",
    "albumin": "labevents",
    "ensure": "inputevents",
    "verapamil": "inputevents",
    "procainamide": "prescriptions",
    "ceftriaxone": "inputevents",
    "ceftazidime": "inputevents",
    "d5ns": "inputevents",
    "citrate": "inputevents",
    "tobramycin": "labevents",
    "solution": "inputevents",
    "phenylephrine": "inputevents",
    "primidone": "prescriptions",
    "vasopressin": "inputevents",
    "doxycycline": "inputevents",
    "albumin 5%": "inputevents",
    "ribavirin": "inputevents",
    "metronidazole": "inputevents",
    "multivitamins": "inputevents",
    "potassium": "prescriptions",
    "tamiflu": "inputevents",
    "factor xiii": "labevents",
    "meropenem": "inputevents",
    "oxycodone": "labevents",
    "protamine sulfate": "inputevents",
    "d5 1/2ns": "inputevents",
    "rocuronium": "inputevents",
    "calcium chloride": "inputevents",
    "test": "prescriptions",
    "phenobarbital": "prescriptions",
    "calcium gluconate": "inputevents",
    "linezolid": "inputevents",
    "potassium chloride": "inputevents",
    "clindamycin": "inputevents",
    "adenosine": "inputevents",
    "morphine sulfate": "inputevents",
    "chloroquine": "inputevents",
    "folic acid": "inputevents",
    "amikacin": "prescriptions",
    "nafcillin": "inputevents",
    "daptomycin": "inputevents",
    "d5lr": "inputevents",
    "sodium": "labevents",
    "quinidine": "prescriptions",
    "moxifloxacin": "inputevents",
    "mannitol": "inputevents",
    "ampicillin": "inputevents",
    "isoniazid": "inputevents",
    "fluconazole": "inputevents",
    "lithium": "labevents",
    "keflex": "inputevents",
    "folate": "inputevents",
    "colistin": "inputevents",
    "ranitidine": "inputevents",
    "argatroban": "inputevents",
    "dobutamine": "inputevents",
    "cisatracurium": "inputevents",
    "dextrose 5%": "inputevents",
    "levofloxacin": "inputevents",
    "factor viii": "inputevents",
    "acetaminophen": "prescriptions",
    "d": "prescriptions",
    "lidocaine": "prescriptions",
    "theophylline": "labevents",
    "vancomycin": "prescriptions",
    "methotrexate": "prescriptions",
    "aminophylline": "inputevents",
    "hydrochloric acid": "inputevents",
    "nesiritide": "inputevents",
    "hydromorphone (dilaudid)": "inputevents",
    "octreotide": "inputevents",
    "gentamicin": "prescriptions",
    "nicardipine": "inputevents",
    "rifampin": "inputevents",
    "amiodarone": "inputevents",
    "tigecycline": "inputevents",
    "magnesium": "labevents",
    "insulin": "prescriptions",
    "hydralazine": "inputevents",
    "labetalol": "inputevents",
    "cyclosporine": "inputevents",
    "sodium bicarbonate 8.4%": "inputevents",
    "potassium acetate": "inputevents",
    "aztreonam": "inputevents",
    "cefepime": "inputevents",
    "carbamazepine": "labevents",
    "norepinephrine": "inputevents",
    "digoxin": "prescriptions",
    "milrinone": "inputevents",
    "heparin sodium": "inputevents",
    "valproic acid": "labevents",
    "foscarnet": "inputevents",
    "mannitol 20%": "inputevents",
    "d5 1/4ns": "inputevents",
    "phenytoin": "labevents",
    "iron": "labevents",
    "acetylcysteine": "inputevents",
    "epoprostenol (veletri)": "inputevents",
    "pyrazinamide": "inputevents",
    "sodium acetate": "inputevents",
    "acyclovir": "inputevents",
    "oxacillin": "inputevents",
    "ketamine": "inputevents",
    "fosphenytoin": "inputevents",
    "sterile water": "inputevents",
    "metoprolol": "inputevents",
    "nitroglycerin": "inputevents",
    "erythromycin": "inputevents",
    "estradiol": "labevents",
    "voriconazole": "inputevents",
    "pamidronate": "inputevents",
    "cefazolin": "inputevents",
    "azithromycin": "inputevents",
    "fondaparinux": "inputevents",
    "lepirudin": "inputevents",
    "thiamine": "inputevents",
    "thrombin": "labevents",
    "zinc": "prescriptions",
}

EXCLUDED_DIAGNOSIS_TITLES: frozenset[str] = frozenset(
    {
        "artificial insemination",
        "dental examination",
        "insertion of intrauterine contraceptive device",
    }
)


def _download_if_missing(url: str, dest: Path, *, timeout_s: float = 60.0) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists() or dest.stat().st_size == 0:
        req = urllib.request.Request(url, headers={"User-Agent": "lab-verify-ehrsql-runner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = resp.read()
        tmp = dest.with_suffix(dest.suffix + ".part")
        tmp.write_bytes(data)
        tmp.replace(dest)
    return hashlib.sha256(dest.read_bytes()).hexdigest()


def _extract_mimic_demo(zip_path: Path, data_dir: Path) -> Path:
    demo_root = data_dir / "mimic-iv-clinical-database-demo-2.2"
    marker = demo_root / "hosp"
    if not marker.is_dir():
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(data_dir)
    if not marker.is_dir():
        candidates = list(data_dir.glob("**/hosp"))
        if not candidates:
            raise FileNotFoundError(f"Extracted {zip_path} did not contain hosp/ directory")
        return candidates[0].parent
    return demo_root


def _iter_mimic_csv(demo_root: Path, rel_path: str) -> Iterator[dict[str, str]]:
    plain = demo_root / rel_path
    gz = demo_root / f"{rel_path}.gz"
    if plain.is_file():
        with plain.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                yield {k.lower(): (v.lower().strip() if v is not None else "") for k, v in row.items()}
        return
    if gz.is_file():
        with gzip.open(gz, "rt", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                yield {k.lower(): (v.lower().strip() if v is not None else "") for k, v in row.items()}
        return
    raise FileNotFoundError(f"Neither {plain} nor {gz} exists")


def _generate_random_dob(year: int) -> str:
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31)
    num_days = (end_date - start_date).days + 1
    rng = random.Random(0)
    dt = start_date + timedelta(days=rng.randint(0, num_days))
    return dt.strftime("%Y-%m-%d 00:00:00")


def _normalize_ts(raw_ts: str | None) -> str | None:
    if raw_ts is None:
        return None
    s = raw_ts.strip()
    if not s:
        return None
    if len(s) == 10:
        return f"{s} 00:00:00"
    return s


def _shift_ts(
    raw_ts: str | None,
    subject_id: int,
    offset_minutes: dict[int, int],
    current_time: str,
) -> str | None:
    norm = _normalize_ts(raw_ts)
    if norm is None or subject_id not in offset_minutes:
        return None
    dt = datetime.strptime(norm, "%Y-%m-%d %H:%M:%S") + timedelta(minutes=offset_minutes[subject_id])
    rendered = dt.strftime("%Y-%m-%d %H:%M:%S")
    if rendered > current_time:
        return None
    return rendered


def build_ehrsql_mimic_iv_sqlite(
    demo_root: Path,
    schema_sql_path: Path,
    sqlite_out_path: Path,
    *,
    num_patient: int = 100,
    start_year: int = 2100,
    time_span: int = 0,
    current_time: str = "2100-12-31 23:59:00",
    cur_patient_ratio: float = 0.1,
) -> dict[str, int]:
    """Pure-Python equivalent of `glee4810/ehrsql-2024/preprocess/preprocess.sh`."""
    if time_span != 0:
        raise ValueError("EHRSQL-2024 MIMIC-IV preprocess uses time_span=0")
    pivot_ts = f"{start_year:04d}-01-01 00:00:00"

    # 1. Patients & Admissions & Time-shift Offsets
    anchor_year: dict[int, int] = {}
    anchor_age: dict[int, int] = {}
    raw_patients: list[dict[str, Any]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/patients.csv"):
        sid = int(r["subject_id"])
        ay = int(r["anchor_year"])
        aa = int(r["anchor_age"])
        anchor_year[sid] = ay
        anchor_age[sid] = aa
        dob_str = _generate_random_dob(ay - aa)
        dod_str = _normalize_ts(r.get("dod", ""))
        raw_patients.append(
            {
                "subject_id": sid,
                "gender": r["gender"],
                "dob": dob_str,
                "dod": dod_str,
            }
        )

    raw_admissions: list[dict[str, Any]] = []
    hadm_orig_adm: dict[int, str] = {}
    hadm_orig_disch: dict[int, str] = {}
    earliest_adm_by_subj: dict[int, str] = {}

    for r in _iter_mimic_csv(demo_root, "hosp/admissions.csv"):
        sid = int(r["subject_id"])
        hid = int(r["hadm_id"])
        adm_ts = r["admittime"]
        disch_ts = r["dischtime"]
        hadm_orig_adm[hid] = adm_ts
        hadm_orig_disch[hid] = disch_ts
        if sid not in earliest_adm_by_subj or adm_ts < earliest_adm_by_subj[sid]:
            earliest_adm_by_subj[sid] = adm_ts
        adm_year = datetime.strptime(adm_ts, "%Y-%m-%d %H:%M:%S").year
        age = adm_year - anchor_year[sid] + anchor_age[sid]
        raw_admissions.append(
            {
                "subject_id": sid,
                "hadm_id": hid,
                "admittime": adm_ts,
                "dischtime": disch_ts,
                "admission_type": r["admission_type"],
                "admission_location": r["admission_location"],
                "discharge_location": r["discharge_location"] or None,
                "insurance": r["insurance"],
                "language": r["language"] or None,
                "marital_status": r["marital_status"] or None,
                "age": age,
            }
        )

    offset_minutes: dict[int, int] = {}
    for sid, earliest_str in earliest_adm_by_subj.items():
        earliest_year = datetime.strptime(earliest_str, "%Y-%m-%d %H:%M:%S").year
        offset_minutes[sid] = (start_year - earliest_year) * 365 * 24 * 60

    shifted_admissions: list[dict[str, Any]] = []
    cur_candidates: list[int] = []
    seen_cur: set[int] = set()
    non_cur_candidates: list[int] = []
    seen_non_cur: set[int] = set()

    for adm in raw_admissions:
        sid = adm["subject_id"]
        s_adm = _shift_ts(adm["admittime"], sid, offset_minutes, current_time)
        if s_adm is None:
            continue
        s_disch = _shift_ts(adm["dischtime"], sid, offset_minutes, current_time)
        disch_loc = adm["discharge_location"] if s_disch is not None else None
        rec = {
            **adm,
            "admittime": s_adm,
            "dischtime": s_disch,
            "discharge_location": disch_loc,
        }
        shifted_admissions.append(rec)
        if s_disch is None and sid not in seen_cur:
            seen_cur.add(sid)
            cur_candidates.append(sid)

    for adm in shifted_admissions:
        sid = adm["subject_id"]
        if adm["dischtime"] is not None and sid not in seen_cur and sid not in seen_non_cur:
            seen_non_cur.add(sid)
            non_cur_candidates.append(sid)

    num_cur = int(num_patient * cur_patient_ratio)
    num_non_cur = num_patient - num_cur
    cohort_rng = random.Random(0)
    chosen_cur = (
        cohort_rng.sample(cur_candidates, num_cur)
        if len(cur_candidates) > num_cur
        else list(cur_candidates)
    )
    chosen_non_cur = (
        cohort_rng.sample(non_cur_candidates, num_non_cur)
        if len(non_cur_candidates) > num_non_cur
        else list(non_cur_candidates)
    )
    patient_set = set(chosen_cur) | set(chosen_non_cur)

    patients_rows: list[tuple[Any, ...]] = []
    for p in raw_patients:
        sid = p["subject_id"]
        if sid not in patient_set:
            continue
        s_dob = _shift_ts(p["dob"], sid, offset_minutes, current_time)
        if s_dob is None:
            continue
        s_dod = _shift_ts(p["dod"], sid, offset_minutes, current_time)
        patients_rows.append((len(patients_rows), sid, p["gender"], s_dob, s_dod))

    admissions_rows: list[tuple[Any, ...]] = []
    hadm_set: set[int] = set()
    for adm in shifted_admissions:
        if adm["subject_id"] not in patient_set:
            continue
        hadm_set.add(adm["hadm_id"])
        admissions_rows.append(
            (
                len(admissions_rows),
                adm["subject_id"],
                adm["hadm_id"],
                adm["admittime"],
                adm["dischtime"],
                adm["admission_type"],
                adm["admission_location"],
                adm["discharge_location"],
                adm["insurance"],
                adm["language"],
                adm["marital_status"],
                adm["age"],
            )
        )

    icustays_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "icu/icustays.csv"):
        sid = int(r["subject_id"])
        hid = int(r["hadm_id"])
        if hid not in hadm_set:
            continue
        s_in = _shift_ts(r["intime"], sid, offset_minutes, current_time)
        if s_in is None:
            continue
        s_out = _shift_ts(r["outtime"], sid, offset_minutes, current_time)
        icustays_rows.append(
            (
                len(icustays_rows),
                sid,
                hid,
                int(r["stay_id"]),
                r["first_careunit"],
                r["last_careunit"],
                s_in,
                s_out,
            )
        )

    transfers_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/transfers.csv"):
        if not r["intime"] or not r["hadm_id"]:
            continue
        sid = int(r["subject_id"])
        hid = int(float(r["hadm_id"]))
        if hid not in hadm_set:
            continue
        s_in = _shift_ts(r["intime"], sid, offset_minutes, current_time)
        if s_in is None:
            continue
        s_out = _shift_ts(r["outtime"], sid, offset_minutes, current_time)
        transfers_rows.append(
            (
                len(transfers_rows),
                sid,
                hid,
                int(r["transfer_id"]),
                r["eventtype"],
                r["careunit"] or None,
                s_in,
                s_out,
            )
        )

    # 2. Dictionary tables
    d_icd_diag_rows: list[tuple[Any, ...]] = []
    seen_diag_codes: set[str] = set()
    seen_diag_titles: set[str] = set()
    for r in _iter_mimic_csv(demo_root, "hosp/d_icd_diagnoses.csv"):
        title = r["long_title"]
        if not r["icd_code"] or not r["icd_version"] or not title:
            continue
        if title in EXCLUDED_DIAGNOSIS_TITLES:
            continue
        code = f"icd{r['icd_version']}|{r['icd_code']}"
        if code in seen_diag_codes or title in seen_diag_titles:
            continue
        seen_diag_codes.add(code)
        seen_diag_titles.add(title)
        d_icd_diag_rows.append((len(d_icd_diag_rows), code, title))

    d_icd_proc_rows: list[tuple[Any, ...]] = []
    seen_proc_codes: set[str] = set()
    seen_proc_titles: set[str] = set()
    for r in _iter_mimic_csv(demo_root, "hosp/d_icd_procedures.csv"):
        title = r["long_title"]
        if not r["icd_code"] or not r["icd_version"] or not title:
            continue
        code = f"icd{r['icd_version']}|{r['icd_code']}"
        if code in seen_proc_codes or title in seen_proc_titles:
            continue
        seen_proc_codes.add(code)
        seen_proc_titles.add(title)
        d_icd_proc_rows.append((len(d_icd_proc_rows), code, title))

    d_labitems_rows: list[tuple[Any, ...]] = []
    valid_lab_itemids: set[int] = set()
    for r in _iter_mimic_csv(demo_root, "hosp/d_labitems.csv"):
        lbl = r["label"]
        if not lbl:
            continue
        if lbl in LABEL_MAPPER and LABEL_MAPPER[lbl] != "labevents":
            continue
        iid = int(r["itemid"])
        valid_lab_itemids.add(iid)
        d_labitems_rows.append((len(d_labitems_rows), iid, lbl))

    d_items_rows: list[tuple[Any, ...]] = []
    valid_d_itemids: set[int] = set()
    for r in _iter_mimic_csv(demo_root, "icu/d_items.csv"):
        lbl = r["label"]
        linksto = r["linksto"]
        if not lbl or linksto not in {"inputevents", "outputevents", "chartevents"}:
            continue
        if lbl in LABEL_MAPPER and LABEL_MAPPER[lbl] != "inputevents":
            continue
        iid = int(r["itemid"])
        valid_d_itemids.add(iid)
        d_items_rows.append((len(d_items_rows), iid, lbl, r["abbreviation"], linksto))

    # 3. Clinical event tables
    diagnoses_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/diagnoses_icd.csv"):
        if not r["icd_code"] or not r["hadm_id"]:
            continue
        sid = int(r["subject_id"])
        hid = int(r["hadm_id"])
        code = f"icd{r['icd_version']}|{r['icd_code']}"
        if code not in seen_diag_codes or hid not in hadm_set:
            continue
        orig_ct = hadm_orig_adm.get(hid)
        s_ct = _shift_ts(orig_ct, sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        diagnoses_rows.append((len(diagnoses_rows), sid, hid, code, s_ct))

    procedures_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/procedures_icd.csv"):
        if not r["icd_code"] or not r["hadm_id"] or not r["chartdate"]:
            continue
        sid = int(r["subject_id"])
        hid = int(r["hadm_id"])
        code = f"icd{r['icd_version']}|{r['icd_code']}"
        if code not in seen_proc_codes or hid not in hadm_set:
            continue
        ct = _normalize_ts(r["chartdate"])
        adm_t = hadm_orig_adm.get(hid)
        disch_t = hadm_orig_disch.get(hid)
        if ct is not None and adm_t is not None and disch_t is not None:
            if ct < adm_t or ct > disch_t:
                ct = disch_t
        s_ct = _shift_ts(ct, sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        procedures_rows.append((len(procedures_rows), sid, hid, code, s_ct))

    labevents_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/labevents.csv"):
        if not r["hadm_id"] or not r["valuenum"] or not r["valueuom"]:
            continue
        iid = int(r["itemid"])
        hid = int(float(r["hadm_id"]))
        if iid not in valid_lab_itemids or hid not in hadm_set:
            continue
        sid = int(r["subject_id"])
        s_ct = _shift_ts(r["charttime"], sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        labevents_rows.append((len(labevents_rows), sid, hid, iid, s_ct, float(r["valuenum"]), r["valueuom"]))

    raw_presc: list[dict[str, Any]] = []
    drug_units: dict[str, Counter[str]] = {}
    for r in _iter_mimic_csv(demo_root, "hosp/prescriptions.csv"):
        drug = r["drug"]
        if not drug or (drug in LABEL_MAPPER and LABEL_MAPPER[drug] != "prescriptions"):
            continue
        if not (r["starttime"] and r["stoptime"] and r["dose_val_rx"] and r["dose_unit_rx"] and r["route"]):
            continue
        clean_dose = r["dose_val_rx"].replace(",", "")
        if not clean_dose.isnumeric():
            continue
        unit = r["dose_unit_rx"]
        drug_units.setdefault(drug, Counter())[unit] += 1
        raw_presc.append(
            {
                "subject_id": int(r["subject_id"]),
                "hadm_id": int(r["hadm_id"]),
                "starttime": r["starttime"],
                "stoptime": r["stoptime"],
                "drug": drug,
                "dose_val_rx": str(int(clean_dose)),
                "dose_unit_rx": unit,
                "route": r["route"],
            }
        )

    top_unit_by_drug = {d: cnt.most_common(1)[0][0] for d, cnt in drug_units.items()}
    prescriptions_rows: list[tuple[Any, ...]] = []
    for pr in raw_presc:
        if pr["dose_unit_rx"] != top_unit_by_drug.get(pr["drug"]):
            continue
        if pr["hadm_id"] not in hadm_set:
            continue
        sid = pr["subject_id"]
        s_start = _shift_ts(pr["starttime"], sid, offset_minutes, current_time)
        if s_start is None or s_start < pivot_ts:
            continue
        s_stop = _shift_ts(pr["stoptime"], sid, offset_minutes, current_time)
        prescriptions_rows.append(
            (
                len(prescriptions_rows),
                sid,
                pr["hadm_id"],
                s_start,
                s_stop,
                pr["drug"],
                pr["dose_val_rx"],
                pr["dose_unit_rx"],
                pr["route"],
            )
        )

    # Cost table (deterministic synthetic unit costs per unique ICD/lab/drug item, matching preprocess_db_mimic_iv.py)
    cost_rng = random.Random(0)
    mean_costs = [10.0, 11.0, 9.0, 12.0]
    diag_cost_map = {
        c: round(max(1.0, cost_rng.gauss(mean_costs[0], 1.0)), 2)
        for c in sorted({r[3] for r in diagnoses_rows})
    }
    lab_cost_map = {
        iid: round(max(1.0, cost_rng.gauss(mean_costs[1], 1.0)), 2)
        for iid in sorted({r[3] for r in labevents_rows})
    }
    proc_cost_map = {
        c: round(max(1.0, cost_rng.gauss(mean_costs[2], 1.0)), 2)
        for c in sorted({r[3] for r in procedures_rows})
    }
    presc_cost_map = {
        d: round(max(1.0, cost_rng.gauss(mean_costs[3], 1.0)), 2)
        for d in sorted({r[5] for r in prescriptions_rows})
    }

    cost_rows: list[tuple[Any, ...]] = []
    for r in diagnoses_rows:
        cost_rows.append((len(cost_rows), r[1], r[2], "diagnoses_icd", r[0], r[4], diag_cost_map[r[3]]))
    for r in labevents_rows:
        cost_rows.append((len(cost_rows), r[1], r[2], "labevents", r[0], r[4], lab_cost_map[r[3]]))
    for r in procedures_rows:
        cost_rows.append((len(cost_rows), r[1], r[2], "procedures_icd", r[0], r[4], proc_cost_map[r[3]]))
    for r in prescriptions_rows:
        cost_rows.append((len(cost_rows), r[1], r[2], "prescriptions", r[0], r[3], presc_cost_map[r[5]]))

    chartevents_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "icu/chartevents.csv"):
        if not (r["subject_id"] and r["hadm_id"] and r["stay_id"] and r["charttime"] and r["valuenum"] and r["valueuom"]):
            continue
        iid = int(r["itemid"])
        sid = int(r["subject_id"])
        if iid not in CHARTEVENT_ITEMIDS or sid not in patient_set:
            continue
        hid = int(r["hadm_id"])
        if hid not in hadm_set:
            continue
        s_ct = _shift_ts(r["charttime"], sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        chartevents_rows.append(
            (len(chartevents_rows), sid, hid, int(r["stay_id"]), iid, s_ct, float(r["valuenum"]), r["valueuom"])
        )

    inputevents_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "icu/inputevents.csv"):
        if not (r["hadm_id"] and r["stay_id"] and r["totalamount"] and r["totalamountuom"] == "ml"):
            continue
        iid = int(r["itemid"])
        hid = int(r["hadm_id"])
        if iid not in valid_d_itemids or hid not in hadm_set:
            continue
        sid = int(r["subject_id"])
        s_st = _shift_ts(r["starttime"], sid, offset_minutes, current_time)
        if s_st is None or s_st < pivot_ts:
            continue
        inputevents_rows.append(
            (len(inputevents_rows), sid, hid, int(r["stay_id"]), s_st, iid, float(r["totalamount"]), "ml")
        )

    outputevents_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "icu/outputevents.csv"):
        if not (r["hadm_id"] and r["stay_id"] and r["value"] and r["valueuom"] == "ml"):
            continue
        iid = int(r["itemid"])
        hid = int(r["hadm_id"])
        if iid not in valid_d_itemids or hid not in hadm_set:
            continue
        sid = int(r["subject_id"])
        s_ct = _shift_ts(r["charttime"], sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        outputevents_rows.append(
            (len(outputevents_rows), sid, hid, int(r["stay_id"]), s_ct, iid, float(r["value"]), "ml")
        )

    microbiology_rows: list[tuple[Any, ...]] = []
    for r in _iter_mimic_csv(demo_root, "hosp/microbiologyevents.csv"):
        if not r["hadm_id"]:
            continue
        hid = int(float(r["hadm_id"]))
        if hid not in hadm_set:
            continue
        sid = int(r["subject_id"])
        raw_ct = r["charttime"] or r["chartdate"]
        s_ct = _shift_ts(raw_ct, sid, offset_minutes, current_time)
        if s_ct is None or s_ct < pivot_ts:
            continue
        microbiology_rows.append(
            (
                len(microbiology_rows),
                sid,
                hid,
                s_ct,
                r["spec_type_desc"] or None,
                r["test_name"] or None,
                r["org_name"] or None,
            )
        )

    sqlite_out_path.parent.mkdir(parents=True, exist_ok=True)
    if sqlite_out_path.exists():
        sqlite_out_path.unlink()

    con = sqlite3.connect(sqlite_out_path)
    try:
        con.executescript(schema_sql_path.read_text(encoding="utf-8"))
        table_payloads: list[tuple[str, list[tuple[Any, ...]], int]] = [
            ("patients", patients_rows, 5),
            ("admissions", admissions_rows, 12),
            ("d_icd_diagnoses", d_icd_diag_rows, 3),
            ("d_icd_procedures", d_icd_proc_rows, 3),
            ("d_items", d_items_rows, 5),
            ("d_labitems", d_labitems_rows, 3),
            ("diagnoses_icd", diagnoses_rows, 5),
            ("procedures_icd", procedures_rows, 5),
            ("labevents", labevents_rows, 7),
            ("prescriptions", prescriptions_rows, 9),
            ("cost", cost_rows, 7),
            ("chartevents", chartevents_rows, 8),
            ("inputevents", inputevents_rows, 8),
            ("outputevents", outputevents_rows, 8),
            ("microbiologyevents", microbiology_rows, 7),
            ("icustays", icustays_rows, 8),
            ("transfers", transfers_rows, 8),
        ]
        row_counts: dict[str, int] = {}
        for tbl_name, rows, arity in table_payloads:
            placeholders = ", ".join("?" for _ in range(arity))
            con.executemany(f"INSERT INTO {tbl_name} VALUES ({placeholders})", rows)
            row_counts[tbl_name] = len(rows)
        con.commit()
        return row_counts
    finally:
        con.close()


def _evaluate_bird_mini_dev_gold_static(
    bird_jsonl_path: Path,
    bird_db_dir: Path | None = None,
) -> dict[str, Any]:
    """Check all 500 BIRD Mini-Dev SQLite gold queries through parse, read-only, and join safety."""
    items = load_sql_benchmark_items("bird-mini-dev-hf", bird_jsonl_path)
    parse_ok = 0
    readonly_ok = 0
    join_lint_ok = 0
    outer_order_by = 0
    failures: list[dict[str, Any]] = []

    for item in items:
        assert item.gold_sql is not None
        stmts, p_err = check_parse(item.gold_sql)
        if p_err or not stmts:
            failures.append({"item_id": item.item_id, "layer": "parse", "reason": p_err or "parse error"})
            continue
        parse_ok += 1
        if stmts[0].args.get("order") is not None:
            outer_order_by += 1
        ro_err = check_read_only(stmts)
        if ro_err:
            failures.append({"item_id": item.item_id, "layer": "read-only", "reason": ro_err})
            continue
        readonly_ok += 1

        # Build permissive schema over referenced base tables/columns to isolate join/CTE rule checks
        stmt = stmts[0]
        db_sqlite = (
            bird_db_dir / item.db_id / f"{item.db_id}.sqlite"
            if bird_db_dir is not None
            else None
        )
        if db_sqlite is not None and db_sqlite.is_file():
            from lab_verify.sql_gate import open_readonly_db

            bcon, bschema = open_readonly_db(db_sqlite)
            bcon.close()
            sch_err = check_schema(stmt, schema=bschema, strict_joins=True, raw_sql=item.gold_sql)
        else:
            from sqlglot import exp as sg_exp

            cte_names = {
                c.alias.lower()
                for wc in stmt.find_all(sg_exp.With)
                for c in wc.expressions
                if c.alias
            }
            all_cols = sorted(
                {(col.name or "").lower() for col in stmt.find_all(sg_exp.Column) if col.name and not col.is_star}
                | {"id"}
            )
            inferred_schema = {
                (tbl.name or "").lower(): all_cols
                for tbl in stmt.find_all(sg_exp.Table)
                if tbl.name and (tbl.name or "").lower() not in cte_names
            }
            # Disambiguate unqualified columns by only checking join/CTE errors when schema is inferred
            sch_err = check_schema(stmt, schema=inferred_schema, strict_joins=True, raw_sql=item.gold_sql)
            if sch_err and sch_err.startswith("ambiguous column "):
                sch_err = None

        if sch_err:
            failures.append({"item_id": item.item_id, "layer": "schema", "reason": sch_err})
        else:
            join_lint_ok += 1

    return {
        "dataset_id": "bird-mini-dev-hf",
        "spdx_license": "CC-BY-SA-4.0",
        "eval_only": True,
        "total_items": len(items),
        "outer_order_by_count": outer_order_by,
        "parse_passed": parse_ok,
        "readonly_passed": readonly_ok,
        "strict_join_and_cte_passed": join_lint_ok,
        "failures": failures,
    }


def run_ehrsql_benchmark(
    *,
    data_dir: Path,
    output_json: Path,
    rebuild_db: bool = False,
    include_bird_mini_dev: bool = True,
    max_vm_steps: int = 50_000_000,
    timeout_s: float = 10.0,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """Download open MIMIC-IV demo + EHRSQL-2024, build SQLite DB, and run all 1,163 validation items."""
    t0 = time.perf_counter()
    data_dir.mkdir(parents=True, exist_ok=True)

    mimic_zip = data_dir / "mimic-iv-clinical-database-demo-2.2.zip"
    schema_sql = data_dir / "mimic_iv.sql"
    valid_annotated = data_dir / "valid_annotated.json"
    sqlite_path = data_dir / "mimic_iv.sqlite"

    mimic_zip_sha256 = _download_if_missing(MIMIC_IV_DEMO_URL, mimic_zip, timeout_s=120.0)
    schema_sha256 = _download_if_missing(EHRSQL_SCHEMA_URL, schema_sql, timeout_s=60.0)
    annotated_sha256 = _download_if_missing(EHRSQL_VALID_ANNOTATED_URL, valid_annotated, timeout_s=60.0)

    demo_root = _extract_mimic_demo(mimic_zip, data_dir)

    table_row_counts: dict[str, int]
    row_counts_cache = data_dir / "mimic_iv_row_counts.json"
    if rebuild_db or not sqlite_path.exists() or not row_counts_cache.exists():
        table_row_counts = build_ehrsql_mimic_iv_sqlite(demo_root, schema_sql, sqlite_path)
        row_counts_cache.write_text(
            json.dumps(table_row_counts, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    else:
        table_row_counts = json.loads(row_counts_cache.read_text(encoding="utf-8"))

    items = load_sql_benchmark_items("ehrsql-2024", valid_annotated)
    answerable_items = [it for it in items if not it.is_unanswerable]
    unanswerable_items = [it for it in items if it.is_unanswerable]

    outer_order_by_count = 0
    for it in answerable_items:
        stmts, err = check_parse(it.gold_sql)
        if not err and stmts and stmts[0].args.get("order") is not None:
            outer_order_by_count += 1

    candidates_map: dict[str, str | None] = {
        it.item_id: ("null" if it.is_unanswerable else it.gold_sql)
        for it in items
    }

    batch = evaluate_open_sql_batch(
        sqlite_path,
        items,
        candidates_map,
        strict_joins=True,
        allow_cross_join=False,
        max_vm_steps=max_vm_steps,
        timeout_s=timeout_s,
        max_rows=max_rows,
    )

    ans_passed = 0
    ans_ambiguous_gold = 0
    abs_passed = 0
    failures: list[dict[str, Any]] = []

    by_id = {it.item_id: it for it in items}
    for res in batch["results"]:
        it = by_id[res["item_id"]]
        if it.is_unanswerable:
            if res["passed"]:
                abs_passed += 1
            else:
                failures.append(
                    {
                        "item_id": it.item_id,
                        "is_unanswerable": True,
                        "layer": res["layer"],
                        "reason": res["reason"],
                    }
                )
        else:
            if res["passed"]:
                ans_passed += 1
                if res["reason"] == "ambiguous_gold":
                    ans_ambiguous_gold += 1
            else:
                failures.append(
                    {
                        "item_id": it.item_id,
                        "is_unanswerable": False,
                        "layer": res["layer"],
                        "reason": res["reason"],
                        "gold_sql": it.gold_sql,
                    }
                )

    bird_summary: dict[str, Any] | None = None
    if include_bird_mini_dev:
        bird_jsonl = data_dir / "mini_dev_sqlite.jsonl"
        bird_sha = _download_if_missing(BIRD_MINI_DEV_URL, bird_jsonl, timeout_s=60.0)
        bird_summary = _evaluate_bird_mini_dev_gold_static(
            bird_jsonl,
            bird_db_dir=REPO_ROOT / "data" / "bird_mini_dev" / "dev_databases",
        )
        bird_summary["jsonl_sha256"] = bird_sha

    elapsed_s = round(time.perf_counter() - t0, 3)
    report: dict[str, Any] = {
        "benchmark": "ehrsql_2024_real_mimic_iv_demo",
        "data_source": "real_downloaded",
        "command": "python scripts/run_ehrsql_real.py",
        "licenses": {
            "database": {
                "name": "MIMIC-IV Clinical Database Demo v2.2",
                "spdx_license": "ODbL-1.0",
                "url": MIMIC_IV_DEMO_URL,
                "zip_sha256": mimic_zip_sha256,
            },
            "questions_and_sql": {
                "name": "EHRSQL-2024 (glee4810/ehrsql-2024 valid/annotated.json)",
                "spdx_license": "CC-BY-4.0",
                "url": "https://github.com/glee4810/ehrsql-2024",
                "schema_sql_sha256": schema_sha256,
                "valid_annotated_sha256": annotated_sha256,
            },
        },
        "database_summary": {
            "num_tables": len(table_row_counts),
            "total_rows": sum(table_row_counts.values()),
            "table_row_counts": table_row_counts,
        },
        "execution_limits": {
            "max_vm_steps": max_vm_steps,
            "timeout_s": timeout_s,
            "max_rows": max_rows,
            "strict_joins": True,
            "allow_cross_join": False,
        },
        "ehrsql_2024_valid": {
            "total_items": len(items),
            "answerable_total": len(answerable_items),
            "answerable_outer_order_by": outer_order_by_count,
            "gold_vs_gold_passed": ans_passed,
            "gold_vs_gold_ambiguous_limit_ties": ans_ambiguous_gold,
            "gold_vs_gold_failed": len(answerable_items) - ans_passed,
            "unanswerable_total": len(unanswerable_items),
            "abstention_passed": abs_passed,
            "abstention_failed": len(unanswerable_items) - abs_passed,
            "stopped_by_layer": batch["stopped_by_layer"],
            "failures": failures,
        },
        "bird_mini_dev_sqlite": bird_summary,
        "runtime_seconds": elapsed_s,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build EHRSQL-2024 SQLite DB from open MIMIC-IV Demo v2.2 and run real gate verification."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=REPO_ROOT / "data" / "ehrsql_2024",
        help="Gitignored cache directory for MIMIC-IV Demo v2.2 and EHRSQL-2024 files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "results" / "ehrsql_2024_real.json",
        help="Output JSON report path (default: results/ehrsql_2024_real.json).",
    )
    parser.add_argument(
        "--rebuild-db",
        action="store_true",
        help="Force rebuilding mimic_iv.sqlite from raw MIMIC-IV Demo v2.2 CSVs.",
    )
    parser.add_argument(
        "--skip-bird-mini-dev",
        action="store_true",
        help="Skip fetching and checking BIRD Mini-Dev SQLite gold queries.",
    )
    parser.add_argument("--max-vm-steps", type=int, default=50_000_000)
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--max-rows", type=int, default=100_000)
    parser.add_argument("--json", action="store_true", help="Print full JSON report to stdout.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_ehrsql_benchmark(
        data_dir=args.data_dir,
        output_json=args.output,
        rebuild_db=args.rebuild_db,
        include_bird_mini_dev=not args.skip_bird_mini_dev,
        max_vm_steps=args.max_vm_steps,
        timeout_s=args.timeout_s,
        max_rows=args.max_rows,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        ehr = report["ehrsql_2024_valid"]
        db_sum = report["database_summary"]
        print(
            f"EHRSQL-2024 real MIMIC-IV Demo v2.2 ({db_sum['num_tables']} tables, "
            f"{db_sum['total_rows']} rows; DB license: ODbL-1.0, QA license: CC-BY-4.0)"
        )
        print(
            f"  Answerable gold-vs-gold: {ehr['gold_vs_gold_passed']}/{ehr['answerable_total']} passed "
            f"(LIMIT-cut tie ambiguous_gold={ehr['gold_vs_gold_ambiguous_limit_ties']})"
        )
        print(
            f"  Unanswerable abstention: {ehr['abstention_passed']}/{ehr['unanswerable_total']} passed"
        )
        if ehr["failures"]:
            print(f"  Failures ({len(ehr['failures'])}):")
            for f in ehr["failures"]:
                print(f"    - {f['item_id']}: layer={f['layer']} reason={f['reason']}")
        else:
            print("  Failures: 0")
        bird = report.get("bird_mini_dev_sqlite")
        if bird is not None:
            print(
                f"  BIRD Mini-Dev SQLite gold static/join audit: "
                f"{bird['strict_join_and_cte_passed']}/{bird['total_items']} passed "
                f"(failures={len(bird['failures'])})"
            )
        print(f"  Report written to: {args.output} ({report['runtime_seconds']}s)")

    ehr = report["ehrsql_2024_valid"]
    if ehr["gold_vs_gold_failed"] > 0 or ehr["abstention_failed"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
