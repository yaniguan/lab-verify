"""Strict layered gate for text-to-SQL candidates on a toy lab database.

Each candidate query from candidates.json goes through four layers and stops
at the first one it fails:
  1 parse     - sqlglot parses it (sqlite dialect)
  2 read-only - exactly one statement, and it is a SELECT
  3 schema    - every table and column exists
  4 execution - result multiset equals the gold query's result
The database is in-memory and filled with hand-written SYNTHETIC rows.
"""
import json
import sqlite3
from collections import Counter
from pathlib import Path

import sqlglot
from sqlglot import exp

SCHEMA = {
    "experiments": ["id", "date", "operator", "protocol", "temperature_c", "yield_pct", "status"],
    "samples": ["id", "experiment_id", "well", "reagent", "volume_ul"],
    "instruments": ["id", "name", "last_calibrated"],
}

# SYNTHETIC data: invented, deterministic rows (12 + 14 + 4 = 30), not real lab records.
EXPERIMENTS = [
    (1, "2026-02-10", "Kim", "PCR", 37.0, 82.5, "done"),
    (2, "2026-02-14", "Patel", "ELISA", 25.0, 64.0, "done"),
    (3, "2026-02-20", "Novak", "Western", 4.0, 41.0, "failed"),
    (4, "2026-03-02", "Kim", "PCR", 42.0, 91.0, "done"),
    (5, "2026-03-05", "Patel", "PCR", 37.0, 55.5, "failed"),
    (6, "2026-03-11", "Novak", "ELISA", 25.0, 70.0, "done"),
    (7, "2026-03-18", "Kim", "Western", 4.0, 38.0, "running"),
    (8, "2026-03-27", "Patel", "ELISA", 30.0, 77.0, "done"),
    (9, "2026-04-03", "Novak", "PCR", 45.0, 88.0, "done"),
    (10, "2026-04-09", "Kim", "ELISA", 25.0, 59.5, "failed"),
    (11, "2026-04-15", "Patel", "Western", 4.0, 47.0, "done"),
    (12, "2026-04-22", "Novak", "PCR", 39.0, 73.0, "running"),
]
SAMPLES = [
    (101, 1, "A1", "Taq", 20.0), (102, 1, "A2", "Taq", 20.0),
    (103, 2, "B1", "Antibody-X", 50.0), (104, 4, "A3", "Taq", 25.0),
    (105, 4, "A4", "Polymerase-Q", 25.0), (106, 4, "A5", "Taq", 25.0),
    (107, 5, "C1", "Taq", 20.0), (108, 6, "B2", "Antibody-Y", 50.0),
    (109, 7, "D1", "Blocking buffer", 100.0), (110, 9, "A6", "Polymerase-Q", 30.0),
    (111, 9, "A7", "Polymerase-Q", 30.0), (112, 10, "B3", "Antibody-X", 40.0),
    (113, 12, "A8", "Taq", 22.5), (114, 12, "A9", "Polymerase-Q", 22.5),
]
INSTRUMENTS = [
    (1, "Thermocycler T1", "2026-01-15"), (2, "Plate reader P2", "2026-07-02"),
    (3, "Imager G3", "2026-05-20"), (4, "Pipette robot R4", "2026-09-30"),
]
LAYERS = ["parse", "read-only", "schema", "execution"]


def build_db():
    """Create the in-memory database and lock it to read-only queries."""
    con = sqlite3.connect(":memory:")
    for table, cols in SCHEMA.items():
        con.execute(f"CREATE TABLE {table} ({', '.join(cols)})")
    for table, rows in [("experiments", EXPERIMENTS), ("samples", SAMPLES), ("instruments", INSTRUMENTS)]:
        marks = ", ".join("?" * len(rows[0]))
        con.executemany(f"INSERT INTO {table} VALUES ({marks})", rows)
    con.commit()
    con.execute("PRAGMA query_only = ON")  # extra safety on top of layer 2
    return con


def check_parse(sql):
    try:
        return [s for s in sqlglot.parse(sql, read="sqlite") if s is not None], None
    except sqlglot.errors.ParseError as e:
        return None, str(e).splitlines()[0]


def check_read_only(stmts):
    if len(stmts) != 1:
        return f"{len(stmts)} statements ({', '.join(type(s).__name__ for s in stmts)})"
    if not isinstance(stmts[0], (exp.Select, exp.SetOperation)):
        return f"{type(stmts[0]).__name__} statement"
    return None


def check_schema(stmt):
    aliases = {}
    for t in stmt.find_all(exp.Table):
        if t.name not in SCHEMA:
            return f"unknown table {t.name}"
        aliases[t.name] = t.name
        if t.alias:
            aliases[t.alias] = t.name
    used_cols = {c for t in set(aliases.values()) for c in SCHEMA[t]}
    output_aliases = {a.alias for a in stmt.find_all(exp.Alias)}
    for c in stmt.find_all(exp.Column):
        if c.table:
            table = aliases.get(c.table)
            if table is None:
                return f"unknown table alias {c.table}"
            if c.name not in SCHEMA[table]:
                return f"unknown column {table}.{c.name}"
        elif c.name not in used_cols and c.name not in output_aliases:
            return f"unknown column {c.name} in {', '.join(sorted(set(aliases.values())))}"
    return None


def run(con, sql):
    rows = con.execute(sql).fetchall()
    return Counter(tuple(round(v, 6) if isinstance(v, float) else v for v in r) for r in rows)


def gate(con, sql, gold_result):
    """Return (index of first failed layer or None, reason)."""
    stmts, err = check_parse(sql)
    if err:
        return 0, err
    err = check_read_only(stmts)
    if err:
        return 1, err
    err = check_schema(stmts[0])
    if err:
        return 2, err
    try:
        got = run(con, sql)
    except sqlite3.Error as e:
        return 3, f"sqlite error: {e}"
    if got != gold_result:
        n_got, n_gold = sum(got.values()), sum(gold_result.values())
        if n_got == n_gold == 1:
            return 3, f"value {list(got)[0]} vs gold {list(gold_result)[0]}"
        return 3, f"{n_got} rows vs {n_gold} gold rows"
    return None, "match"


def main():
    items = json.loads((Path(__file__).parent / "candidates.json").read_text())
    con = build_db()
    print("Toy lab database with SYNTHETIC data: "
          f"{len(EXPERIMENTS)} experiments, {len(SAMPLES)} samples, {len(INSTRUMENTS)} instruments.")
    print(f"{len(items)} questions, {sum(len(i['candidates']) for i in items)} candidates\n")
    print(f"{'q':>2}  {'label':<24} {'first failed layer':<20} reason")
    print("-" * 96)

    fails = Counter()
    wrong = passed = passed_wrong = passed_static_wrong = agree = 0
    for item in items:
        gold = run(con, item["gold"])
        for cand in item["candidates"]:
            layer, reason = gate(con, cand["sql"], gold)
            is_wrong = cand["label"] != "correct"
            shown = "PASS" if layer is None else f"{layer + 1} {LAYERS[layer]}"
            print(f"{item['qid']:>2}  {cand['label']:<24} {shown:<20} {reason[:48]}")
            wrong += is_wrong
            agree += is_wrong == (layer is not None)
            if layer is None:
                passed += 1
                passed_wrong += is_wrong
            else:
                fails[layer] += 1
            if is_wrong and (layer is None or layer == 3):
                passed_static_wrong += 1

    total = sum(len(i["candidates"]) for i in items)
    print("\nCandidates stopped at each layer:")
    for i, name in enumerate(LAYERS):
        print(f"  layer {i + 1} {name:<10} {fails[i]}")
    print(f"  passed all     {passed}")
    print(f"\nGate verdict agrees with hand label: {agree}/{total}")
    print(f"Wrong candidates: {wrong}; wrong ones passing the full gate: {passed_wrong}")
    print(f"Wrong candidates that would pass with layers 1-3 only: {passed_static_wrong}/{wrong}")


if __name__ == "__main__":
    main()
