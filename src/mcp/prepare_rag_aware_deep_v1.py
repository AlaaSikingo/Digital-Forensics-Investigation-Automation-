import argparse
import json
import sqlite3
from pathlib import Path


WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")


def read_json(path):

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        return json.load(handle)


def atomic_write_json(
    path,
    payload,
):

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temp.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            payload,
            handle,
            ensure_ascii=False,
            indent=2,
        )

        handle.write("\n")

    temp.replace(path)


def open_readonly(path):

    uri = (
        "file:"
        + path.resolve().as_posix()
        + "?mode=ro"
    )

    conn = sqlite3.connect(
        uri,
        uri=True,
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA query_only = ON"
    )

    return conn


parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

if not CASE:

    raise RuntimeError(
        "Case ID cannot be empty"
    )


CASE_DIR = (
    WORKSPACE_ROOT
    / CASE
)

TRIAGE_DB = (
    CASE_DIR
    / "triage.db"
)

CONTEXT_DIR = (
    CASE_DIR
    / "investigation"
    / "contexts_v1"
)

CONTEXT_INDEX = (
    CONTEXT_DIR
    / "index.json"
)

RAG_RESULTS_DIR = (
    CASE_DIR
    / "investigation"
    / "rag_v1"
    / "results"
)

QWEN8_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen_v1"
)

OUTPUT_DIR = (
    CASE_DIR
    / "investigation"
    / "deep_ready_v1"
)


print("=" * 72)
print("RAG-AWARE DEEP PREPARATION V1")
print("=" * 72)

print()
print(f"Case:      {CASE}")
print(f"Triage:    {TRIAGE_DB}")
print(f"Contexts:  {CONTEXT_DIR}")
print(f"RAG:       {RAG_RESULTS_DIR}")
print(f"Existing8: {QWEN8_DIR}")
print(f"Output:    {OUTPUT_DIR}")


if not TRIAGE_DB.is_file():

    raise RuntimeError(
        f"Missing triage.db: "
        f"{TRIAGE_DB}"
    )


if not CONTEXT_INDEX.is_file():

    raise RuntimeError(
        f"Missing context index: "
        f"{CONTEXT_INDEX}"
    )


context_index = read_json(
    CONTEXT_INDEX
)

packages = (
    context_index.get(
        "packages",
        []
    )
)

context_map = {
    item["finding_id"]: item
    for item in packages
}


# ------------------------------------------------------------
# Detect existing valid 8B finding IDs.
# We do not modify or overwrite them.
# ------------------------------------------------------------

existing_8b_ids = set()

if QWEN8_DIR.is_dir():

    for path in QWEN8_DIR.glob(
        "*.json"
    ):

        if path.name.lower() == "index.json":
            continue

        try:

            payload = read_json(
                path
            )

            finding_id = (
                payload.get(
                    "analysis",
                    {}
                ).get(
                    "finding_id",
                    ""
                )
            )

            if finding_id:
                existing_8b_ids.add(
                    finding_id
                )

        except Exception:
            continue


# ------------------------------------------------------------
# Read triage database strictly read-only.
# Only findings explicitly requiring deep 8B are selected.
# ------------------------------------------------------------

conn = open_readonly(
    TRIAGE_DB
)

try:

    integrity = conn.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    if integrity != "ok":

        raise RuntimeError(
            "triage.db integrity failure"
        )


    run = conn.execute(
        """
        SELECT run_id
        FROM triage_runs
        WHERE case_id = ?
        ORDER BY created_utc DESC
        LIMIT 1
        """,
        (CASE,),
    ).fetchone()


    if run is None:

        raise RuntimeError(
            "No triage run found"
        )


    run_id = run["run_id"]


    rows = conn.execute(
        """
        SELECT
            finding_id,
            finding_type,
            severity,
            confidence,
            title,
            planned_route,
            status,
            routing_score
        FROM triage_routes
        WHERE run_id = ?
        ORDER BY
            routing_score DESC,
            finding_id
        """,
        (run_id,),
    ).fetchall()


finally:

    conn.close()


selected = []

for row in rows:

    finding_id = (
        row["finding_id"]
    )

    if finding_id in existing_8b_ids:
        continue


    deep_required = (
        row["status"]
        == "ESCALATE_8B"
        or (
            row["planned_route"]
            == "DEEP_8B"
            and row["status"]
            == "PENDING"
        )
    )


    if deep_required:

        selected.append(
            row
        )


print()
print("SELECTION")
print(
    f"Total triage findings: "
    f"{len(rows):,}"
)

print(
    f"Existing valid 8B:     "
    f"{len(existing_8b_ids):,}"
)

print(
    f"Pending deep 8B:       "
    f"{len(selected):,}"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


prepared_index = {
    "version": "1.0",
    "case_id": CASE,
    "purpose":
        "RAG-aware selective deep investigation preparation",
    "qwen_calls": 0,
    "historical_reference_is_case_fact": False,
    "selected_count":
        len(selected),
    "packages": [],
}


for position, row in enumerate(
    selected,
    start=1,
):

    finding_id = (
        row["finding_id"]
    )

    context_meta = (
        context_map.get(
            finding_id
        )
    )


    if context_meta is None:

        raise RuntimeError(
            "Context package missing for "
            f"{finding_id}"
        )


    context_path = (
        CONTEXT_DIR
        / context_meta["file"]
    )

    current_case_package = (
        read_json(
            context_path
        )
    )


    rag_candidates = list(
        RAG_RESULTS_DIR.glob(
            f"*{finding_id}*.json"
        )
    )


    historical_reference = None
    rag_file = None


    if rag_candidates:

        rag_path = (
            rag_candidates[0]
        )

        historical_reference = (
            read_json(
                rag_path
            )
        )

        rag_file = (
            rag_path.name
        )


    prepared = {

        "preparation_version":
            "1.0",

        "case_id":
            CASE,

        "finding_id":
            finding_id,

        "selection": {
            "severity":
                row["severity"],

            "confidence":
                row["confidence"],

            "planned_route":
                row["planned_route"],

            "triage_status":
                row["status"],

            "routing_score":
                row["routing_score"],

            "title":
                row["title"],
        },


        "current_case_evidence": {

            "authority":
                "CURRENT_CASE_EVIDENCE",

            "case_fact_eligible":
                True,

            "event_uid_grounding_required":
                True,

            "source_context_file":
                context_path.name,

            "package":
                current_case_package,
        },


        "historical_reference": {

            "authority":
                "HISTORICAL_REFERENCE_ONLY",

            "case_fact_eligible":
                False,

            "can_establish_maliciousness":
                False,

            "similarity_is_evidence":
                False,

            "investigation_sequence_is_authoritative_chronology":
                False,

            "analyst_validation_required":
                True,

            "source_rag_file":
                rag_file,

            "available":
                historical_reference
                is not None,

            "reference":
                historical_reference,
        },


        "analysis_guardrails": [

            "Current CASE evidence is authoritative for CASE facts.",

            "Every observed CASE fact must be grounded in event_uid values from current_case_evidence.",

            "Historical references are contextual knowledge only.",

            "Historical similarity cannot establish maliciousness.",

            "Historical reports cannot create new CASE events, users, IPs, commands, files, or timelines.",

            "Historical investigation_sequence must not be treated as authoritative chronology for this CASE.",

            "Hayabusa and EvtxECmd may describe the same underlying EVTX event and must not be counted as independent evidence.",

            "Preserve uncertainty and explicitly identify evidence gaps."
        ],
    }


    output_name = (
        f"{position:03d}_"
        f"{finding_id}.deep.json"
    )

    output_path = (
        OUTPUT_DIR
        / output_name
    )


    atomic_write_json(
        output_path,
        prepared,
    )


    prepared_index[
        "packages"
    ].append({

        "finding_id":
            finding_id,

        "severity":
            row["severity"],

        "title":
            row["title"],

        "triage_status":
            row["status"],

        "historical_reference":
            historical_reference
            is not None,

        "file":
            output_name,
    })


atomic_write_json(
    OUTPUT_DIR
    / "index.json",
    prepared_index,
)


print()
print("=" * 72)
print("DEEP PREPARATION RESULTS")
print("=" * 72)

print(
    f"Prepared packages: "
    f"{len(selected):,}"
)

print(
    f"Qwen calls:        0"
)

print(
    f"Existing 8B preserved: "
    f"{len(existing_8b_ids):,}"
)

print(
    f"Triage DB integrity: "
    f"{integrity}"
)

print()
print(
    "Current evidence authority: YES"
)

print(
    "Historical refs case facts: NO"
)

print(
    "Historical similarity proof: NO"
)

print()
print("=" * 72)
print("RAG-AWARE DEEP PREPARATION V1: COMPLETE")
print("=" * 72)
