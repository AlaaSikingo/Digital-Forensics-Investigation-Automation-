import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


MCP_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")


from policy import validate_case_id
from triage_collector import collect_triage_artifacts
from triage_parser import parse_triage_artifacts
from evidence_db import (
    create_evidence_db,
    create_secondary_indexes,
)
from evidence_importer import import_evidence_source


SOURCES = (
    "mftecmd",
    "evtxecmd",
    "pecmd",
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def atomic_json(path, payload):

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    temp.replace(path)


def marker_complete(path):

    if not path.is_file():
        return False

    try:

        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        return (
            payload.get("status")
            == "COMPLETE"
        )

    except Exception:

        return False


def write_marker(
    path,
    stage,
    extra=None,
):

    payload = {
        "stage":
            stage,

        "case_id":
            CASE,

        "status":
            "COMPLETE",

        "completed_utc":
            utc_now(),
    }

    if extra:
        payload.update(extra)

    atomic_json(
        path,
        payload,
    )


def sqlite_event_count(db_path):

    if not db_path.is_file():
        return 0

    uri = (
        "file:"
        + db_path.resolve().as_posix()
        + "?mode=ro"
    )

    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=10,
    )

    try:

        return conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

    finally:

        conn.close()


parser = argparse.ArgumentParser(
    description=(
        "Prepare a new DFIR-AI case from "
        "a forensic image."
    )
)

parser.add_argument(
    "--case",
    required=True,
)

parser.add_argument(
    "--image",
    required=True,
)

parser.add_argument(
    "--profile",
    default="windows_standard",
)

args = parser.parse_args()


CASE = validate_case_id(
    args.case.strip()
)

IMAGE = Path(
    args.image
).resolve()

PROFILE = args.profile.strip()


if not IMAGE.is_file():

    raise RuntimeError(
        f"Forensic image does not exist: "
        f"{IMAGE}"
    )


CASE_DIR = (
    WORKSPACE_ROOT
    / CASE
)

STATE_DIR = (
    CASE_DIR
    / ".pipeline_state"
)

COLLECT_MARKER = (
    STATE_DIR
    / "collection.json"
)

PARSE_MARKER = (
    STATE_DIR
    / "parsing.json"
)

DB_MARKER = (
    STATE_DIR
    / "evidence_db_created.json"
)

IMPORT_MARKER = (
    STATE_DIR
    / "base_import.json"
)

EVIDENCE_DB = (
    CASE_DIR
    / "evidence.db"
)


print("=" * 72)
print("DFIR-AI NEW CASE PREPARATION V1")
print("=" * 72)

print()
print(f"Case:    {CASE}")
print(f"Image:   {IMAGE}")
print(f"Profile: {PROFILE}")


# ============================================================
# 1. COLLECTION
# ============================================================

print()
print("=" * 72)
print("STAGE 1 - COLLECTION")
print("=" * 72)


if marker_complete(
    COLLECT_MARKER
):

    print(
        "Collection: SKIP "
        "(completion marker)"
    )

else:

    result = collect_triage_artifacts(
        str(IMAGE),
        CASE,
        PROFILE,
    )

    if not result.get(
        "success"
    ):

        raise RuntimeError(
            "Collection failed: "
            + json.dumps(
                result,
                ensure_ascii=False,
            )
        )

    failure_count = int(
        result.get(
            "failure_count"
        )
        or 0
    )

    collector_status = (
        "PARTIAL_SUCCESS"
        if failure_count > 0
        else "SUCCESS"
    )

    write_marker(
        COLLECT_MARKER,
        "collection",
        {
            "source_image":
                str(IMAGE),

            "profile":
                PROFILE,

            "collector_status":
                collector_status,

            "artifact_count":
                result.get(
                    "artifact_count"
                ),

            "failure_count":
                failure_count,

            "original_evidence_modified":
                False,
        },
    )

    print(
        "Collection: "
        + collector_status
    )


# ============================================================
# 2. PARSING
# ============================================================

print()
print("=" * 72)
print("STAGE 2 - PARSING")
print("=" * 72)


if marker_complete(
    PARSE_MARKER
):

    print(
        "Parsing: SKIP "
        "(completion marker)"
    )

else:

    result = parse_triage_artifacts(
        CASE
    )

    if result.get(
        "status"
    ) not in (
        "SUCCESS",
        "PARTIAL_SUCCESS",
    ):

        raise RuntimeError(
            "Parsing failed: "
            + json.dumps(
                result,
                ensure_ascii=False,
            )
        )

    write_marker(
        PARSE_MARKER,
        "parsing",
        {
            "parser_status":
                result.get(
                    "status"
                )
        },
    )

    print(
        "Parsing: COMPLETE"
    )


# ============================================================
# 3. EVIDENCE DATABASE
# ============================================================

print()
print("=" * 72)
print("STAGE 3 - EVIDENCE DATABASE")
print("=" * 72)


if EVIDENCE_DB.is_file():

    print(
        "evidence.db: EXISTS"
    )

    if not marker_complete(
        DB_MARKER
    ):

        write_marker(
            DB_MARKER,
            "evidence_db_created",
            {
                "bootstrap":
                    True
            },
        )

else:

    result = create_evidence_db(
        CASE,
        defer_indexes=True,
    )

    write_marker(
        DB_MARKER,
        "evidence_db_created",
        {
            "database":
                result.get(
                    "database"
                )
        },
    )

    print(
        "evidence.db: CREATED"
    )


# ============================================================
# 4. BASE NORMALIZATION / IMPORT
# ============================================================

print()
print("=" * 72)
print("STAGE 4 - BASE NORMALIZATION / IMPORT")
print("=" * 72)


if marker_complete(
    IMPORT_MARKER
):

    print(
        "Base import: SKIP "
        "(completion marker)"
    )

else:

    import_results = {}

    for number, source in enumerate(
        SOURCES,
        start=1,
    ):

        print()
        print(
            f"[{number}/{len(SOURCES)}] "
            f"Importing {source}..."
        )

        if source == "pecmd":

            pecmd_dir = (
                CASE_DIR
                / "parsed"
                / "pecmd"
            )

            pecmd_outputs = [
                p
                for p in pecmd_dir.glob(
                    "pecmd_*.csv"
                )
                if (
                    p.is_file()
                    and not p.name.lower().endswith(
                        "_timeline.csv"
                    )
                )
            ]

            if not pecmd_outputs:

                print(
                    "pecmd: SKIP "
                    "(no Prefetch evidence)"
                )

                import_results[source] = {
                    "status":
                        "SKIPPED_NO_SOURCE",

                    "normalized_events_inserted":
                        0,

                    "source_rows_processed":
                        0,
                }

                continue

        batch_size = (
            50000
            if source == "mftecmd"
            else 5000
        )

        result = import_evidence_source(
            CASE,
            source,
            batch_size=batch_size,
        )

        status = result.get(
            "status"
        )

        if status not in (
            "COMPLETED",
            "ALREADY_COMPLETED",
        ):

            raise RuntimeError(
                f"{source} import failed "
                f"with status: {status}"
            )

        import_results[source] = {
            "status":
                status,

            "normalized_events_inserted":
                result.get(
                    "normalized_events_inserted"
                ),

            "source_rows_processed":
                result.get(
                    "source_rows_processed"
                ),
        }

        print(
            f"{source}: {status}"
        )


    print()
    print(
        "Creating deferred secondary indexes..."
    )

    index_result = create_secondary_indexes(
        CASE
    )

    print(
        "Secondary indexes: COMPLETE "
        f"({index_result['secondary_indexes']})"
    )

    total_events = sqlite_event_count(
        EVIDENCE_DB
    )

    if total_events <= 0:

        raise RuntimeError(
            "Base import completed but "
            "evidence.db contains no events."
        )


    write_marker(
        IMPORT_MARKER,
        "base_import",
        {
            "sources":
                import_results,

            "total_events":
                total_events,
        },
    )

    print()
    print(
        f"Base import: COMPLETE"
    )

    print(
        f"Evidence events: "
        f"{total_events:,}"
    )


# ============================================================
# RESULT
# ============================================================

total_events = sqlite_event_count(
    EVIDENCE_DB
)


print()
print("=" * 72)
print("NEW CASE PREPARATION RESULT")
print("=" * 72)

print()
print(
    f"Case:            {CASE}"
)

print(
    f"Evidence DB:     {EVIDENCE_DB}"
)

print(
    f"Evidence events: {total_events:,}"
)

print()
print(
    "Original evidence modified: NEVER"
)

print(
    "Qwen calls: 0"
)

print(
    "Ready for run_case_v2.py: YES"
)

print()
print("=" * 72)
print("DFIR-AI NEW CASE PREPARATION V1: COMPLETE")
print("=" * 72)

