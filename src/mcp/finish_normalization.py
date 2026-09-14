import argparse
import sqlite3
from pathlib import Path

from case_config import require_existing_case
from evidence_db import (
    connect_evidence_db,
    insert_normalized_event,
)
from normalizer import (
    discover_normalization_inputs,
    normalize_recmd,
    normalize_lecmd,
    normalize_hayabusa,
)


parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

CASE_DIR = require_existing_case(
    CASE
)

DB = (
    CASE_DIR
    / "evidence.db"
)

if not DB.is_file():
    raise RuntimeError(
        f"evidence.db missing: {DB}"
    )


SOURCE_ORDER = (
    "recmd",
    "lecmd",
    "hayabusa",
)


def source_count(
    conn,
    source_tool,
):

    return conn.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE source_tool = ?
        """,
        (source_tool,),
    ).fetchone()[0]


def existing_source_uids(
    conn,
    source_tool,
):

    return {
        row[0]
        for row in conn.execute(
            """
            SELECT event_uid
            FROM events
            WHERE source_tool = ?
            """,
            (source_tool,),
        )
    }


def normalize_source(
    source_tool,
    parser_input,
):

    if source_tool == "recmd":

        if not parser_input:
            return []

        return normalize_recmd(
            CASE,
            parser_input,
        )

    if source_tool == "lecmd":

        if not parser_input:
            return []

        return normalize_lecmd(
            CASE,
            parser_input,
        )

    if source_tool == "hayabusa":

        if not parser_input:
            return []

        return normalize_hayabusa(
            CASE,
            parser_input,
        )

    raise ValueError(
        f"Unsupported completion source: "
        f"{source_tool}"
    )


print(
    "=" * 72
)

print(
    "GENERIC FINAL NORMALIZATION / "
    "EVIDENCE COMPLETION"
)

print(
    "=" * 72
)

print()
print(
    f"Case: {CASE}"
)

discovered = (
    discover_normalization_inputs(
        CASE
    )
)

inputs = discovered[
    "inputs"
]

states = discovered[
    "states"
]

conn = connect_evidence_db(
    CASE
)

try:

    integrity_before = (
        conn.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
    )

    fk_before = list(
        conn.execute(
            "PRAGMA foreign_key_check"
        )
    )

    total_before = (
        conn.execute(
            "SELECT COUNT(*) "
            "FROM events"
        ).fetchone()[0]
    )

    unique_before = (
        conn.execute(
            """
            SELECT COUNT(
                DISTINCT event_uid
            )
            FROM events
            """
        ).fetchone()[0]
    )

    print()
    print(
        "BASELINE"
    )

    print(
        f"Events:      "
        f"{total_before:,}"
    )

    print(
        f"Unique UIDs: "
        f"{unique_before:,}"
    )

    print(
        f"Integrity:   "
        f"{integrity_before}"
    )

    print(
        f"FK errors:   "
        f"{len(fk_before)}"
    )

    if integrity_before != "ok":

        raise RuntimeError(
            "evidence.db integrity "
            "check failed before "
            "completion"
        )

    if fk_before:

        raise RuntimeError(
            "evidence.db has foreign "
            "key violations before "
            "completion"
        )

    if (
        total_before
        != unique_before
    ):

        raise RuntimeError(
            "Duplicate event_uid "
            "detected before "
            "completion"
        )

    print()
    print(
        "SOURCE COMPLETION"
    )

    total_inserted = 0

    source_results = {}

    for source_tool in (
        SOURCE_ORDER
    ):

        state = states.get(
            source_tool,
            "ABSENT",
        )

        parser_input = inputs.get(
            source_tool
        )

        current_count = (
            source_count(
                conn,
                source_tool,
            )
        )

        if state != "AVAILABLE":

            source_results[
                source_tool
            ] = {
                "state":
                    "SKIPPED_NO_SOURCE",
                "existing":
                    current_count,
                "normalized":
                    0,
                "inserted":
                    0,
            }

            print(
                f"{source_tool:10} "
                f"SKIP - NO SOURCE"
            )

            continue

        normalized_events = (
            normalize_source(
                source_tool,
                parser_input,
            )
        )

        normalized_uids = [
            event[
                "event_uid"
            ]
            for event
            in normalized_events
        ]

        if (
            len(normalized_uids)
            != len(
                set(
                    normalized_uids
                )
            )
        ):

            raise RuntimeError(
                f"{source_tool} "
                "normalizer produced "
                "duplicate event_uid "
                "values"
            )

        existing_uids = (
            existing_source_uids(
                conn,
                source_tool,
            )
        )

        missing_events = [
            event
            for event
            in normalized_events
            if (
                event["event_uid"]
                not in existing_uids
            )
        ]

        if not missing_events:

            source_results[
                source_tool
            ] = {
                "state":
                    "ALREADY_COMPLETE",
                "existing":
                    current_count,
                "normalized":
                    len(
                        normalized_events
                    ),
                "inserted":
                    0,
            }

            print(
                f"{source_tool:10} "
                f"ALREADY COMPLETE "
                f"({current_count:,})"
            )

            continue

        print(
            f"{source_tool:10} "
            f"MISSING "
            f"{len(missing_events):,} "
            f"EVENT(S)"
        )

        inserted = 0

        try:

            conn.execute(
                "BEGIN"
            )

            for event in (
                missing_events
            ):

                if (
                    event.get(
                        "case_id"
                    )
                    != CASE
                ):

                    raise RuntimeError(
                        "Normalized event "
                        "case_id mismatch"
                    )

                insert_normalized_event(
                    conn,
                    event,
                )

                inserted += 1

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        total_inserted += (
            inserted
        )

        source_results[
            source_tool
        ] = {
            "state":
                "COMPLETED_MISSING_EVENTS",
            "existing":
                current_count,
            "normalized":
                len(
                    normalized_events
                ),
            "inserted":
                inserted,
        }

        print(
            f"{source_tool:10} "
            f"INSERTED "
            f"{inserted:,}"
        )

    total_after = (
        conn.execute(
            "SELECT COUNT(*) "
            "FROM events"
        ).fetchone()[0]
    )

    unique_after = (
        conn.execute(
            """
            SELECT COUNT(
                DISTINCT event_uid
            )
            FROM events
            """
        ).fetchone()[0]
    )

    provenance_after = (
        conn.execute(
            """
            SELECT COUNT(*)
            FROM provenance
            """
        ).fetchone()[0]
    )

    integrity_after = (
        conn.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
    )

    fk_after = list(
        conn.execute(
            "PRAGMA foreign_key_check"
        )
    )

    print()
    print(
        "=" * 72
    )

    print(
        "FINAL EVIDENCE DATABASE"
    )

    print(
        "=" * 72
    )

    rows = conn.execute(
        """
        SELECT
            source_tool,
            COUNT(*)
        FROM events
        GROUP BY source_tool
        ORDER BY source_tool
        """
    ).fetchall()

    for (
        source_tool,
        count,
    ) in rows:

        print(
            f"{source_tool:12} "
            f"{count:,}"
        )

    print(
        "-" * 72
    )

    print(
        f"Total:       "
        f"{total_after:,}"
    )

    print(
        f"Unique UIDs: "
        f"{unique_after:,}"
    )

    print(
        f"Provenance:  "
        f"{provenance_after:,}"
    )

    print(
        f"Inserted:    "
        f"{total_inserted:,}"
    )

    print(
        f"Integrity:   "
        f"{integrity_after}"
    )

    print(
        f"FK errors:   "
        f"{len(fk_after)}"
    )

    if (
        total_after
        != unique_after
    ):

        raise RuntimeError(
            "Final event_uid "
            "uniqueness failure"
        )

    if integrity_after != "ok":

        raise RuntimeError(
            "Final SQLite "
            "integrity failure"
        )

    if fk_after:

        raise RuntimeError(
            "Final foreign-key "
            "validation failure"
        )

    if (
        provenance_after
        < total_after
    ):

        raise RuntimeError(
            "Final provenance "
            "coverage is lower "
            "than event count"
        )

finally:

    conn.close()


print()
print(
    "=" * 72
)

print(
    "NORMALIZATION / "
    "EVIDENCE COMPLETION: COMPLETE"
)

print(
    "=" * 72
)

print()
print(
    "Collection:      FROZEN"
)

print(
    "Parsing:         FROZEN"
)

print(
    "Evidence DB:     VALIDATED"
)

print(
    "Original evidence: UNTOUCHED"
)

print()
print(
    "NEXT PHASE: CORRELATION ENGINE"
)
