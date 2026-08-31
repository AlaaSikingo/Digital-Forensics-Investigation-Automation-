import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from evidence_db import (
    connect_evidence_db,
    insert_normalized_event,
    insert_normalized_event_batch,
)

from normalizer import (
    discover_normalization_inputs,
    iter_evtxecmd,
    iter_mftecmd,
    iter_pecmd,
)


DEFAULT_BATCH_SIZE = 5000
MFT_BATCH_SIZE = 50000


class ImportSafetyRefusal(RuntimeError):
    """Expected safety refusal that must not mutate import state."""

    pass


# ============================================================
# ADAPTER REGISTRY
# ============================================================

ADAPTERS = {
    "mftecmd": iter_mftecmd,
    "evtxecmd": iter_evtxecmd,
    "pecmd": iter_pecmd,
}


def _file_identity(
    path: str,
) -> tuple[str, int]:

    source = Path(path).resolve()

    if not source.is_file():
        raise RuntimeError(
            f"Import source does not exist: {source}"
        )

    digest = hashlib.sha256()
    size = 0

    with source.open("rb") as handle:

        while True:

            block = handle.read(
                1024 * 1024
            )

            if not block:
                break

            digest.update(block)
            size += len(block)

    return digest.hexdigest(), size


def _utc_now() -> str:

    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _make_import_id(
    case_id: str,
    source_tool: str,
    parser_output: str,
) -> str:

    identity = (
        f"{case_id}|"
        f"{source_tool}|"
        f"{Path(parser_output).resolve()}"
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def _event_exists(
    conn,
    event_uid: str,
) -> bool:

    row = conn.execute(
        """
        SELECT 1
        FROM events
        WHERE event_uid = ?
        LIMIT 1
        """,
        (event_uid,),
    ).fetchone()

    return row is not None


def _get_adapter(
    source_tool: str,
) -> Callable:

    adapter = ADAPTERS.get(source_tool)

    if adapter is None:
        raise ValueError(
            f"Unsupported evidence source: {source_tool}"
        )

    return adapter


def _resolve_parser_output(
    case_id: str,
    source_tool: str,
) -> str:

    discovered = discover_normalization_inputs(
        case_id
    )

    parser_output = discovered[
        "inputs"
    ].get(source_tool)

    if parser_output is None:
        raise RuntimeError(
            f"No parser output discovered for {source_tool}"
        )

    if isinstance(parser_output, list):
        raise RuntimeError(
            f"{source_tool} has multiple parser outputs. "
            "Multi-source adapters are not enabled yet."
        )

    return str(
        Path(parser_output).resolve()
    )


# ============================================================
# GENERIC IMPORT CONTROLLER
# ============================================================

def import_evidence_source(
    case_id: str,
    source_tool: str,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_rows: int | None = None,
) -> dict:

    source_tool = str(
        source_tool
    ).strip().lower()

    if batch_size < 1:
        raise ValueError(
            "batch_size must be greater than zero"
        )

    adapter = _get_adapter(
        source_tool
    )

    parser_output = _resolve_parser_output(
        case_id,
        source_tool,
    )

    source_sha256, source_size = _file_identity(
        parser_output
    )

    import_id = _make_import_id(
        case_id,
        source_tool,
        parser_output,
    )

    conn = connect_evidence_db(
        case_id
    )

    inserted_this_run = 0
    skipped_duplicates = 0
    batch_events = 0
    pending_events = []

    # A batch may exceed batch_size, but a checkpoint must
    # never split events emitted from the same source row.
    batch_last_source_row = None

    last_source_row = None

    previous_last_row = None
    previous_rows = 0
    previous_events = 0

    resume_start_row = 2

    try:

        existing_import = conn.execute(
            """
            SELECT
                status,
                source_rows_processed,
                normalized_events_inserted,
                last_source_row,
                source_sha256,
                source_size
            FROM imports
            WHERE import_id = ?
            """,
            (import_id,),
        ).fetchone()

        if existing_import:

            (
                previous_status,
                previous_rows,
                previous_events,
                previous_last_row,
                previous_sha256,
                previous_size,
            ) = existing_import

            if (
                not previous_sha256
                or previous_size is None
            ):
                raise ImportSafetyRefusal(
                    "Existing import checkpoint has no "
                    "source identity. Refusing unsafe resume."
                )

            if previous_sha256 != source_sha256:
                raise ImportSafetyRefusal(
                    "Import source SHA256 changed. "
                    "Refusing checkpoint resume."
                )

            if int(previous_size) != source_size:
                raise ImportSafetyRefusal(
                    "Import source size changed. "
                    "Refusing checkpoint resume."
                )

            if (
                previous_status == "COMPLETED"
                and max_rows is None
            ):
                raise ImportSafetyRefusal(
                    f"{source_tool} production import is "
                    "already marked COMPLETED"
                )

            print(
                "Existing import state:",
                previous_status,
            )

            print(
                "Previous events:",
                previous_events,
            )

            print(
                "Previous last row:",
                previous_last_row,
            )

            if previous_last_row is not None:
                resume_start_row = (
                    int(previous_last_row) + 1
                )

            print(
                "Resume start row:",
                resume_start_row,
            )

        else:

            now = _utc_now()

            conn.execute(
                """
                INSERT INTO imports(
                    import_id,
                    case_id,
                    source_tool,
                    parser_output,
                    status,
                    started_at,
                    updated_at,
                    completed_at,
                    source_rows_processed,
                    normalized_events_inserted,
                    last_source_row,
                    error_message,
                    source_sha256,
                    source_size
                )
                VALUES (
                    ?, ?, ?, ?,
                    'RUNNING',
                    ?, ?,
                    NULL,
                    0, 0,
                    NULL,
                    NULL,
                    ?, ?
                )
                """,
                (
                    import_id,
                    case_id,
                    source_tool,
                    parser_output,
                    now,
                    now,
                    source_sha256,
                    source_size,
                ),
            )

            conn.commit()

        conn.execute(
            """
            UPDATE imports
            SET
                status = 'RUNNING',
                updated_at = ?,
                completed_at = NULL,
                error_message = NULL
            WHERE import_id = ?
            """,
            (
                _utc_now(),
                import_id,
            ),
        )

        conn.commit()

        conn.execute("BEGIN")

        for event in adapter(
            case_id,
            parser_output,
            max_rows=max_rows,
            start_row=resume_start_row,
        ):

            if event.get("source_tool") != source_tool:
                raise RuntimeError(
                    "Adapter source_tool mismatch: "
                    f"expected {source_tool}, "
                    f"received {event.get('source_tool')}"
                )

            provenance = event.get(
                "provenance"
            )

            if not isinstance(
                provenance,
                dict,
            ):
                raise RuntimeError(
                    "Normalized event has invalid provenance"
                )

            source_row = int(
                provenance["source_row"]
            )

            if source_row < resume_start_row:
                raise RuntimeError(
                    "Adapter emitted a source row before "
                    "the requested checkpoint"
                )

            # Commit only at a source-row boundary.
            #
            # If the previous row caused the batch threshold to
            # be reached/exceeded, all events from that row have
            # already been consumed. The first event from this new
            # row is therefore the safe point to checkpoint.
            if (
                batch_events >= batch_size
                and batch_last_source_row is not None
                and source_row != batch_last_source_row
            ):

                bulk_result = (
                    insert_normalized_event_batch(
                        conn,
                        pending_events,
                    )
                )

                inserted_this_run += (
                    bulk_result["inserted"]
                )

                skipped_duplicates += (
                    bulk_result["duplicates"]
                )

                pending_events = []

                total_events = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM events
                    WHERE source_tool = ?
                    """,
                    (source_tool,),
                ).fetchone()[0]

                conn.execute(
                    """
                    UPDATE imports
                    SET
                        status = 'RUNNING',
                        updated_at = ?,
                        source_rows_processed = ?,
                        normalized_events_inserted = ?,
                        last_source_row = ?,
                        error_message = NULL
                    WHERE import_id = ?
                    """,
                    (
                        _utc_now(),
                        max(
                            0,
                            batch_last_source_row - 1,
                        ),
                        total_events,
                        batch_last_source_row,
                        import_id,
                    ),
                )

                conn.commit()

                print(
                    f"Committed [{source_tool}]: "
                    f"{total_events:,} total events | "
                    f"source row {batch_last_source_row:,} | "
                    f"duplicates skipped "
                    f"{skipped_duplicates:,}"
                )

                conn.execute("BEGIN")

                batch_events = 0
                batch_last_source_row = None
                pending_events = []

            last_source_row = source_row

            pending_events.append(
                event
            )

            batch_events += 1
            batch_last_source_row = source_row


        if pending_events:

            bulk_result = (
                insert_normalized_event_batch(
                    conn,
                    pending_events,
                )
            )

            inserted_this_run += (
                bulk_result["inserted"]
            )

            skipped_duplicates += (
                bulk_result["duplicates"]
            )

            pending_events = []

        total_events = conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE source_tool = ?
            """,
            (source_tool,),
        ).fetchone()[0]

        effective_last_source_row = (
            last_source_row
            if last_source_row is not None
            else previous_last_row
        )

        source_rows_processed = (
            max(
                0,
                effective_last_source_row - 1,
            )
            if effective_last_source_row is not None
            else 0
        )

        final_status = (
            "PARTIAL"
            if max_rows is not None
            else "COMPLETED"
        )

        completed_at = (
            _utc_now()
            if final_status == "COMPLETED"
            else None
        )

        conn.execute(
            """
            UPDATE imports
            SET
                status = ?,
                updated_at = ?,
                completed_at = ?,
                source_rows_processed = ?,
                normalized_events_inserted = ?,
                last_source_row = ?,
                error_message = NULL
            WHERE import_id = ?
            """,
            (
                final_status,
                _utc_now(),
                completed_at,
                source_rows_processed,
                total_events,
                effective_last_source_row,
                import_id,
            ),
        )

        conn.commit()

        return {
            "success": True,
            "case_id": case_id,
            "source_tool": source_tool,
            "import_id": import_id,
            "status": final_status,
            "parser_output": parser_output,
            "source_sha256": source_sha256,
            "source_size": source_size,
            "inserted_this_run":
                inserted_this_run,
            "duplicates_skipped":
                skipped_duplicates,
            "total_events":
                total_events,
            "source_rows_processed":
                source_rows_processed,
            "last_source_row":
                effective_last_source_row,
        }

    except ImportSafetyRefusal:

        # Expected refusal before import execution.
        # Never mutate the existing checkpoint.
        try:
            conn.rollback()
        except Exception:
            pass

        raise

    except Exception as exc:

        try:
            conn.rollback()

            conn.execute(
                """
                UPDATE imports
                SET
                    status = 'FAILED',
                    updated_at = ?,
                    error_message = ?
                WHERE import_id = ?
                """,
                (
                    _utc_now(),
                    str(exc),
                    import_id,
                ),
            )

            conn.commit()

        except Exception:
            pass

        raise

    finally:
        conn.close()


# ============================================================
# COMPATIBILITY WRAPPERS
# ============================================================

def import_mftecmd(
    case_id: str,
    *,
    batch_size: int = MFT_BATCH_SIZE,
    max_rows: int | None = None,
) -> dict:

    result = import_evidence_source(
        case_id,
        "mftecmd",
        batch_size=batch_size,
        max_rows=max_rows,
    )

    # Preserve the historical MFTECmd return key for callers
    # that still depend on it.
    result["total_mftecmd_events"] = result[
        "total_events"
    ]

    return result


def import_evtxecmd(
    case_id: str,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_rows: int | None = None,
) -> dict:

    return import_evidence_source(
        case_id,
        "evtxecmd",
        batch_size=batch_size,
        max_rows=max_rows,
    )
