import sqlite3
from pathlib import Path
from typing import Any


from evidence_db import canonical_timestamp_sort

WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace").resolve()


def connect_readonly(case_id: str):

    db_path = (
        WORKSPACE_ROOT /
        case_id /
        "evidence.db"
    ).resolve()

    try:
        db_path.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise ValueError(
            "Database path escapes workspace root"
        )

    if not db_path.is_file():
        raise FileNotFoundError(
            f"Evidence database does not exist: {db_path}"
        )

    uri = db_path.as_uri() + "?mode=ro"

    conn = sqlite3.connect(
        uri,
        uri=True,
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA query_only = ON"
    )

    return conn


def get_event(
    case_id: str,
    event_uid: str,
) -> dict[str, Any] | None:

    conn = connect_readonly(case_id)

    try:

        row = conn.execute(
            """
            SELECT *
            FROM events
            WHERE event_uid = ?
            """,
            (event_uid,),
        ).fetchone()

        if row is None:
            return None

        result = dict(row)

        attributes = conn.execute(
            """
            SELECT
                attribute_key,
                attribute_value
            FROM attributes
            WHERE event_uid = ?
            ORDER BY attribute_key
            """,
            (event_uid,),
        ).fetchall()

        result["attributes"] = {
            r["attribute_key"]:
                r["attribute_value"]
            for r in attributes
        }

        provenance = conn.execute(
            """
            SELECT
                parser,
                parser_output,
                source_evidence,
                source_row
            FROM provenance
            WHERE event_uid = ?
            """,
            (event_uid,),
        ).fetchone()

        result["provenance"] = (
            dict(provenance)
            if provenance
            else None
        )

        return result

    finally:
        conn.close()


def events_by_time(
    case_id: str,
    start_time: str,
    end_time: str,
    *,
    limit: int = 1000,
) -> list[dict[str, Any]]:

    if limit < 1 or limit > 10000:
        raise ValueError(
            "limit must be between 1 and 10000"
        )

    start_sort = canonical_timestamp_sort(
        start_time
    )

    end_sort = canonical_timestamp_sort(
        end_time
    )

    if start_sort > end_sort:
        raise ValueError(
            "start_time must not be after end_time"
        )

    conn = connect_readonly(case_id)

    try:

        rows = conn.execute(
            """
            SELECT
                event_uid,
                timestamp,
                timestamp_type,
                artifact_type,
                event_type,
                source_tool,
                hostname,
                username,
                executable,
                path,
                target_path,
                windows_event_id,
                provider,
                channel,
                detection_rule,
                severity,
                description
            FROM events
            WHERE timestamp_sort >= ?
              AND timestamp_sort <= ?
            ORDER BY timestamp_sort, event_uid
            LIMIT ?
            """,
            (
                start_sort,
                end_sort,
                limit,
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        conn.close()


def events_by_artifact(
    case_id: str,
    artifact_type: str,
    *,
    limit: int = 1000,
) -> list[dict[str, Any]]:

    if limit < 1 or limit > 10000:
        raise ValueError(
            "limit must be between 1 and 10000"
        )

    conn = connect_readonly(case_id)

    try:

        rows = conn.execute(
            """
            SELECT
                event_uid,
                timestamp,
                artifact_type,
                event_type,
                source_tool,
                description
            FROM events
            WHERE artifact_type = ?
            ORDER BY timestamp
            LIMIT ?
            """,
            (
                artifact_type,
                limit,
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        conn.close()


def windows_events(
    case_id: str,
    *,
    event_id: str | None = None,
    provider: str | None = None,
    channel: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:

    if limit < 1 or limit > 10000:
        raise ValueError(
            "limit must be between 1 and 10000"
        )

    clauses = [
        "artifact_type = 'evtx'"
    ]

    params: list[Any] = []

    if event_id is not None:
        clauses.append(
            "windows_event_id = ?"
        )
        params.append(event_id)

    if provider is not None:
        clauses.append(
            "provider = ?"
        )
        params.append(provider)

    if channel is not None:
        clauses.append(
            "channel = ?"
        )
        params.append(channel)

    params.append(limit)

    sql = """
        SELECT
            event_uid,
            timestamp,
            hostname,
            windows_event_id,
            provider,
            channel,
            username,
            process_id,
            description
        FROM events
        WHERE
    """

    sql += " AND ".join(clauses)

    sql += """
        ORDER BY timestamp
        LIMIT ?
    """

    conn = connect_readonly(case_id)

    try:

        rows = conn.execute(
            sql,
            params,
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        conn.close()



