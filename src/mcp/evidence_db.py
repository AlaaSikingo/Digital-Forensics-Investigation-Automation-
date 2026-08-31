import sqlite3
from pathlib import Path


SCHEMA_VERSION = "1.0"
WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace").resolve()


SECONDARY_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_artifact_type
    ON events(artifact_type);

CREATE INDEX IF NOT EXISTS idx_events_event_type
    ON events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_hostname
    ON events(hostname);

CREATE INDEX IF NOT EXISTS idx_events_username
    ON events(username);

CREATE INDEX IF NOT EXISTS idx_events_executable
    ON events(executable);

CREATE INDEX IF NOT EXISTS idx_events_path
    ON events(path);

CREATE INDEX IF NOT EXISTS idx_events_target_path
    ON events(target_path);

CREATE INDEX IF NOT EXISTS idx_events_windows_event
    ON events(
        provider,
        channel,
        windows_event_id
    );

CREATE INDEX IF NOT EXISTS idx_events_mft
    ON events(
        mft_entry,
        mft_sequence
    );

CREATE INDEX IF NOT EXISTS idx_events_registry
    ON events(
        registry_hive,
        registry_key
    );

CREATE INDEX IF NOT EXISTS idx_events_detection
    ON events(detection_rule);

CREATE INDEX IF NOT EXISTS idx_provenance_source
    ON provenance(
        parser,
        source_row
    );
"""


def create_evidence_db(
    case_id: str,
    *,
    defer_indexes: bool = False,
) -> dict:

    if not case_id or not case_id.strip():
        raise ValueError("case_id is required")

    case_root = (
        WORKSPACE_ROOT / case_id
    ).resolve()

    try:
        case_root.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise ValueError(
            "Case path escapes workspace root"
        )

    if not case_root.is_dir():
        raise FileNotFoundError(
            f"Case workspace does not exist: {case_root}"
        )

    db_path = case_root / "evidence.db"

    if db_path.exists():
        raise FileExistsError(
            f"Evidence database already exists: {db_path}"
        )

    conn = sqlite3.connect(str(db_path))

    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")

        conn.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE sources (
                source_id INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                parser_output TEXT,
                source_evidence TEXT,
                UNIQUE(
                    case_id,
                    source_tool,
                    parser_output,
                    source_evidence
                )
            );

            CREATE TABLE imports (
                import_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                parser_output TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                source_rows_processed INTEGER NOT NULL DEFAULT 0,
                normalized_events_inserted INTEGER NOT NULL DEFAULT 0,
                last_source_row INTEGER,
                error_message TEXT,
                source_sha256 TEXT NOT NULL,
                source_size INTEGER NOT NULL
            );

            CREATE TABLE events (
                event_uid TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                case_id TEXT NOT NULL,

                timestamp TEXT NOT NULL,
                timestamp_sort TEXT,
                timestamp_type TEXT NOT NULL,
                timestamp_source TEXT NOT NULL,

                artifact_type TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_tool TEXT NOT NULL,

                hostname TEXT,
                username TEXT,
                executable TEXT,
                process_id TEXT,
                command_line TEXT,

                path TEXT,
                target_path TEXT,

                windows_event_id TEXT,
                provider TEXT,
                channel TEXT,

                registry_hive TEXT,
                registry_key TEXT,
                registry_value_name TEXT,
                registry_value_data TEXT,

                mft_entry TEXT,
                mft_sequence TEXT,

                detection_rule TEXT,
                severity TEXT,
                description TEXT,

                source_id INTEGER,

                FOREIGN KEY(source_id)
                    REFERENCES sources(source_id)
            );

            CREATE TABLE attributes (
                event_uid TEXT NOT NULL,
                attribute_key TEXT NOT NULL,
                attribute_value TEXT,

                PRIMARY KEY(
                    event_uid,
                    attribute_key
                ),

                FOREIGN KEY(event_uid)
                    REFERENCES events(event_uid)
                    ON DELETE CASCADE
            );

            CREATE TABLE provenance (
                event_uid TEXT PRIMARY KEY,
                parser TEXT NOT NULL,
                parser_output TEXT,
                source_evidence TEXT,
                source_row INTEGER,

                FOREIGN KEY(event_uid)
                    REFERENCES events(event_uid)
                    ON DELETE CASCADE
            );


            """
        )

        if not defer_indexes:
            conn.executescript(
                SECONDARY_INDEX_SQL
            )

        conn.execute(
            """
            INSERT INTO metadata(key, value)
            VALUES (?, ?)
            """,
            ("schema_version", SCHEMA_VERSION),
        )

        conn.execute(
            """
            INSERT INTO metadata(key, value)
            VALUES (?, ?)
            """,
            ("case_id", case_id),
        )

        conn.commit()

    except Exception:
        conn.close()

        if db_path.exists():
            db_path.unlink()

        raise

    finally:
        try:
            conn.close()
        except Exception:
            pass

    return {
        "success": True,
        "component": "evidence_db",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "database": str(db_path),
    }


if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: evidence_db.py CASE-ID"
        )

    result = create_evidence_db(sys.argv[1])

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

# ============================================================
# EVIDENCE DATABASE ACCESS / INSERTION
# ============================================================

def create_secondary_indexes(
    case_id: str,
) -> dict:

    if not case_id or not case_id.strip():
        raise ValueError(
            "case_id is required"
        )

    case_root = (
        WORKSPACE_ROOT / case_id
    ).resolve()

    try:
        case_root.relative_to(
            WORKSPACE_ROOT
        )
    except ValueError:
        raise ValueError(
            "Case path escapes workspace root"
        )

    db_path = (
        case_root / "evidence.db"
    )

    if not db_path.is_file():
        raise FileNotFoundError(
            "Evidence database does not exist: "
            f"{db_path}"
        )

    conn = sqlite3.connect(
        str(db_path)
    )

    try:
        conn.execute(
            "PRAGMA foreign_keys = ON"
        )

        conn.executescript(
            SECONDARY_INDEX_SQL
        )

        conn.commit()

        integrity = conn.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":
            raise RuntimeError(
                "Evidence database integrity "
                f"check failed: {integrity}"
            )

        expected = {
            "idx_events_timestamp",
            "idx_events_artifact_type",
            "idx_events_event_type",
            "idx_events_hostname",
            "idx_events_username",
            "idx_events_executable",
            "idx_events_path",
            "idx_events_target_path",
            "idx_events_windows_event",
            "idx_events_mft",
            "idx_events_registry",
            "idx_events_detection",
            "idx_provenance_source",
        }

        rows = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
            """
        ).fetchall()

        existing = {
            row[0]
            for row in rows
        }

        missing = sorted(
            expected - existing
        )

        if missing:
            raise RuntimeError(
                "Secondary indexes missing: "
                + ", ".join(missing)
            )

        return {
            "success": True,
            "case_id": case_id,
            "database": str(db_path),
            "secondary_indexes":
                len(expected),
            "integrity": integrity,
        }

    finally:
        conn.close()


import json as _json


EVENT_COLUMNS = [
    "event_uid",
    "schema_version",
    "case_id",
    "timestamp",
    "timestamp_sort",
    "timestamp_type",
    "timestamp_source",
    "artifact_type",
    "event_type",
    "source_tool",
    "hostname",
    "username",
    "executable",
    "process_id",
    "command_line",
    "path",
    "target_path",
    "windows_event_id",
    "provider",
    "channel",
    "registry_hive",
    "registry_key",
    "registry_value_name",
    "registry_value_data",
    "mft_entry",
    "mft_sequence",
    "detection_rule",
    "severity",
    "description",
]


def connect_evidence_db(case_id: str):

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

    conn = sqlite3.connect(str(db_path))

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    enabled = conn.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    if enabled != 1:
        conn.close()
        raise RuntimeError(
            "SQLite foreign key enforcement "
            "could not be enabled"
        )

    return conn


def _serialize_attribute(value):

    if value is None:
        return None

    if isinstance(
        value,
        (dict, list, tuple, bool, int, float),
    ):
        return _json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    return str(value)


_SOURCE_ID_CACHE = {}


def _resolve_source_id(
    conn,
    *,
    case_id,
    source_tool,
    parser_output,
    source_evidence,
):
    db_identity = conn.execute(
        "PRAGMA database_list"
    ).fetchone()[2]

    key = (
        db_identity,
        case_id,
        source_tool,
        parser_output,
        source_evidence,
    )

    cached = _SOURCE_ID_CACHE.get(key)

    if cached is not None:
        return cached

    conn.execute(
        """
        INSERT OR IGNORE INTO sources(
            case_id,
            source_tool,
            parser_output,
            source_evidence
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            case_id,
            source_tool,
            parser_output,
            source_evidence,
        ),
    )

    row = conn.execute(
        """
        SELECT source_id
        FROM sources
        WHERE case_id = ?
          AND source_tool = ?
          AND parser_output = ?
          AND source_evidence = ?
        """,
        (
            case_id,
            source_tool,
            parser_output,
            source_evidence,
        ),
    ).fetchone()

    if row is None:
        raise RuntimeError(
            "Unable to resolve source_id"
        )

    source_id = row[0]

    _SOURCE_ID_CACHE[key] = source_id

    return source_id


def insert_normalized_event(
    conn,
    event: dict,
) -> bool:

    required = {
        "event_uid",
        "schema_version",
        "case_id",
        "timestamp",
        "timestamp_type",
        "timestamp_source",
        "artifact_type",
        "event_type",
        "source_tool",
        "attributes",
        "provenance",
    }

    missing = required - set(event)

    if missing:
        raise ValueError(
            "Normalized event missing fields: "
            + ", ".join(sorted(missing))
        )

    if not event["event_uid"]:
        raise ValueError(
            "event_uid cannot be blank"
        )

    if not event["timestamp"]:
        raise ValueError(
            "timestamp cannot be blank"
        )

    provenance = event["provenance"]

    parser = str(
        provenance.get("parser") or ""
    )

    parser_output = str(
        provenance.get("parser_output") or ""
    )

    source_evidence = str(
        provenance.get("source_evidence") or ""
    )

    source_row = provenance.get(
        "source_row"
    )

    if not parser:
        raise ValueError(
            "provenance.parser cannot be blank"
        )

    # --------------------------------------------------------
    # Register/reuse source with connection-local cache
    # --------------------------------------------------------

    source_id = _resolve_source_id(
        conn,
        case_id=event["case_id"],
        source_tool=event["source_tool"],
        parser_output=parser_output,
        source_evidence=source_evidence,
    )

    # --------------------------------------------------------
    # Insert normalized event
    # --------------------------------------------------------

    db_event = dict(event)

    db_event["timestamp_sort"] = (
        canonical_timestamp_sort(
            event["timestamp"]
        )
    )

    values = [
        db_event.get(column, "")
        for column in EVENT_COLUMNS
    ]

    placeholders = ",".join(
        "?" for _ in EVENT_COLUMNS
    )

    columns_sql = ",".join(
        EVENT_COLUMNS
    )

    cursor = conn.execute(
        f"""
        INSERT INTO events(
            {columns_sql},
            source_id
        )
        VALUES (
            {placeholders},
            ?
        )
        ON CONFLICT(event_uid) DO NOTHING
        """,
        values + [source_id],
    )

    # event_uid is the PRIMARY KEY.
    #
    # If the row already exists, SQLite ignores the insert.
    # Do not insert duplicate attributes or provenance.
    if cursor.rowcount == 0:
        return False

    # --------------------------------------------------------
    # Attributes
    # --------------------------------------------------------

    attributes = event.get(
        "attributes"
    ) or {}

    if not isinstance(attributes, dict):
        raise ValueError(
            "attributes must be a dictionary"
        )

    for key, value in attributes.items():

        conn.execute(
            """
            INSERT INTO attributes(
                event_uid,
                attribute_key,
                attribute_value
            )
            VALUES (?, ?, ?)
            """,
            (
                event["event_uid"],
                str(key),
                _serialize_attribute(value),
            ),
        )

    # --------------------------------------------------------
    # Provenance
    # --------------------------------------------------------

    conn.execute(
        """
        INSERT INTO provenance(
            event_uid,
            parser,
            parser_output,
            source_evidence,
            source_row
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            event["event_uid"],
            parser,
            parser_output,
            source_evidence,
            source_row,
        ),
    )

    return True


def insert_normalized_event_batch(
    conn,
    events: list[dict],
) -> dict:
    """
    Bulk insert normalized events while preserving the same
    event_uid, attributes, provenance, and duplicate semantics.

    The caller owns the transaction.
    """

    if not events:
        return {
            "inserted": 0,
            "duplicates": 0,
        }

    # --------------------------------------------------------
    # Validate + deduplicate inside this batch
    # --------------------------------------------------------

    unique_events = []
    seen = set()
    duplicate_count = 0

    required = {
        "event_uid",
        "schema_version",
        "case_id",
        "timestamp",
        "timestamp_type",
        "timestamp_source",
        "artifact_type",
        "event_type",
        "source_tool",
        "attributes",
        "provenance",
    }

    for event in events:

        missing = required - set(event)

        if missing:
            raise ValueError(
                "Normalized event missing fields: "
                + ", ".join(sorted(missing))
            )

        event_uid = str(
            event["event_uid"] or ""
        )

        if not event_uid:
            raise ValueError(
                "event_uid cannot be blank"
            )

        if not event["timestamp"]:
            raise ValueError(
                "timestamp cannot be blank"
            )

        if event_uid in seen:
            duplicate_count += 1
            continue

        seen.add(event_uid)
        unique_events.append(event)

    if not unique_events:
        return {
            "inserted": 0,
            "duplicates": duplicate_count,
        }

    # --------------------------------------------------------
    # Find event_uids already present.
    #
    # SQLite has a parameter limit, so query in chunks.
    # This replaces one SELECT per event with only a handful
    # of SELECTs per batch.
    # --------------------------------------------------------

    existing = set()

    uids = [
        event["event_uid"]
        for event in unique_events
    ]

    query_chunk_size = 900

    for offset in range(
        0,
        len(uids),
        query_chunk_size,
    ):

        chunk = uids[
            offset:
            offset + query_chunk_size
        ]

        placeholders = ",".join(
            "?"
            for _ in chunk
        )

        rows = conn.execute(
            f"""
            SELECT event_uid
            FROM events
            WHERE event_uid IN ({placeholders})
            """,
            chunk,
        ).fetchall()

        existing.update(
            row[0]
            for row in rows
        )

    new_events = [
        event
        for event in unique_events
        if event["event_uid"] not in existing
    ]

    duplicate_count += (
        len(unique_events)
        - len(new_events)
    )

    if not new_events:
        return {
            "inserted": 0,
            "duplicates": duplicate_count,
        }

    # --------------------------------------------------------
    # Resolve each unique source only once
    # --------------------------------------------------------

    source_ids = {}

    for event in new_events:

        provenance = event["provenance"]

        if not isinstance(
            provenance,
            dict,
        ):
            raise ValueError(
                "provenance must be a dictionary"
            )

        parser = str(
            provenance.get("parser") or ""
        )

        if not parser:
            raise ValueError(
                "provenance.parser cannot be blank"
            )

        parser_output = str(
            provenance.get(
                "parser_output"
            ) or ""
        )

        source_evidence = str(
            provenance.get(
                "source_evidence"
            ) or ""
        )

        source_key = (
            event["case_id"],
            event["source_tool"],
            parser_output,
            source_evidence,
        )

        if source_key not in source_ids:

            source_ids[source_key] = (
                _resolve_source_id(
                    conn,
                    case_id=source_key[0],
                    source_tool=source_key[1],
                    parser_output=source_key[2],
                    source_evidence=source_key[3],
                )
            )

    # --------------------------------------------------------
    # Prepare rows
    # --------------------------------------------------------

    event_rows = []
    attribute_rows = []
    provenance_rows = []

    for event in new_events:

        provenance = event["provenance"]

        parser = str(
            provenance.get("parser") or ""
        )

        parser_output = str(
            provenance.get(
                "parser_output"
            ) or ""
        )

        source_evidence = str(
            provenance.get(
                "source_evidence"
            ) or ""
        )

        source_row = provenance.get(
            "source_row"
        )

        source_key = (
            event["case_id"],
            event["source_tool"],
            parser_output,
            source_evidence,
        )

        source_id = source_ids[
            source_key
        ]

        db_event = dict(event)

        db_event["timestamp_sort"] = (
            canonical_timestamp_sort(
                event["timestamp"]
            )
        )

        values = [
            db_event.get(column, "")
            for column in EVENT_COLUMNS
        ]

        event_rows.append(
            tuple(
                values
                + [source_id]
            )
        )

        attributes = (
            event.get("attributes")
            or {}
        )

        if not isinstance(
            attributes,
            dict,
        ):
            raise ValueError(
                "attributes must be a dictionary"
            )

        for key, value in attributes.items():

            attribute_rows.append(
                (
                    event["event_uid"],
                    str(key),
                    _serialize_attribute(
                        value
                    ),
                )
            )

        provenance_rows.append(
            (
                event["event_uid"],
                parser,
                parser_output,
                source_evidence,
                source_row,
            )
        )

    # --------------------------------------------------------
    # Bulk INSERT
    # --------------------------------------------------------

    placeholders = ",".join(
        "?"
        for _ in EVENT_COLUMNS
    )

    columns_sql = ",".join(
        EVENT_COLUMNS
    )

    conn.executemany(
        f"""
        INSERT INTO events(
            {columns_sql},
            source_id
        )
        VALUES (
            {placeholders},
            ?
        )
        ON CONFLICT(event_uid) DO NOTHING
        """,
        event_rows,
    )

    if attribute_rows:

        conn.executemany(
            """
            INSERT INTO attributes(
                event_uid,
                attribute_key,
                attribute_value
            )
            VALUES (?, ?, ?)
            """,
            attribute_rows,
        )

    conn.executemany(
        """
        INSERT INTO provenance(
            event_uid,
            parser,
            parser_output,
            source_evidence,
            source_row
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        provenance_rows,
    )

    return {
        "inserted": len(new_events),
        "duplicates": duplicate_count,
    }


def insert_normalized_events(
    case_id: str,
    events: list[dict],
) -> dict:

    conn = connect_evidence_db(
        case_id
    )

    inserted = 0

    try:

        conn.execute("BEGIN")

        for event in events:

            if event.get("case_id") != case_id:
                raise ValueError(
                    "Event case_id does not match "
                    f"database case: "
                    f"{event.get('case_id')} "
                    f"!= {case_id}"
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

    finally:
        conn.close()

    return {
        "success": True,
        "case_id": case_id,
        "inserted_events": inserted,
    }

# ============================================================
# TIMESTAMP SORT NORMALIZATION
# ============================================================

from datetime import datetime, timezone


def canonical_timestamp_sort(
    timestamp: str,
) -> str:

    value = str(timestamp or "").strip()

    if not value:
        raise ValueError(
            "timestamp cannot be blank"
        )

    parse_value = value

    if parse_value.endswith("Z"):
        parse_value = (
            parse_value[:-1] + "+00:00"
        )

    try:
        dt = datetime.fromisoformat(
            parse_value
        )
    except ValueError:
        raise ValueError(
            f"Unsupported timestamp format: {value}"
        )

    # Explicit timezone:
    # convert to canonical UTC.
    if dt.tzinfo is not None:

        dt = dt.astimezone(
            timezone.utc
        ).replace(
            tzinfo=None
        )

    # Do NOT assume a timezone for naive parser timestamps.

    return dt.isoformat(
        sep=" ",
        timespec="microseconds",
    )

