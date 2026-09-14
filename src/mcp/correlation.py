import argparse
import hashlib
import json
import ntpath
import re
import sqlite3

from datetime import datetime, timedelta, timezone
from pathlib import Path



from case_config import require_existing_case


parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

CASE_DIR = require_existing_case(CASE)

EVIDENCE_DB = (
    CASE_DIR
    / "evidence.db"
)

CORRELATION_DB = (
    CASE_DIR
    / "correlation.db"
)

ENGINE_VERSION = "1.2"
RULE_VERSION = "1.2"

EXPECTED_EVIDENCE_EVENTS = 975501 if CASE == "CASE-001" else None

GENERIC_WINDOW_SECONDS = 1.0
HAYABUSA_WINDOW_SECONDS = 2.0
MAX_WINDOW_CANDIDATES = 5000


def utc_now():
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_attribute_key(value):
    return re.sub(
        r"[^a-z0-9]",
        "",
        (value or "").lower(),
    )


def clean(value):
    return (value or "").strip()


def norm_text(value):
    return clean(value).lower()


def norm_path(value):
    value = clean(value)

    if not value:
        return ""

    value = value.strip('"').strip("'")
    value = value.replace("/", "\\")

    while "\\\\" in value:
        value = value.replace("\\\\", "\\")

    return value.lower()


def norm_executable(value):
    value = norm_path(value)

    if not value:
        return ""

    return ntpath.basename(value)


def path_keys(row):
    values = set()

    for key in ("path", "target_path"):
        value = norm_path(row[key])

        if not value:
            continue

        if value in {
            "\\",
            "$mft",
        }:
            continue

        if len(value) < 3:
            continue

        values.add(value)

    return values


def executable_keys(
    row,
    event_attributes=None,
):
    values = set()

    def add_executable_value(value):
        value = norm_executable(value)

        if not value:
            return

        values.add(value)

        # Windows Prefetch:
        # VMTOOLSIO.EXE-B05FE979.pf
        # -> vmtoolsio.exe
        match = re.match(
            r"^(.+?\.exe)-[0-9a-f]{8}\.pf$",
            value,
            re.IGNORECASE,
        )

        if match:
            values.add(
                match.group(1).lower()
            )

    add_executable_value(
        row["executable"]
    )

    for key in ("path", "target_path"):
        add_executable_value(
            row[key]
        )

    event_attributes = (
        event_attributes or {}
    )

    # EvtxECmd Event 7045 commonly stores
    # the installed service ImagePath here.
    for key in (
        "executableinfo",
        "imagepath",
    ):
        add_executable_value(
            event_attributes.get(
                key,
                ""
            )
        )


    # RECmd registry values may contain executable
    # paths inside descriptive text, for example:
    #
    # Extension: exe Absolute path:
    # Example path: C:\Evidence\example.exe
    #
    # Extract only Windows-path tokens ending in .exe.
    try:
        registry_value_data = (
            row["registry_value_data"]
            if "registry_value_data" in row.keys()
            else None
        )
    except Exception:
        registry_value_data = None

    if registry_value_data:

        for match in re.finditer(
            r"(?i)(?:[A-Z]:\\|\\Device\\)"
            r"[^\r\n\"';,]*?\.exe\b",
            str(registry_value_data),
        ):
            add_executable_value(
                match.group(0)
            )

    return values


def parse_timestamp_sort(value):
    value = clean(value)

    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S.%f",
        )

    except ValueError:
        return None


def format_timestamp_sort(value):
    return value.strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )


def timestamp_delta(a, b):
    a_dt = parse_timestamp_sort(a)
    b_dt = parse_timestamp_sort(b)

    if a_dt is None or b_dt is None:
        return None

    return abs(
        (a_dt - b_dt).total_seconds()
    )


def confidence_from_score(score):
    if score >= 0.90:
        return "VERY_HIGH"

    if score >= 0.80:
        return "HIGH"

    if score >= 0.70:
        return "MEDIUM"

    return "LOW"


def make_edge_uid(
    relationship_type,
    event_a,
    event_b,
):
    first, second = sorted(
        [event_a, event_b]
    )

    identity = (
        f"{RULE_VERSION}|"
        f"{relationship_type}|"
        f"{first}|{second}"
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def evidence_connection():
    uri = (
        "file:"
        + EVIDENCE_DB.resolve().as_posix()
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


def correlation_connection():
    conn = sqlite3.connect(
        str(CORRELATION_DB)
    )

    conn.row_factory = sqlite3.Row

    return conn


def initialize_correlation_db(conn):

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            started_utc TEXT NOT NULL,
            completed_utc TEXT,
            status TEXT NOT NULL,
            evidence_event_count INTEGER NOT NULL,
            edge_count INTEGER,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS edges (
            edge_uid TEXT PRIMARY KEY,

            run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,

            event_uid_a TEXT NOT NULL,
            event_uid_b TEXT NOT NULL,

            source_tool_a TEXT NOT NULL,
            source_tool_b TEXT NOT NULL,

            timestamp_a TEXT,
            timestamp_b TEXT,

            relationship_type TEXT NOT NULL,

            score REAL NOT NULL,
            confidence TEXT NOT NULL,

            time_delta_seconds REAL,

            shared_keys_json TEXT NOT NULL,
            reason TEXT NOT NULL,

            rule_version TEXT NOT NULL,
            created_utc TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS
            idx_edges_event_a
            ON edges(event_uid_a);

        CREATE INDEX IF NOT EXISTS
            idx_edges_event_b
            ON edges(event_uid_b);

        CREATE INDEX IF NOT EXISTS
            idx_edges_relationship
            ON edges(relationship_type);

        CREATE INDEX IF NOT EXISTS
            idx_edges_confidence
            ON edges(confidence);

        CREATE INDEX IF NOT EXISTS
            idx_edges_score
            ON edges(score);

        CREATE INDEX IF NOT EXISTS
            idx_edges_time_delta
            ON edges(time_delta_seconds);

        CREATE INDEX IF NOT EXISTS
            idx_edges_tools
            ON edges(
                source_tool_a,
                source_tool_b
            );
        """
    )

    conn.execute(
        """
        INSERT OR REPLACE INTO metadata(
            key,
            value
        )
        VALUES(
            'schema_version',
            '1.0'
        )
        """
    )

    conn.execute(
        """
        INSERT OR REPLACE INTO metadata(
            key,
            value
        )
        VALUES(
            'engine_version',
            ?
        )
        """,
        (ENGINE_VERSION,),
    )

    conn.commit()


def insert_edge(
    conn,
    run_id,
    event_a,
    event_b,
    relationship_type,
    score,
    delta,
    shared_keys,
    reason,
):

    uid_a = event_a["event_uid"]
    uid_b = event_b["event_uid"]

    if uid_a == uid_b:
        return 0

    if uid_a < uid_b:
        first = event_a
        second = event_b
    else:
        first = event_b
        second = event_a

    edge_uid = make_edge_uid(
        relationship_type,
        first["event_uid"],
        second["event_uid"],
    )

    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO edges (
            edge_uid,
            run_id,
            case_id,

            event_uid_a,
            event_uid_b,

            source_tool_a,
            source_tool_b,

            timestamp_a,
            timestamp_b,

            relationship_type,

            score,
            confidence,
            time_delta_seconds,

            shared_keys_json,
            reason,

            rule_version,
            created_utc
        )
        VALUES (
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?, ?,
            ?, ?,
            ?, ?
        )
        """,
        (
            edge_uid,
            run_id,
            CASE,

            first["event_uid"],
            second["event_uid"],

            first["source_tool"],
            second["source_tool"],

            first["timestamp_sort"],
            second["timestamp_sort"],

            relationship_type,

            round(score, 4),
            confidence_from_score(score),
            delta,

            json.dumps(
                shared_keys,
                ensure_ascii=False,
                sort_keys=True,
            ),

            reason,

            RULE_VERSION,
            utc_now(),
        ),
    )

    return 1 if cursor.rowcount == 1 else 0


def load_attributes(
    evidence,
    tools,
):
    placeholders = ",".join(
        "?" for _ in tools
    )

    rows = evidence.execute(
        f"""
        SELECT
            a.event_uid,
            a.attribute_key,
            a.attribute_value
        FROM attributes a
        JOIN events e
          ON e.event_uid = a.event_uid
        WHERE e.source_tool
          IN ({placeholders})
        """,
        tools,
    )

    result = {}

    for row in rows:
        result.setdefault(
            row["event_uid"],
            {},
        )

        result[row["event_uid"]][
            canonical_attribute_key(
                row["attribute_key"]
            )
        ] = clean(
            row["attribute_value"]
        )

    return result


def load_provenance(
    evidence,
    tools,
):
    placeholders = ",".join(
        "?" for _ in tools
    )

    rows = evidence.execute(
        f"""
        SELECT
            p.event_uid,
            p.parser_output,
            p.source_evidence
        FROM provenance p
        JOIN events e
          ON e.event_uid = p.event_uid
        WHERE e.source_tool
          IN ({placeholders})
        """,
        tools,
    )

    return {
        row["event_uid"]: {
            "parser_output":
                clean(row["parser_output"]),

            "source_evidence":
                clean(row["source_evidence"]),
        }
        for row in rows
    }


def get_attribute(
    attributes,
    event_uid,
    possible_keys,
):
    event_attributes = attributes.get(
        event_uid,
        {},
    )

    for key in possible_keys:
        key = canonical_attribute_key(key)

        value = clean(
            event_attributes.get(
                key,
                ""
            )
        )

        if value:
            return value

    return ""


def basename(value):
    value = clean(value)

    if not value:
        return ""

    value = value.replace(
        "/",
        "\\",
    )

    return ntpath.basename(
        value
    ).lower()


def correlate_hayabusa_evtx(
    evidence,
    correlation,
    run_id,
):

    print()
    print(
        "RULE 1: HAYABUSA_EVTX_MATCH"
    )

    hayabusa = evidence.execute(
        """
        SELECT
            event_uid,
            source_tool,
            timestamp_sort,
            hostname,
            username,
            executable,
            path,
            target_path,
            windows_event_id,
            provider,
            channel
        FROM events
        WHERE source_tool = 'hayabusa'
        """
    ).fetchall()

    evtx = evidence.execute(
        """
        SELECT
            event_uid,
            source_tool,
            timestamp_sort,
            hostname,
            username,
            executable,
            path,
            target_path,
            windows_event_id,
            provider,
            channel
        FROM events
        WHERE source_tool = 'evtxecmd'
        """
    ).fetchall()

    print(
        f"Hayabusa anchors: {len(hayabusa):,}"
    )

    print(
        f"EVTX candidates:  {len(evtx):,}"
    )

    attributes = load_attributes(
        evidence,
        (
            "hayabusa",
            "evtxecmd",
        ),
    )

    provenance = load_provenance(
        evidence,
        (
            "hayabusa",
            "evtxecmd",
        ),
    )

    by_event_id = {}

    for row in evtx:
        event_id = clean(
            row["windows_event_id"]
        )

        if not event_id:
            continue

        by_event_id.setdefault(
            event_id,
            [],
        ).append(row)

    record_keys = (
        "record_id",
        "recordid",
        "event_record_id",
        "eventrecordid",
        "record_number",
        "recordnumber",
        "event_record_number",
    )

    file_keys = (
        "evtx_file",
        "evtxfile",
        "file_name",
        "filename",
    )

    inserted = 0

    for anchor in hayabusa:

        event_id = clean(
            anchor["windows_event_id"]
        )

        if not event_id:
            continue

        candidates = by_event_id.get(
            event_id,
            [],
        )

        anchor_record = get_attribute(
            attributes,
            anchor["event_uid"],
            record_keys,
        )

        anchor_file = get_attribute(
            attributes,
            anchor["event_uid"],
            file_keys,
        )

        anchor_file = basename(
            anchor_file
        )

        for candidate in candidates:

            delta = timestamp_delta(
                anchor["timestamp_sort"],
                candidate["timestamp_sort"],
            )

            if delta is None:
                continue

            if (
                delta >
                HAYABUSA_WINDOW_SECONDS
            ):
                continue

            candidate_record = get_attribute(
                attributes,
                candidate["event_uid"],
                record_keys,
            )

            record_match = bool(
                anchor_record
                and candidate_record
                and anchor_record
                    == candidate_record
            )

            host_match = bool(
                norm_text(anchor["hostname"])
                and
                norm_text(candidate["hostname"])
                and
                norm_text(anchor["hostname"])
                    ==
                norm_text(candidate["hostname"])
            )

            channel_match = bool(
                norm_text(anchor["channel"])
                and
                norm_text(candidate["channel"])
                and
                norm_text(anchor["channel"])
                    ==
                norm_text(candidate["channel"])
            )

            candidate_prov = provenance.get(
                candidate["event_uid"],
                {},
            )

            candidate_file = basename(
                candidate_prov.get(
                    "source_evidence",
                    "",
                )
                or
                candidate_prov.get(
                    "parser_output",
                    "",
                )
            )

            file_match = bool(
                anchor_file
                and candidate_file
                and anchor_file
                    == candidate_file
            )

            exact_time = (
                delta <= 0.001
            )

            contextual_match = (
                host_match
                or channel_match
                or file_match
            )

            if record_match:
                accepted = True

            elif (
                delta <= 0.25
                and contextual_match
            ):
                accepted = True

            else:
                accepted = False

            if not accepted:
                continue

            score = 0.25

            if record_match:
                score += 0.45

            if exact_time:
                score += 0.15

            elif delta <= 0.25:
                score += 0.10

            else:
                score += 0.05

            if host_match:
                score += 0.05

            if channel_match:
                score += 0.05

            if file_match:
                score += 0.10

            score = min(
                score,
                1.0,
            )

            if score < 0.70:
                continue

            shared = {
                "windows_event_id":
                    event_id,
            }

            if record_match:
                shared["record_id"] = (
                    anchor_record
                )

            if host_match:
                shared["hostname"] = (
                    anchor["hostname"]
                )

            if channel_match:
                shared["channel"] = (
                    anchor["channel"]
                )

            if file_match:
                shared["evtx_file"] = (
                    anchor_file
                )

            inserted += insert_edge(
                correlation,
                run_id,
                anchor,
                candidate,
                "HAYABUSA_EVTX_MATCH",
                score,
                delta,
                shared,
                (
                    "Hayabusa detection and "
                    "EvtxECmd event share "
                    "Windows event identity "
                    "and supporting context."
                ),
            )

    print(
        f"Edges created: {inserted:,}"
    )

    return inserted


def correlate_generic_anchors(
    evidence,
    correlation,
    run_id,
):

    print()
    print(
        "RULE 2/3: SHARED PATH / "
        "EXECUTABLE NEAR TIME"
    )

    anchors = evidence.execute(
        """
        SELECT
            event_uid,
            source_tool,
            timestamp_sort,
            hostname,
            username,
            executable,
            path,
            target_path,
            registry_value_data,
            windows_event_id,
            provider,
            channel
        FROM events
        WHERE (
            source_tool IN (
                'pecmd',
                'recmd',
                'lecmd'
            )
            OR (
                source_tool = 'evtxecmd'
                AND windows_event_id = '7045'
            )
        )
        ORDER BY timestamp_sort
        """
    ).fetchall()

    print(
        f"Generic anchors: {len(anchors):,}"
    )

    generic_attributes = load_attributes(
        evidence,
        (
            "pecmd",
            "recmd",
            "lecmd",
            "evtxecmd",
        ),
    )

    path_edges = 0
    executable_edges = 0
    hot_windows_skipped = 0

    for anchor in anchors:

        anchor_dt = parse_timestamp_sort(
            anchor["timestamp_sort"]
        )

        if anchor_dt is None:
            continue

        anchor_paths = path_keys(
            anchor
        )

        anchor_executables = executable_keys(
            anchor,
            generic_attributes.get(
                anchor["event_uid"],
                {},
            ),
        )

        if (
            not anchor_paths
            and not anchor_executables
        ):
            continue

        start = format_timestamp_sort(
            anchor_dt
            - timedelta(
                seconds=GENERIC_WINDOW_SECONDS
            )
        )

        end = format_timestamp_sort(
            anchor_dt
            + timedelta(
                seconds=GENERIC_WINDOW_SECONDS
            )
        )

        candidates = evidence.execute(
            """
            SELECT
                event_uid,
                source_tool,
                timestamp_sort,
                hostname,
                username,
                executable,
                path,
                target_path,
                windows_event_id,
                provider,
                channel
            FROM events
            WHERE case_id = ?
              AND source_tool <> ?
              AND timestamp_sort
                  BETWEEN ? AND ?
            LIMIT ?
            """,
            (
                CASE,
                anchor["source_tool"],
                start,
                end,
                MAX_WINDOW_CANDIDATES + 1,
            ),
        ).fetchall()

        if (
            len(candidates)
            >
            MAX_WINDOW_CANDIDATES
        ):
            hot_windows_skipped += 1
            continue

        executable_matches = []

        for candidate in candidates:

            delta = timestamp_delta(
                anchor["timestamp_sort"],
                candidate["timestamp_sort"],
            )

            if delta is None:
                continue

            candidate_paths = path_keys(
                candidate
            )

            common_paths = (
                anchor_paths
                & candidate_paths
            )

            if common_paths:

                host_match = bool(
                    norm_text(anchor["hostname"])
                    and
                    norm_text(candidate["hostname"])
                    and
                    norm_text(anchor["hostname"])
                    ==
                    norm_text(candidate["hostname"])
                )

                score = (
                    0.90
                    if delta <= 0.10
                    else 0.85
                )

                if host_match:
                    score = min(
                        score + 0.05,
                        1.0,
                    )

                path_edges += insert_edge(
                    correlation,
                    run_id,
                    anchor,
                    candidate,
                    "SHARED_PATH_NEAR_TIME",
                    score,
                    delta,
                    {
                        "paths":
                            sorted(common_paths)
                    },
                    (
                        "Events from different "
                        "sources reference the "
                        "same normalized path "
                        "within the correlation "
                        "time window."
                    ),
                )

            candidate_executables = (
                executable_keys(
                    candidate
                )
            )

            common_executables = (
                anchor_executables
                & candidate_executables
            )

            if not common_executables:
                continue

            host_match = bool(
                norm_text(anchor["hostname"])
                and
                norm_text(candidate["hostname"])
                and
                norm_text(anchor["hostname"])
                    ==
                norm_text(candidate["hostname"])
            )

            user_match = bool(
                norm_text(anchor["username"])
                and
                norm_text(candidate["username"])
                and
                norm_text(anchor["username"])
                    ==
                norm_text(candidate["username"])
            )

            score = (
                0.78
                if delta <= 0.10
                else 0.72
            )

            if host_match:
                score += 0.05

            if user_match:
                score += 0.05

            score = min(
                score,
                0.90,
            )

            executable_matches.append(
                (
                    score,
                    delta,
                    candidate,
                    common_executables,
                )
            )

        executable_matches.sort(
            key=lambda item: (
                -item[0],
                item[1],
            )
        )

        # Prevent common executables from
        # creating large low-value fan-out.
        for (
            score,
            delta,
            candidate,
            common_executables,
        ) in executable_matches[:10]:

            executable_edges += insert_edge(
                correlation,
                run_id,
                anchor,
                candidate,
                (
                    "SHARED_EXECUTABLE_"
                    "NEAR_TIME"
                ),
                score,
                delta,
                {
                    "executables":
                        sorted(
                            common_executables
                        )
                },
                (
                    "Events from different "
                    "sources reference the "
                    "same executable or "
                    "basename within the "
                    "correlation time window."
                ),
            )

    print(
        f"Path edges:       {path_edges:,}"
    )

    print(
        f"Executable edges: {executable_edges:,}"
    )

    print(
        "Hot windows skipped: "
        f"{hot_windows_skipped:,}"
    )

    return (
        path_edges
        + executable_edges
    )


print("=" * 72)
print("CORRELATION ENGINE V1")
print("=" * 72)

print()
print(f"Evidence DB:    {EVIDENCE_DB}")
print(f"Correlation DB: {CORRELATION_DB}")

if not EVIDENCE_DB.is_file():
    raise RuntimeError(
        "Evidence database does not exist."
    )


evidence = evidence_connection()

try:

    evidence_count = evidence.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    ).fetchone()[0]

    evidence_unique = evidence.execute(
        """
        SELECT COUNT(
            DISTINCT event_uid
        )
        FROM events
        """
    ).fetchone()[0]

    integrity = evidence.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    print()
    print("FROZEN EVIDENCE BASELINE")
    print(
        f"Events:      {evidence_count:,}"
    )
    print(
        f"Unique UIDs: {evidence_unique:,}"
    )
    print(
        f"Integrity:   {integrity}"
    )

    if (
        EXPECTED_EVIDENCE_EVENTS is not None
        and evidence_count
        != EXPECTED_EVIDENCE_EVENTS
    ):
        raise RuntimeError(
            "Unexpected evidence event count."
        )

    if (
        EXPECTED_EVIDENCE_EVENTS is not None
        and evidence_unique
        != EXPECTED_EVIDENCE_EVENTS
    ):
        raise RuntimeError(
            "Evidence UID uniqueness failure."
        )

    if integrity != "ok":
        raise RuntimeError(
            "Evidence database integrity "
            "failure."
        )


    correlation = correlation_connection()

    try:

        initialize_correlation_db(
            correlation
        )

        completed = correlation.execute(
            """
            SELECT COUNT(*)
            FROM runs
            WHERE engine_version = ?
              AND status = 'COMPLETED'
            """,
            (ENGINE_VERSION,),
        ).fetchone()[0]

        if completed:
            print()
            print(
                "Correlation Engine v1 "
                "already completed."
            )

            print(
                "No rebuild performed."
            )

            raise SystemExit(0)


        started = utc_now()

        run_id = hashlib.sha256(
            (
                CASE
                + "|"
                + ENGINE_VERSION
                + "|"
                + started
            ).encode("utf-8")
        ).hexdigest()


        correlation.execute(
            """
            INSERT INTO runs (
                run_id,
                case_id,
                engine_version,
                started_utc,
                status,
                evidence_event_count
            )
            VALUES (
                ?, ?, ?, ?,
                'RUNNING',
                ?
            )
            """,
            (
                run_id,
                CASE,
                ENGINE_VERSION,
                started,
                evidence_count,
            ),
        )

        correlation.commit()


        print()
        print(f"Run ID: {run_id}")

        try:

            correlation.execute(
                "BEGIN"
            )

            hayabusa_edges = (
                correlate_hayabusa_evtx(
                    evidence,
                    correlation,
                    run_id,
                )
            )

            generic_edges = (
                correlate_generic_anchors(
                    evidence,
                    correlation,
                    run_id,
                )
            )

            total_edges = correlation.execute(
                """
                SELECT COUNT(*)
                FROM edges
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()[0]

            correlation.commit()

        except Exception:

            correlation.rollback()

            correlation.execute(
                """
                UPDATE runs
                SET
                    status = 'FAILED',
                    completed_utc = ?,
                    error_message = ?
                WHERE run_id = ?
                """,
                (
                    utc_now(),
                    "Correlation rule failure",
                    run_id,
                ),
            )

            correlation.commit()

            raise


        correlation.execute(
            """
            UPDATE runs
            SET
                status = 'COMPLETED',
                completed_utc = ?,
                edge_count = ?,
                error_message = NULL
            WHERE run_id = ?
            """,
            (
                utc_now(),
                total_edges,
                run_id,
            ),
        )

        correlation.commit()


        print()
        print("=" * 72)
        print("CORRELATION RESULTS")
        print("=" * 72)

        for row in correlation.execute(
            """
            SELECT
                relationship_type,
                confidence,
                COUNT(*) AS count
            FROM edges
            WHERE run_id = ?
            GROUP BY
                relationship_type,
                confidence
            ORDER BY
                relationship_type,
                confidence
            """,
            (run_id,),
        ):

            print(
                f"{row['relationship_type']:<32} "
                f"{row['confidence']:<10} "
                f"{row['count']:,}"
            )


        print()
        print(
            f"TOTAL EDGES: {total_edges:,}"
        )


        print()
        print("TOP CORRELATIONS")

        for row in correlation.execute(
            """
            SELECT
                relationship_type,
                source_tool_a,
                source_tool_b,
                score,
                time_delta_seconds,
                event_uid_a,
                event_uid_b
            FROM edges
            WHERE run_id = ?
            ORDER BY
                score DESC,
                time_delta_seconds ASC
            LIMIT 20
            """,
            (run_id,),
        ):

            print()
            print(
                row["relationship_type"]
            )

            print(
                "  tools: "
                f"{row['source_tool_a']} "
                f"<-> "
                f"{row['source_tool_b']}"
            )

            print(
                "  score: "
                f"{row['score']}"
            )

            print(
                "  delta: "
                f"{row['time_delta_seconds']}"
            )

            print(
                "  A: "
                f"{row['event_uid_a']}"
            )

            print(
                "  B: "
                f"{row['event_uid_b']}"
            )


        corr_integrity = (
            correlation.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
        )

        print()
        print(
            "Correlation DB integrity: "
            f"{corr_integrity}"
        )

        if corr_integrity != "ok":
            raise RuntimeError(
                "Correlation database "
                "integrity failure."
            )


    finally:
        correlation.close()


finally:
    evidence.close()


print()
print("=" * 72)
print("CORRELATION ENGINE V1: COMPLETE")
print("=" * 72)

print()
print("evidence.db:    READ-ONLY / UNCHANGED")
print("correlation.db: CREATED")
print()
print("No maliciousness inference performed.")
print("No timestamp-only correlations created.")
print()
print("NEXT: inspect correlation quality and build")
print("      evidence clusters / findings layer.")
