import argparse
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path



from case_config import require_existing_case
from prefetch_standalone_v17 import create_prefetch_standalone_findings


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

FINDINGS_DB = (
    CASE_DIR
    / "findings.db"
)

ENGINE_VERSION = "1.7"
CORRELATION_VERSION = "1.2"
CLUSTER_VERSION = "1.1"
CANDIDATE_VERSION = "1.1"

EXPECTED_EVIDENCE_EVENTS = 975501 if CASE == "CASE-001" else None

FAMILY_MAP = {
    "evtxecmd": "EVTX",
    "hayabusa": "EVTX",
    "mftecmd": "MFT",
    "pecmd": "PREFETCH",
    "recmd": "REGISTRY",
    "lecmd": "LNK",
}

SEVERITY_RANK = {
    "UNKNOWN": -1,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def utc_now():
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_severity(value):
    value = (value or "").strip().lower()

    mapping = {
        "informational": "INFO",
        "information": "INFO",
        "info": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "med": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
        "crit": "CRITICAL",
    }

    return mapping.get(
        value,
        "UNKNOWN",
    )


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
    conn.execute("PRAGMA query_only = ON")

    return conn


def correlation_connection():
    uri = (
        "file:"
        + CORRELATION_DB.resolve().as_posix()
        + "?mode=ro"
    )

    conn = sqlite3.connect(
        uri,
        uri=True,
    )

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")

    return conn


def findings_connection():
    conn = sqlite3.connect(
        str(FINDINGS_DB)
    )

    conn.row_factory = sqlite3.Row

    return conn


def batches(values, size=500):
    values = list(values)

    for offset in range(
        0,
        len(values),
        size,
    ):
        yield values[
            offset:offset + size
        ]


def fetch_events(
    evidence,
    event_uids,
):
    result = {}

    for group in batches(
        event_uids
    ):

        placeholders = ",".join(
            "?"
            for _ in group
        )

        rows = evidence.execute(
            f"""
            SELECT
                event_uid,
                source_tool,
                timestamp,
                timestamp_sort,
                timestamp_type,
                artifact_type,
                event_type,
                hostname,
                username,
                executable,
                command_line,
                path,
                target_path,
                windows_event_id,
                provider,
                channel,
                registry_hive,
                registry_key,
                registry_value_name,
                registry_value_data,
                mft_entry,
                mft_sequence,
                detection_rule,
                severity,
                description
            FROM events
            WHERE event_uid
              IN ({placeholders})
            """,
            tuple(group),
        )

        for row in rows:
            result[
                row["event_uid"]
            ] = row

    return result


def initialize_findings_db(conn):

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,

            case_id TEXT NOT NULL,

            engine_version TEXT NOT NULL,

            correlation_run_id TEXT NOT NULL,
            cluster_run_id TEXT NOT NULL,

            started_utc TEXT NOT NULL,
            completed_utc TEXT,

            status TEXT NOT NULL,

            finding_count INTEGER,

            error_message TEXT
        );


        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,

            run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,

            finding_type TEXT NOT NULL,

            state TEXT NOT NULL,

            confidence TEXT NOT NULL,
            severity TEXT NOT NULL,

            title TEXT NOT NULL,
            summary TEXT NOT NULL,

            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,

            start_timestamp TEXT,
            end_timestamp TEXT,

            independent_family_count
                INTEGER NOT NULL,

            evidence_count INTEGER NOT NULL,

            evidence_families_json
                TEXT NOT NULL,

            source_tools_json
                TEXT NOT NULL,

            detection_rules_json
                TEXT NOT NULL,

            executables_json
                TEXT NOT NULL,

            paths_json
                TEXT NOT NULL,

            created_utc TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS
        finding_evidence (
            finding_id TEXT NOT NULL,

            event_uid TEXT NOT NULL,

            source_tool TEXT NOT NULL,

            evidence_family TEXT NOT NULL,

            evidence_role TEXT NOT NULL,

            PRIMARY KEY (
                finding_id,
                event_uid
            )
        );


        CREATE INDEX IF NOT EXISTS
            idx_findings_type
            ON findings(finding_type);


        CREATE INDEX IF NOT EXISTS
            idx_findings_state
            ON findings(state);


        CREATE INDEX IF NOT EXISTS
            idx_findings_severity
            ON findings(severity);


        CREATE INDEX IF NOT EXISTS
            idx_findings_confidence
            ON findings(confidence);


        CREATE INDEX IF NOT EXISTS
            idx_finding_evidence_uid
            ON finding_evidence(
                event_uid
            );
        """
    )

    conn.commit()


def make_finding_id(
    finding_type,
    source_id,
):
    identity = (
        ENGINE_VERSION
        + "|"
        + finding_type
        + "|"
        + source_id
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def extract_candidate_shared_values(
    shared_json,
):

    executables = set()
    paths = set()

    try:
        values = json.loads(
            shared_json or "[]"
        )

    except Exception:
        values = []

    if not isinstance(
        values,
        list,
    ):
        values = [values]

    for item in values:

        if not isinstance(
            item,
            dict,
        ):
            continue

        for value in item.get(
            "executables",
            [],
        ):
            value = (
                str(value)
                .strip()
                .lower()
            )

            if value:
                executables.add(value)

        for value in item.get(
            "paths",
            [],
        ):
            value = (
                str(value)
                .strip()
                .lower()
            )

            if value:
                paths.add(value)

    return (
        sorted(executables),
        sorted(paths),
    )


print("=" * 72)
print("FINDINGS / INVESTIGATION ENGINE V1")
print("=" * 72)


if not EVIDENCE_DB.is_file():
    raise RuntimeError(
        "evidence.db missing"
    )

if not CORRELATION_DB.is_file():
    raise RuntimeError(
        "correlation.db missing"
    )


evidence = evidence_connection()
correlation = correlation_connection()
findings = findings_connection()


try:

    # ------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------

    evidence_count = evidence.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    evidence_integrity = evidence.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    correlation_integrity = (
        correlation.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
    )


    print()
    print("DATABASE BASELINE")
    print(
        f"Evidence events:       "
        f"{evidence_count:,}"
    )
    print(
        f"Evidence integrity:    "
        f"{evidence_integrity}"
    )
    print(
        f"Correlation integrity: "
        f"{correlation_integrity}"
    )


    if (
        EXPECTED_EVIDENCE_EVENTS is not None
        and evidence_count
        != EXPECTED_EVIDENCE_EVENTS
    ):
        raise RuntimeError(
            "Unexpected evidence count"
        )

    if evidence_integrity != "ok":
        raise RuntimeError(
            "Evidence DB integrity failed"
        )

    if correlation_integrity != "ok":
        raise RuntimeError(
            "Correlation DB integrity failed"
        )


    correlation_run = correlation.execute(
        """
        SELECT
            run_id
        FROM runs
        WHERE engine_version = ?
          AND status = 'COMPLETED'
        ORDER BY completed_utc DESC
        LIMIT 1
        """,
        (CORRELATION_VERSION,),
    ).fetchone()


    if correlation_run is None:
        raise RuntimeError(
            "Completed correlation run missing"
        )


    correlation_run_id = (
        correlation_run["run_id"]
    )


    cluster_run = correlation.execute(
        """
        SELECT
            cluster_run_id
        FROM cluster_runs
        WHERE correlation_run_id = ?
          AND cluster_version = ?
          AND status = 'COMPLETED'
        ORDER BY completed_utc DESC
        LIMIT 1
        """,
        (
            correlation_run_id,
            CLUSTER_VERSION,
        ),
    ).fetchone()


    if cluster_run is None:
        raise RuntimeError(
            "Completed cluster run missing"
        )


    cluster_run_id = (
        cluster_run["cluster_run_id"]
    )


    print()
    print("SOURCE RUNS")
    print(
        f"Correlation: {correlation_run_id}"
    )
    print(
        f"Clusters:    {cluster_run_id}"
    )


    # ------------------------------------------------------------
    # Load candidate clusters
    # ------------------------------------------------------------

    candidates = correlation.execute(
        """
        SELECT *
        FROM candidate_clusters
        WHERE correlation_run_id = ?
          AND candidate_version = ?
        ORDER BY start_timestamp
        """,
        (
            correlation_run_id,
            CANDIDATE_VERSION,
        ),
    ).fetchall()


    candidate_members = defaultdict(list)

    for row in correlation.execute(
        """
        SELECT
            ce.candidate_id,
            ce.event_uid,
            ce.source_tool,
            ce.evidence_family
        FROM candidate_cluster_events ce
        JOIN candidate_clusters c
          ON c.candidate_id =
             ce.candidate_id
        WHERE c.correlation_run_id = ?
          AND c.candidate_version = ?
        """,
        (
            correlation_run_id,
            CANDIDATE_VERSION,
        ),
    ):

        candidate_members[
            row["candidate_id"]
        ].append(row)


    # ------------------------------------------------------------
    # Load core clusters
    # ------------------------------------------------------------

    clusters = correlation.execute(
        """
        SELECT *
        FROM clusters
        WHERE cluster_run_id = ?
        """,
        (cluster_run_id,),
    ).fetchall()


    cluster_members = defaultdict(list)

    for row in correlation.execute(
        """
        SELECT
            ce.cluster_id,
            ce.event_uid,
            ce.source_tool,
            ce.evidence_family,
            ce.membership_role
        FROM cluster_events ce
        JOIN clusters c
          ON c.cluster_id =
             ce.cluster_id
        WHERE c.cluster_run_id = ?
        """,
        (cluster_run_id,),
    ):

        cluster_members[
            row["cluster_id"]
        ].append(row)


    # ------------------------------------------------------------
    # Fetch all evidence referenced by
    # clusters/candidates.
    # ------------------------------------------------------------

    referenced_uids = set()

    for members in candidate_members.values():
        for member in members:
            referenced_uids.add(
                member["event_uid"]
            )

    for members in cluster_members.values():
        for member in members:
            referenced_uids.add(
                member["event_uid"]
            )


    evidence_rows = fetch_events(
        evidence,
        referenced_uids,
    )


    missing = (
        referenced_uids
        - set(evidence_rows)
    )

    if missing:
        raise RuntimeError(
            f"{len(missing)} finding evidence "
            "references are missing"
        )


    # ------------------------------------------------------------
    # Load attributes only for referenced evidence events.
    # ------------------------------------------------------------

    evidence_attributes = defaultdict(list)

    referenced_uid_list = sorted(
        referenced_uids
    )

    ATTRIBUTE_BATCH_SIZE = 500

    for offset in range(
        0,
        len(referenced_uid_list),
        ATTRIBUTE_BATCH_SIZE,
    ):

        batch = referenced_uid_list[
            offset:
            offset + ATTRIBUTE_BATCH_SIZE
        ]

        placeholders = ",".join(
            "?" for _ in batch
        )

        rows = evidence.execute(
            f"""
            SELECT
                event_uid,
                attribute_key,
                attribute_value
            FROM attributes
            WHERE event_uid
                IN ({placeholders})
            """,
            tuple(batch),
        )

        for attr in rows:

            evidence_attributes[
                attr["event_uid"]
            ].append(
                (
                    attr["attribute_key"],
                    attr["attribute_value"],
                )
            )


    # Stronger multi-family core clusters suppress
    # redundant candidate-only findings when the
    # full candidate evidence set is already contained
    # within the core cluster.

    multi_family_core_sets = []

    for cluster in clusters:

        if (
            cluster["independent_family_count"]
            < 2
        ):
            continue

        core_uids = {
            member["event_uid"]
            for member in cluster_members[
                cluster["cluster_id"]
            ]
        }

        if core_uids:
            multi_family_core_sets.append(
                core_uids
            )


    print()
    print("INVESTIGATION INPUT")
    print(
        f"Core clusters:       "
        f"{len(clusters):,}"
    )
    print(
        f"Candidate clusters:  "
        f"{len(candidates):,}"
    )
    print(
        f"Referenced events:   "
        f"{len(referenced_uids):,}"
    )


    # ------------------------------------------------------------
    # Hayabusa severity distribution.
    # ------------------------------------------------------------

    hayabusa_severity = Counter()

    for row in evidence_rows.values():

        if row["source_tool"] != "hayabusa":
            continue

        hayabusa_severity[
            normalize_severity(
                row["severity"]
            )
        ] += 1


    print()
    print("HAYABUSA SEVERITY DISTRIBUTION")

    for severity in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
        "UNKNOWN",
    ):

        print(
            f"{severity:<10} "
            f"{hayabusa_severity[severity]:,}"
        )


    # ------------------------------------------------------------
    # Initialize findings database.
    # ------------------------------------------------------------

    initialize_findings_db(
        findings
    )


    existing_run = findings.execute(
        """
        SELECT run_id
        FROM runs
        WHERE engine_version = ?
          AND correlation_run_id = ?
          AND cluster_run_id = ?
          AND status = 'COMPLETED'
        LIMIT 1
        """,
        (
            ENGINE_VERSION,
            correlation_run_id,
            cluster_run_id,
        ),
    ).fetchone()


    if existing_run:

        print()
        print(
            "Findings Engine v1 already "
            "completed."
        )
        print(
            f"Run ID: {existing_run['run_id']}"
        )

        raise SystemExit(0)


    started = utc_now()

    run_id = hashlib.sha256(
        (
            CASE
            + "|"
            + ENGINE_VERSION
            + "|"
            + correlation_run_id
            + "|"
            + cluster_run_id
            + "|"
            + started
        ).encode("utf-8")
    ).hexdigest()


    findings.execute(
        """
        INSERT INTO runs (
            run_id,
            case_id,
            engine_version,
            correlation_run_id,
            cluster_run_id,
            started_utc,
            status
        )
        VALUES (
            ?, ?, ?, ?, ?, ?,
            'RUNNING'
        )
        """,
        (
            run_id,
            CASE,
            ENGINE_VERSION,
            correlation_run_id,
            cluster_run_id,
            started,
        ),
    )

    findings.commit()


    created_candidate = 0
    created_core_cross_artifact = 0
    created_detection = 0
    created_prefetch_standalone = 0
    created_powershell_history = 0
    created_sparse_artifact = 0
    skipped_detection = 0
    suppressed_candidate = 0


    try:

        findings.execute("BEGIN")


        # --------------------------------------------------------
        # Type 1:
        # Cross-artifact execution leads.
        # --------------------------------------------------------

        for candidate in candidates:

            candidate_id = (
                candidate["candidate_id"]
            )

            members = candidate_members[
                candidate_id
            ]

            candidate_uids = {
                member["event_uid"]
                for member in members
            }

            covered_by_core = any(
                candidate_uids
                and candidate_uids.issubset(
                    core_uids
                )
                for core_uids
                in multi_family_core_sets
            )

            if covered_by_core:
                suppressed_candidate += 1
                continue


            executables, shared_paths = (
                extract_candidate_shared_values(
                    candidate[
                        "shared_keys_json"
                    ]
                )
            )


            event_rows = [
                evidence_rows[
                    member["event_uid"]
                ]
                for member in members
            ]


            paths = set(shared_paths)

            for event in event_rows:

                for key in (
                    "path",
                    "target_path",
                ):

                    value = (
                        event[key] or ""
                    ).strip()

                    if value:
                        paths.add(value)


            if len(executables) == 1:

                title = (
                    "Cross-artifact activity "
                    "correlation: "
                    + executables[0]
                )

            else:

                title = (
                    "Cross-artifact activity "
                    "correlation"
                )


            summary = (
                "Multiple independent artifact "
                "families reference the same "
                "executable within the correlation "
                "time window. This is an "
                "investigation lead only and does "
                "not by itself prove execution or "
                "maliciousness."
            )


            finding_id = make_finding_id(
                "CROSS_ARTIFACT_ACTIVITY_LEAD",
                candidate_id,
            )


            findings.execute(
                """
                INSERT INTO findings (
                    finding_id,
                    run_id,
                    case_id,
                    finding_type,
                    state,
                    confidence,
                    severity,
                    title,
                    summary,
                    source_kind,
                    source_id,
                    start_timestamp,
                    end_timestamp,
                    independent_family_count,
                    evidence_count,
                    evidence_families_json,
                    source_tools_json,
                    detection_rules_json,
                    executables_json,
                    paths_json,
                    created_utc
                )
                VALUES (
                    ?, ?, ?,
                    'CROSS_ARTIFACT_ACTIVITY_LEAD',
                    'REVIEW_REQUIRED',
                    'MEDIUM',
                    'UNASSESSED',
                    ?, ?,
                    'CANDIDATE_CLUSTER',
                    ?,
                    ?, ?,
                    ?, ?,
                    ?, ?,
                    '[]',
                    ?, ?,
                    ?
                )
                """,
                (
                    finding_id,
                    run_id,
                    CASE,

                    title,
                    summary,

                    candidate_id,

                    candidate[
                        "start_timestamp"
                    ],

                    candidate[
                        "end_timestamp"
                    ],

                    candidate[
                        "independent_family_count"
                    ],

                    len(members),

                    candidate[
                        "evidence_families_json"
                    ],

                    candidate[
                        "source_tools_json"
                    ],

                    json.dumps(
                        executables
                    ),

                    json.dumps(
                        sorted(paths)
                    ),

                    utc_now(),
                ),
            )


            for member in members:

                findings.execute(
                    """
                    INSERT INTO finding_evidence (
                        finding_id,
                        event_uid,
                        source_tool,
                        evidence_family,
                        evidence_role
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        member["event_uid"],
                        member["source_tool"],
                        member[
                            "evidence_family"
                        ],
                        (
                            "EXECUTION_EVIDENCE"
                            if member[
                                "evidence_family"
                            ] == "PREFETCH"
                            else
                            "FILESYSTEM_EVIDENCE"
                        ),
                    ),
                )


            created_candidate += 1


        # --------------------------------------------------------
        # Type 1B:
        # Multi-family core-cluster leads.
        #
        # A core cluster supported by two or more independent
        # forensic evidence families becomes an investigation
        # lead even when Hayabusa severity is INFO/LOW.
        #
        # This represents corroboration, not maliciousness.
        # --------------------------------------------------------

        for cluster in clusters:

            if (
                cluster["independent_family_count"]
                < 2
            ):
                continue

            cluster_id = cluster["cluster_id"]

            members = cluster_members[
                cluster_id
            ]

            event_rows = [
                evidence_rows[
                    member["event_uid"]
                ]
                for member in members
            ]

            executables = set()
            paths = set()
            rules = set()
            service_names = set()

            for event in event_rows:

                executable = (
                    event["executable"] or ""
                ).strip()

                if executable:
                    executables.add(executable)

                for key in (
                    "path",
                    "target_path",
                ):
                    value = (
                        event[key] or ""
                    ).strip()

                    if value:
                        paths.add(value)

                        name = Path(
                            value.replace(
                                "\\",
                                "/",
                            )
                        ).name.lower()

                        match = re.match(
                            r"^(.+?\.exe)-"
                            r"[0-9a-f]{8}\.pf$",
                            name,
                            re.IGNORECASE,
                        )

                        if match:
                            executables.add(
                                match.group(1)
                            )

                if (
                    event["source_tool"]
                    == "hayabusa"
                ):
                    rule = (
                        event["detection_rule"]
                        or event["description"]
                        or ""
                    ).strip()

                    if rule:
                        rules.add(rule)

            # Service-name enrichment from attributes
            # belonging to evidence already inside this cluster.

            for event in event_rows:

                event_uid = event["event_uid"]

                for (
                    attribute_key,
                    attribute_value,
                ) in evidence_attributes.get(
                    event_uid,
                    [],
                ):

                    key = (
                        attribute_key
                        or ""
                    ).strip().lower()

                    value = str(
                        attribute_value
                        or ""
                    )

                    if not value:
                        continue

                    if key in {
                        "service_name",
                        "servicename",
                        "svc",
                    }:

                        candidate_service = (
                            value.strip()
                        )

                        if candidate_service:
                            service_names.add(
                                candidate_service
                            )

                    match = re.search(
                        r'"ServiceName"\s*,\s*"#text"\s*:\s*"([^"]+)"',
                        value,
                        re.IGNORECASE,
                    )

                    if match:
                        service_names.add(
                            match.group(1).strip()
                        )

                    match = re.search(
                        r"['\"]Svc['\"]\s*:\s*['\"]([^'\"]+)['\"]",
                        value,
                        re.IGNORECASE,
                    )

                    if match:
                        service_names.add(
                            match.group(1).strip()
                        )

                    match = re.search(
                        r'"PayloadData1"\s*:\s*"Name:\s*([^"]+)"',
                        value,
                        re.IGNORECASE,
                    )

                    if match:
                        service_names.add(
                            match.group(1).strip()
                        )


            finding_id = make_finding_id(
                "CORE_CROSS_ARTIFACT_LEAD",
                cluster_id,
            )

            title = (
                "Cross-artifact forensic lead"
            )

            if executables:
                title += (
                    ": "
                    + sorted(executables)[0]
                )

            summary = (
                "Multiple independent forensic "
                "evidence families corroborate "
                "activity within the same core "
                "cluster. This is an investigation "
                "lead only; no maliciousness "
                "determination has been made."
            )

            if service_names:
                summary += (
                    " Observed service name(s): "
                    + ", ".join(
                        sorted(service_names)
                    )
                    + "."
                )

            findings.execute(
                """
                INSERT INTO findings (
                    finding_id,
                    run_id,
                    case_id,
                    finding_type,
                    state,
                    confidence,
                    severity,
                    title,
                    summary,
                    source_kind,
                    source_id,
                    start_timestamp,
                    end_timestamp,
                    independent_family_count,
                    evidence_count,
                    evidence_families_json,
                    source_tools_json,
                    detection_rules_json,
                    executables_json,
                    paths_json,
                    created_utc
                )
                VALUES (
                    ?, ?, ?,
                    'CORE_CROSS_ARTIFACT_LEAD',
                    'REVIEW_REQUIRED',
                    'HIGH',
                    'UNASSESSED',
                    ?, ?,
                    'CORE_CLUSTER',
                    ?,
                    ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?
                )
                """,
                (
                    finding_id,
                    run_id,
                    CASE,

                    title,
                    summary,

                    cluster_id,

                    cluster[
                        "start_timestamp"
                    ],
                    cluster[
                        "end_timestamp"
                    ],

                    cluster[
                        "independent_family_count"
                    ],

                    len(members),

                    cluster[
                        "evidence_families_json"
                    ],

                    cluster[
                        "source_tools_json"
                    ],

                    json.dumps(
                        sorted(rules)
                    ),

                    json.dumps(
                        sorted(executables)
                    ),

                    json.dumps(
                        sorted(paths)
                    ),

                    utc_now(),
                ),
            )

            for member in members:

                tool = member["source_tool"]

                role = (
                    "DETECTION_ENRICHMENT"
                    if tool == "hayabusa"
                    else
                    (
                        "CORE_EVIDENCE"
                        if member[
                            "membership_role"
                        ] == "CORE"
                        else
                        "CORROBORATING_ATTACHMENT"
                    )
                )

                findings.execute(
                    """
                    INSERT INTO finding_evidence (
                        finding_id,
                        event_uid,
                        source_tool,
                        evidence_family,
                        evidence_role
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        member["event_uid"],
                        tool,
                        member[
                            "evidence_family"
                        ],
                        role,
                    ),
                )

            created_core_cross_artifact += 1


        # --------------------------------------------------------
        # Type 1C:
        # PowerShell PSReadLine history leads.
        #
        # PSReadLine does not provide per-command timestamps.
        # These findings therefore preserve the command as
        # historical evidence without assigning event time.
        # --------------------------------------------------------

        ps_history_rows = evidence.execute(
            """
            SELECT *
            FROM events
            WHERE case_id = ?
              AND source_tool =
                  'powershell_history'
            ORDER BY source_id, event_uid
            """,
            (CASE,),
        ).fetchall()

        for event in ps_history_rows:

            command = (
                event["command_line"]
                or ""
            ).strip()

            if not command:
                continue

            low = command.lower()

            lead_kind = None

            if (
                "drivers\\etc\\hosts" in low
                or "drivers/etc/hosts" in low
            ):
                lead_kind = (
                    "hosts file modification"
                )

            elif (
                "disablerealtimemonitoring"
                in low
            ):
                lead_kind = (
                    "Defender real-time "
                    "monitoring change"
                )

            elif (
                "add-mppreference"
                in low
                and "exclusionpath"
                in low
            ):
                lead_kind = (
                    "Defender exclusion change"
                )

            elif (
                "noautoupdate"
                in low
            ):
                lead_kind = (
                    "Windows Update policy change"
                )

            if lead_kind is None:
                continue

            source_id = (
                event["event_uid"]
            )

            finding_id = make_finding_id(
                "POWERSHELL_HISTORY_LEAD",
                source_id,
            )

            title = (
                "PowerShell history lead: "
                + lead_kind
            )

            summary = (
                "PSReadLine command history "
                "records the following command: "
                + command
                + " This is historical command "
                "evidence only; PSReadLine does "
                "not provide a per-command "
                "timestamp and no maliciousness "
                "determination has been made."
            )

            attributes = dict(
                evidence.execute(
                    """
                    SELECT
                        attribute_key,
                        attribute_value
                    FROM attributes
                    WHERE event_uid = ?
                    """,
                    (
                        event["event_uid"],
                    ),
                ).fetchall()
            )

            executables = []

            paths = []

            if event["path"]:
                paths.append(
                    event["path"]
                )

            evidence_families = [
                "POWERSHELL_HISTORY"
            ]

            source_tools = [
                "powershell_history"
            ]

            findings.execute(
                """
                INSERT INTO findings (
                    finding_id,
                    run_id,
                    case_id,
                    finding_type,
                    state,
                    confidence,
                    severity,
                    title,
                    summary,
                    source_kind,
                    source_id,
                    start_timestamp,
                    end_timestamp,
                    independent_family_count,
                    evidence_count,
                    evidence_families_json,
                    source_tools_json,
                    detection_rules_json,
                    executables_json,
                    paths_json,
                    created_utc
                )
                VALUES (
                    ?, ?, ?,
                    'POWERSHELL_HISTORY_LEAD',
                    'REVIEW_REQUIRED',
                    'HIGH',
                    'UNASSESSED',
                    ?, ?,
                    'EVIDENCE_EVENT',
                    ?,
                    NULL,
                    NULL,
                    1,
                    1,
                    ?, ?,
                    '[]',
                    ?, ?,
                    ?
                )
                """,
                (
                    finding_id,
                    run_id,
                    CASE,

                    title,
                    summary,

                    event["event_uid"],

                    json.dumps(
                        evidence_families
                    ),

                    json.dumps(
                        source_tools
                    ),

                    json.dumps(
                        executables
                    ),

                    json.dumps(
                        paths
                    ),

                    utc_now(),
                ),
            )

            findings.execute(
                """
                INSERT INTO finding_evidence (
                    finding_id,
                    event_uid,
                    source_tool,
                    evidence_family,
                    evidence_role
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    event["event_uid"],
                    "powershell_history",
                    "POWERSHELL_HISTORY",
                    "COMMAND_HISTORY_EVIDENCE",
                ),
            )

            created_powershell_history += 1


        # --------------------------------------------------------
        # Type 2:
        # Hayabusa detection leads.
        #
        # Only MEDIUM/HIGH/CRITICAL become
        # findings. INFO/LOW remain available
        # in correlation.db but do not flood
        # the investigation queue.
        # --------------------------------------------------------

        for cluster in clusters:

            cluster_id = (
                cluster["cluster_id"]
            )

            members = cluster_members[
                cluster_id
            ]


            hayabusa_events = []

            for member in members:

                event = evidence_rows[
                    member["event_uid"]
                ]

                if (
                    event["source_tool"]
                    == "hayabusa"
                ):
                    hayabusa_events.append(
                        event
                    )


            if not hayabusa_events:
                continue


            severities = [
                normalize_severity(
                    event["severity"]
                )
                for event in hayabusa_events
            ]


            max_severity = max(
                severities,
                key=lambda value:
                    SEVERITY_RANK[value],
            )


            if (
                SEVERITY_RANK[
                    max_severity
                ]
                <
                SEVERITY_RANK["MEDIUM"]
            ):

                skipped_detection += 1
                continue


            rules = sorted({
                (
                    event[
                        "detection_rule"
                    ]
                    or
                    event[
                        "description"
                    ]
                    or
                    "Unnamed Hayabusa rule"
                ).strip()
                for event in hayabusa_events
            })


            if len(rules) == 1:

                title = (
                    "Detection lead: "
                    + rules[0]
                )

            else:

                title = (
                    "Detection lead: "
                    + rules[0]
                    + f" (+{len(rules)-1} related)"
                )


            summary = (
                "Hayabusa produced one or more "
                "detections for Windows event "
                "evidence in this cluster. "
                "EvtxECmd and Hayabusa describe "
                "the same underlying EVTX "
                "family, so they are not counted "
                "as independent corroborating "
                "evidence. Analyst review is "
                "required before any incident "
                "conclusion."
            )


            finding_id = make_finding_id(
                "HAYABUSA_DETECTION_LEAD",
                cluster_id,
            )


            findings.execute(
                """
                INSERT INTO findings (
                    finding_id,
                    run_id,
                    case_id,
                    finding_type,
                    state,
                    confidence,
                    severity,
                    title,
                    summary,
                    source_kind,
                    source_id,
                    start_timestamp,
                    end_timestamp,
                    independent_family_count,
                    evidence_count,
                    evidence_families_json,
                    source_tools_json,
                    detection_rules_json,
                    executables_json,
                    paths_json,
                    created_utc
                )
                VALUES (
                    ?, ?, ?,
                    'HAYABUSA_DETECTION_LEAD',
                    'REVIEW_REQUIRED',
                    'HIGH',
                    ?,
                    ?, ?,
                    'CORE_CLUSTER',
                    ?,
                    ?, ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    '[]',
                    '[]',
                    ?
                )
                """,
                (
                    finding_id,
                    run_id,
                    CASE,

                    max_severity,

                    title,
                    summary,

                    cluster_id,

                    cluster[
                        "start_timestamp"
                    ],

                    cluster[
                        "end_timestamp"
                    ],

                    cluster[
                        "independent_family_count"
                    ],

                    len(members),

                    cluster[
                        "evidence_families_json"
                    ],

                    cluster[
                        "source_tools_json"
                    ],

                    json.dumps(rules),

                    utc_now(),
                ),
            )


            for member in members:

                family = member[
                    "evidence_family"
                ]

                tool = member[
                    "source_tool"
                ]

                role = (
                    "DETECTION_ENRICHMENT"
                    if tool == "hayabusa"
                    else
                    "UNDERLYING_EVTX"
                )


                findings.execute(
                    """
                    INSERT INTO finding_evidence (
                        finding_id,
                        event_uid,
                        source_tool,
                        evidence_family,
                        evidence_role
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        member["event_uid"],
                        tool,
                        family,
                        role,
                    ),
                )


            created_detection += 1


        # --------------------------------------------------------
        # Type 3:
        # Sparse / standalone artifact investigation leads.
        #
        # This fallback runs only when the normal correlation,
        # detection, and command-history paths produced no
        # findings. It preserves potentially useful standalone
        # forensic observations without asserting maliciousness.
        #
        # Current implementation supports LNK evidence using
        # artifact semantics rather than case-specific names.
        # --------------------------------------------------------

        normal_finding_count = (
            created_candidate
            + created_core_cross_artifact
            + created_detection
            + created_powershell_history
        )

        if normal_finding_count == 0:

            event_columns = {
                row["name"]
                for row in evidence.execute(
                    "PRAGMA table_info(events)"
                )
            }

            required_lnk_columns = {
                "event_uid",
                "case_id",
                "source_tool",
                "timestamp",
                "target_path",
            }

            if required_lnk_columns.issubset(
                event_columns
            ):

                lnk_rows = evidence.execute(
                    """
                    SELECT
                        event_uid,
                        timestamp,
                        timestamp_source,
                        target_path,
                        event_type,
                        source_tool
                    FROM events
                    WHERE case_id = ?
                      AND source_tool = 'lecmd'
                      AND target_path IS NOT NULL
                      AND TRIM(target_path) <> ''
                      AND timestamp_source LIKE 'LNK.Target%'
                    ORDER BY
                        target_path,
                        timestamp,
                        event_uid
                    """,
                    (CASE,),
                ).fetchall()

                grouped_targets = defaultdict(list)

                executable_extensions = {
                    ".ps1",
                    ".psm1",
                    ".bat",
                    ".cmd",
                    ".vbs",
                    ".vbe",
                    ".js",
                    ".jse",
                    ".wsf",
                    ".wsh",
                    ".hta",
                    ".jar",
                    ".msi",
                    ".msp",
                }

                direct_executable_extensions = {
                    ".exe",
                    ".com",
                    ".scr",
                    ".dll",
                    ".cpl",
                }

                package_extensions = {
                    ".zip",
                    ".rar",
                    ".7z",
                    ".iso",
                    ".img",
                    ".cab",
                }

                writable_markers = (
                    "\\downloads\\",
                    "\\desktop\\",
                    "\\appdata\\",
                    "\\temp\\",
                    "\\users\\public\\",
                    "\\programdata\\",
                )

                for event in lnk_rows:

                    target = (
                        event["target_path"]
                        or ""
                    ).strip()

                    if not target:
                        continue

                    normalized_target = (
                        target
                        .replace("/", "\\")
                        .lower()
                    )

                    suffix = Path(
                        normalized_target
                    ).suffix.lower()

                    supported_extensions = (
                        executable_extensions
                        | direct_executable_extensions
                        | package_extensions
                    )

                    if suffix not in supported_extensions:
                        continue

                    if suffix in direct_executable_extensions:

                        user_download_or_desktop = (
                            "\\downloads\\"
                            in normalized_target
                            or
                            "\\desktop\\"
                            in normalized_target
                            or
                            "\\temp\\"
                            in normalized_target
                            or
                            "\\users\\public\\"
                            in normalized_target
                        )

                        if not user_download_or_desktop:
                            continue

                    if not any(
                        marker in normalized_target
                        for marker in writable_markers
                    ):
                        continue

                    grouped_targets[
                        normalized_target
                    ].append(event)

                for (
                    normalized_target,
                    target_events
                ) in sorted(
                    grouped_targets.items()
                ):

                    if not target_events:
                        continue

                    original_target = (
                        target_events[0][
                            "target_path"
                        ]
                    )

                    suffix = Path(
                        normalized_target
                    ).suffix.lower()

                    if suffix in (
                        executable_extensions
                        | direct_executable_extensions
                    ):

                        lead_class = (
                            "EXECUTABLE_OR_SCRIPT"
                        )

                        confidence = "MEDIUM"

                        title = (
                            "Standalone LNK execution "
                            "artifact lead: "
                            + Path(
                                original_target
                            ).name
                        )

                        summary = (
                            "Windows shortcut evidence "
                            "references an executable or "
                            "script target located in a "
                            "user-writable path. This is "
                            "an investigation lead only. "
                            "The shortcut artifact does "
                            "not by itself prove execution, "
                            "maliciousness, or user intent."
                        )

                    else:

                        lead_class = (
                            "ARCHIVE_OR_PACKAGE"
                        )

                        confidence = "LOW"

                        title = (
                            "Standalone LNK package "
                            "artifact lead: "
                            + Path(
                                original_target
                            ).name
                        )

                        summary = (
                            "Windows shortcut evidence "
                            "references an archive or "
                            "package located in a "
                            "user-writable path. This is "
                            "an investigation lead only. "
                            "The artifact name or path "
                            "does not by itself establish "
                            "maliciousness, execution, "
                            "or user intent."
                        )

                    event_uids = sorted({
                        event["event_uid"]
                        for event in target_events
                        if event["event_uid"]
                    })

                    if not event_uids:
                        continue

                    timestamps = sorted(
                        event["timestamp"]
                        for event in target_events
                        if event["timestamp"]
                    )

                    start_timestamp = (
                        timestamps[0]
                        if timestamps
                        else None
                    )

                    end_timestamp = (
                        timestamps[-1]
                        if timestamps
                        else None
                    )

                    source_id = (
                        "LNK|"
                        + lead_class
                        + "|"
                        + normalized_target
                    )

                    finding_id = make_finding_id(
                        "STANDALONE_ARTIFACT_LEAD",
                        source_id,
                    )

                    findings.execute(
                        """
                        INSERT INTO findings (
                            finding_id,
                            run_id,
                            case_id,
                            finding_type,
                            state,
                            confidence,
                            severity,
                            title,
                            summary,
                            source_kind,
                            source_id,
                            start_timestamp,
                            end_timestamp,
                            independent_family_count,
                            evidence_count,
                            evidence_families_json,
                            source_tools_json,
                            detection_rules_json,
                            executables_json,
                            paths_json,
                            created_utc
                        )
                        VALUES (
                            ?, ?, ?,
                            'STANDALONE_ARTIFACT_LEAD',
                            'REVIEW_REQUIRED',
                            ?,
                            'UNASSESSED',
                            ?, ?,
                            'STANDALONE_ARTIFACT',
                            ?,
                            ?, ?,
                            1,
                            ?,
                            ?,
                            ?,
                            '[]',
                            ?,
                            ?,
                            ?
                        )
                        """,
                        (
                            finding_id,
                            run_id,
                            CASE,

                            confidence,
                            title,
                            summary,

                            source_id,

                            start_timestamp,
                            end_timestamp,

                            len(event_uids),

                            json.dumps(
                                ["LNK"]
                            ),

                            json.dumps(
                                ["lecmd"]
                            ),

                            (
                                json.dumps(
                                    [original_target]
                                )
                                if suffix
                                in executable_extensions
                                else "[]"
                            ),

                            json.dumps(
                                [original_target]
                            ),

                            utc_now(),
                        ),
                    )

                    for event_uid in event_uids:

                        findings.execute(
                            """
                            INSERT INTO
                                finding_evidence (
                                    finding_id,
                                    event_uid,
                                    source_tool,
                                    evidence_family,
                                    evidence_role
                                )
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                finding_id,
                                event_uid,
                                "lecmd",
                                "LNK",
                                (
                                    "STANDALONE_EXECUTION_LEAD"
                                    if suffix
                                    in executable_extensions
                                    else
                                    "STANDALONE_PACKAGE_LEAD"
                                ),
                            ),
                        )

                    created_sparse_artifact += 1


        created_prefetch_standalone = (
            create_prefetch_standalone_findings(
                evidence=evidence,
                findings=findings,
                run_id=run_id,
                case_id=CASE,
                make_finding_id=make_finding_id,
                utc_now=utc_now,
            )
        )

        total_created = (
            created_candidate
            + created_core_cross_artifact
            + created_detection
            + created_powershell_history
            + created_sparse_artifact
            + created_prefetch_standalone
        )


        findings.execute(
            """
            UPDATE runs
            SET
                status = 'COMPLETED',
                completed_utc = ?,
                finding_count = ?,
                error_message = NULL
            WHERE run_id = ?
            """,
            (
                utc_now(),
                total_created,
                run_id,
            ),
        )


        findings.commit()


    except Exception as exc:

        findings.rollback()

        findings.execute(
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
                str(exc),
                run_id,
            ),
        )

        findings.commit()

        raise


    # ------------------------------------------------------------
    # Results
    # ------------------------------------------------------------

    total_findings = findings.execute(
        """
        SELECT COUNT(*)
        FROM findings
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()[0]


    evidence_links = findings.execute(
        """
        SELECT COUNT(*)
        FROM finding_evidence fe
        JOIN findings f
          ON f.finding_id =
             fe.finding_id
        WHERE f.run_id = ?
        """,
        (run_id,),
    ).fetchone()[0]


    print()
    print("=" * 72)
    print("FINDINGS ENGINE RESULTS")
    print("=" * 72)

    print(
        f"Cross-artifact leads:   "
        f"{created_candidate:,}"
    )

    print(
        f"Detection leads:        "
        f"{created_detection:,}"
    )

    print(
        f"Low/info detections skipped: "
        f"{skipped_detection:,}"
    )

    print(
        f"Total findings/leads:   "
        f"{total_findings:,}"
    )

    print(
        f"Evidence links:         "
        f"{evidence_links:,}"
    )


    print()
    print("FINDINGS BY TYPE")


    for row in findings.execute(
        """
        SELECT
            finding_type,
            COUNT(*) AS count
        FROM findings
        WHERE run_id = ?
        GROUP BY finding_type
        ORDER BY count DESC
        """,
        (run_id,),
    ):

        print(
            f"{row['finding_type']:<35} "
            f"{row['count']:,}"
        )


    print()
    print("FINDINGS BY SEVERITY")


    for row in findings.execute(
        """
        SELECT
            severity,
            COUNT(*) AS count
        FROM findings
        WHERE run_id = ?
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'INFO' THEN 5
                WHEN 'UNASSESSED' THEN 6
                ELSE 7
            END
        """,
        (run_id,),
    ):

        print(
            f"{row['severity']:<12} "
            f"{row['count']:,}"
        )


    print()
    print("TOP INVESTIGATION LEADS")


    rows = findings.execute(
        """
        SELECT
            finding_id,
            finding_type,
            severity,
            confidence,
            title,
            independent_family_count,
            evidence_count,
            start_timestamp
        FROM findings
        WHERE run_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'UNASSESSED' THEN 4
                ELSE 5
            END,
            independent_family_count DESC,
            evidence_count DESC,
            start_timestamp
        LIMIT 25
        """,
        (run_id,),
    ).fetchall()


    for row in rows:

        print()
        print(
            f"{row['severity']} | "
            f"{row['finding_type']}"
        )

        print(
            f"  {row['title']}"
        )

        print(
            "  confidence: "
            f"{row['confidence']}"
        )

        print(
            "  independent families: "
            f"{row['independent_family_count']}"
        )

        print(
            "  evidence events: "
            f"{row['evidence_count']}"
        )

        print(
            f"  finding_id: "
            f"{row['finding_id']}"
        )


    integrity = findings.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    print()
    print(
        "Findings DB integrity: "
        f"{integrity}"
    )


    if integrity != "ok":
        raise RuntimeError(
            "Findings DB integrity failure"
        )


finally:

    findings.close()
    correlation.close()
    evidence.close()


print()
print("=" * 72)
print("FINDINGS / INVESTIGATION ENGINE V1: COMPLETE")
print("=" * 72)

print()
print("evidence.db:     READ-ONLY / UNCHANGED")
print("correlation.db:  READ-ONLY / UNCHANGED")
print("findings.db:     CREATED")
print()
print("No automatic maliciousness determination.")
print("All findings retain original event UIDs.")
print()
print("NEXT: QWEN INVESTIGATION CONTEXT / EVIDENCE RETRIEVAL V1")
