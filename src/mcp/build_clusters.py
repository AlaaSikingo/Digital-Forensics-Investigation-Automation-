import argparse
import hashlib
import json
import sqlite3

from collections import defaultdict
from datetime import datetime, timezone
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

ENGINE_VERSION = "1.0"
CLUSTER_VERSION = "1.0"

EXPECTED_EVIDENCE_EVENTS = None


FAMILY_MAP = {
    "evtxecmd": "EVTX",
    "hayabusa": "EVTX",
    "mftecmd": "MFT",
    "pecmd": "PREFETCH",
    "recmd": "REGISTRY",
    "lecmd": "LNK",
}


def utc_now():
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def batches(values, size=500):
    values = list(values)

    for i in range(
        0,
        len(values),
        size,
    ):
        yield values[i:i + size]


class UnionFind:

    def __init__(self):
        self.parent = {}
        self.rank = {}

    def add(self, item):

        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0

    def find(self, item):

        parent = self.parent[item]

        if parent != item:
            self.parent[item] = self.find(
                parent
            )

        return self.parent[item]

    def union(self, a, b):

        self.add(a)
        self.add(b)

        root_a = self.find(a)
        root_b = self.find(b)

        if root_a == root_b:
            return

        if (
            self.rank[root_a]
            <
            self.rank[root_b]
        ):
            root_a, root_b = (
                root_b,
                root_a,
            )

        self.parent[root_b] = root_a

        if (
            self.rank[root_a]
            ==
            self.rank[root_b]
        ):
            self.rank[root_a] += 1


def initialize_cluster_schema(conn):

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cluster_runs (
            cluster_run_id TEXT PRIMARY KEY,

            correlation_run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,

            cluster_version TEXT NOT NULL,

            started_utc TEXT NOT NULL,
            completed_utc TEXT,

            status TEXT NOT NULL,

            cluster_count INTEGER,
            clustered_event_count INTEGER,
            clustered_edge_count INTEGER,

            error_message TEXT
        );


        CREATE TABLE IF NOT EXISTS clusters (
            cluster_id TEXT PRIMARY KEY,

            cluster_run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,

            cluster_confidence TEXT NOT NULL,

            start_timestamp TEXT,
            end_timestamp TEXT,

            event_count INTEGER NOT NULL,
            edge_count INTEGER NOT NULL,

            independent_family_count INTEGER
                NOT NULL,

            source_tools_json TEXT NOT NULL,
            evidence_families_json TEXT NOT NULL,
            relationship_types_json TEXT NOT NULL,

            has_detection_enrichment INTEGER
                NOT NULL,

            created_utc TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS cluster_events (
            cluster_id TEXT NOT NULL,
            event_uid TEXT NOT NULL,

            source_tool TEXT NOT NULL,
            evidence_family TEXT NOT NULL,

            membership_role TEXT NOT NULL,

            PRIMARY KEY (
                cluster_id,
                event_uid
            )
        );


        CREATE TABLE IF NOT EXISTS cluster_edges (
            cluster_id TEXT NOT NULL,
            edge_uid TEXT NOT NULL,

            relationship_type TEXT NOT NULL,
            confidence TEXT NOT NULL,

            PRIMARY KEY (
                cluster_id,
                edge_uid
            )
        );


        CREATE INDEX IF NOT EXISTS
            idx_cluster_events_uid
            ON cluster_events(event_uid);


        CREATE INDEX IF NOT EXISTS
            idx_cluster_events_family
            ON cluster_events(evidence_family);


        CREATE INDEX IF NOT EXISTS
            idx_cluster_edges_type
            ON cluster_edges(relationship_type);


        CREATE INDEX IF NOT EXISTS
            idx_clusters_families
            ON clusters(
                independent_family_count
            );
        """
    )

    conn.commit()


print("=" * 72)
print("EVIDENCE CLUSTERS V1")
print("=" * 72)


# -----------------------------------------------------------------
# Evidence baseline
# -----------------------------------------------------------------

evidence = evidence_connection()

try:

    evidence_count = evidence.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    ).fetchone()[0]

    evidence_integrity = evidence.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    print()
    print("EVIDENCE BASELINE")
    print(
        f"Events:    {evidence_count:,}"
    )
    print(
        f"Integrity: {evidence_integrity}"
    )

    if (
        EXPECTED_EVIDENCE_EVENTS is not None
        and evidence_count
        != EXPECTED_EVIDENCE_EVENTS
    ):
        raise RuntimeError(
            "Unexpected evidence event count."
        )

    if evidence_integrity != "ok":
        raise RuntimeError(
            "Evidence database integrity "
            "failure."
        )


    correlation = correlation_connection()

    try:

        correlation_integrity = (
            correlation.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
        )

        if correlation_integrity != "ok":
            raise RuntimeError(
                "Correlation DB integrity "
                "failure."
            )


        run = correlation.execute(
            """
            SELECT
                run_id,
                edge_count
            FROM runs
            WHERE engine_version = ?
              AND status = 'COMPLETED'
            ORDER BY completed_utc DESC
            LIMIT 1
            """,
            (ENGINE_VERSION,),
        ).fetchone()

        if run is None:
            raise RuntimeError(
                "Completed correlation v1 "
                "run not found."
            )

        correlation_run_id = (
            run["run_id"]
        )

        expected_edge_count = (
            run["edge_count"]
        )


        print()
        print("CORRELATION BASELINE")
        print(
            f"Run ID: {correlation_run_id}"
        )
        print(
            f"Edges:  {expected_edge_count:,}"
        )


        edges = correlation.execute(
            """
            SELECT
                edge_uid,

                event_uid_a,
                event_uid_b,

                source_tool_a,
                source_tool_b,

                timestamp_a,
                timestamp_b,

                relationship_type,
                confidence,
                score,

                time_delta_seconds
            FROM edges
            WHERE run_id = ?
            """,
            (correlation_run_id,),
        ).fetchall()


        if len(edges) != expected_edge_count:
            raise RuntimeError(
                "Correlation edge count "
                "does not match run metadata."
            )


        # ---------------------------------------------------------
        # Correlation quality gate
        # ---------------------------------------------------------

        print()
        print("=" * 72)
        print("CORRELATION QUALITY GATE")
        print("=" * 72)


        self_edges = [
            edge
            for edge in edges
            if (
                edge["event_uid_a"]
                ==
                edge["event_uid_b"]
            )
        ]

        if self_edges:
            raise RuntimeError(
                "Self-referencing correlation "
                "edges detected."
            )


        referenced = set()

        for edge in edges:
            referenced.add(
                edge["event_uid_a"]
            )
            referenced.add(
                edge["event_uid_b"]
            )


        evidence_rows = {}

        for group in batches(
            referenced
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
                    timestamp_sort,
                    artifact_type,
                    event_type,
                    hostname,
                    username,
                    executable,
                    path,
                    target_path,
                    windows_event_id,
                    channel,
                    detection_rule,
                    severity,
                    description
                FROM events
                WHERE event_uid
                  IN ({placeholders})
                """,
                group,
            )

            for row in rows:
                evidence_rows[
                    row["event_uid"]
                ] = row


        missing = (
            referenced
            - set(evidence_rows)
        )

        if missing:
            raise RuntimeError(
                f"{len(missing)} correlation "
                "event references are missing "
                "from evidence.db."
            )


        confidence_counts = defaultdict(int)
        type_counts = defaultdict(int)
        pair_counts = defaultdict(int)
        degrees = defaultdict(int)


        for edge in edges:

            confidence_counts[
                edge["confidence"]
            ] += 1

            type_counts[
                edge["relationship_type"]
            ] += 1

            pair = tuple(
                sorted(
                    (
                        edge["source_tool_a"],
                        edge["source_tool_b"],
                    )
                )
            )

            pair_counts[pair] += 1

            degrees[
                edge["event_uid_a"]
            ] += 1

            degrees[
                edge["event_uid_b"]
            ] += 1


        print()
        print("CONFIDENCE")

        for key in sorted(
            confidence_counts
        ):
            print(
                f"{key:<12} "
                f"{confidence_counts[key]:,}"
            )


        print()
        print("RELATIONSHIP TYPES")

        for key in sorted(
            type_counts
        ):
            print(
                f"{key:<34} "
                f"{type_counts[key]:,}"
            )


        print()
        print("TOOL PAIRS")

        for pair, count in sorted(
            pair_counts.items()
        ):
            print(
                f"{pair[0]:<12} "
                f"<-> {pair[1]:<12} "
                f"{count:,}"
            )


        max_degree = (
            max(degrees.values())
            if degrees
            else 0
        )

        print()
        print(
            f"Referenced evidence events: "
            f"{len(referenced):,}"
        )

        print(
            f"Maximum event degree:       "
            f"{max_degree:,}"
        )

        print(
            "Self edges:                 0"
        )

        print(
            "Missing evidence refs:      0"
        )


        # ---------------------------------------------------------
        # Core graph
        # ---------------------------------------------------------

        core_edges = [
            edge
            for edge in edges
            if edge["confidence"]
            in {
                "VERY_HIGH",
                "HIGH",
            }
        ]


        medium_edges = [
            edge
            for edge in edges
            if edge["confidence"]
            == "MEDIUM"
        ]


        print()
        print("=" * 72)
        print("CORE CLUSTER CONSTRUCTION")
        print("=" * 72)

        print(
            f"Core edges:    "
            f"{len(core_edges):,}"
        )

        print(
            f"Medium edges:  "
            f"{len(medium_edges):,}"
        )


        uf = UnionFind()

        for edge in core_edges:

            uf.union(
                edge["event_uid_a"],
                edge["event_uid_b"],
            )


        core_components = defaultdict(set)

        for event_uid in uf.parent:

            root = uf.find(
                event_uid
            )

            core_components[
                root
            ].add(event_uid)


        print(
            f"Core components: "
            f"{len(core_components):,}"
        )


        # Original core membership before
        # any medium attachment.
        event_to_core = {}

        for root, members in (
            core_components.items()
        ):

            for event_uid in members:
                event_to_core[
                    event_uid
                ] = root


        cluster_members = {
            root: set(members)
            for root, members
            in core_components.items()
        }

        cluster_edge_map = defaultdict(list)


        # Put every core edge into its
        # corresponding component.
        for edge in core_edges:

            root = event_to_core[
                edge["event_uid_a"]
            ]

            cluster_edge_map[
                root
            ].append(edge)


        medium_attached = 0
        medium_same_core = 0
        medium_cross_core = 0
        medium_unclustered = 0


        # ---------------------------------------------------------
        # Medium edges are allowed only as
        # one-hop attachments to a high
        # confidence core.
        # ---------------------------------------------------------

        for edge in medium_edges:

            a = edge["event_uid_a"]
            b = edge["event_uid_b"]

            core_a = event_to_core.get(a)
            core_b = event_to_core.get(b)


            if (
                core_a is not None
                and core_b is not None
            ):

                if core_a == core_b:

                    cluster_edge_map[
                        core_a
                    ].append(edge)

                    medium_same_core += 1

                else:

                    # Never merge two
                    # independent cores using
                    # only a MEDIUM edge.
                    medium_cross_core += 1

                continue


            if (
                core_a is not None
                and core_b is None
            ):

                cluster_members[
                    core_a
                ].add(b)

                cluster_edge_map[
                    core_a
                ].append(edge)

                medium_attached += 1
                continue


            if (
                core_b is not None
                and core_a is None
            ):

                cluster_members[
                    core_b
                ].add(a)

                cluster_edge_map[
                    core_b
                ].append(edge)

                medium_attached += 1
                continue


            medium_unclustered += 1


        print()
        print(
            "Medium same-core:     "
            f"{medium_same_core:,}"
        )

        print(
            "Medium attachments:   "
            f"{medium_attached:,}"
        )

        print(
            "Medium cross-core:    "
            f"{medium_cross_core:,}"
        )

        print(
            "Medium unclustered:   "
            f"{medium_unclustered:,}"
        )


        # ---------------------------------------------------------
        # Persist clusters
        # ---------------------------------------------------------

        initialize_cluster_schema(
            correlation
        )


        previous = correlation.execute(
            """
            SELECT COUNT(*)
            FROM cluster_runs
            WHERE correlation_run_id = ?
              AND cluster_version = ?
              AND status = 'COMPLETED'
            """,
            (
                correlation_run_id,
                CLUSTER_VERSION,
            ),
        ).fetchone()[0]


        if previous:

            print()
            print(
                "Evidence Clusters v1 "
                "already completed."
            )

            print(
                "No rebuild performed."
            )

            raise SystemExit(0)


        started = utc_now()

        cluster_run_id = hashlib.sha256(
            (
                CASE
                + "|"
                + correlation_run_id
                + "|"
                + CLUSTER_VERSION
                + "|"
                + started
            ).encode("utf-8")
        ).hexdigest()


        correlation.execute(
            """
            INSERT INTO cluster_runs (
                cluster_run_id,
                correlation_run_id,
                case_id,
                cluster_version,
                started_utc,
                status
            )
            VALUES (
                ?, ?, ?, ?, ?,
                'RUNNING'
            )
            """,
            (
                cluster_run_id,
                correlation_run_id,
                CASE,
                CLUSTER_VERSION,
                started,
            ),
        )

        correlation.commit()


        cluster_count = 0
        clustered_events = set()
        clustered_edges = set()

        try:

            correlation.execute(
                "BEGIN"
            )


            for root in sorted(
                cluster_members
            ):

                members = sorted(
                    cluster_members[root]
                )

                component_edges = (
                    cluster_edge_map[root]
                )

                if not members:
                    continue


                cluster_identity = (
                    CLUSTER_VERSION
                    + "|"
                    + "|".join(
                        sorted(
                            event_to_core_uid
                            for event_to_core_uid
                            in core_components[
                                root
                            ]
                        )
                    )
                )

                cluster_id = (
                    hashlib.sha256(
                        cluster_identity.encode(
                            "utf-8"
                        )
                    ).hexdigest()
                )


                tools = set()
                families = set()
                relationships = set()

                timestamps = []

                has_detection = False
                has_medium = False


                for uid in members:

                    row = evidence_rows[uid]

                    tool = (
                        row["source_tool"]
                    )

                    tools.add(tool)

                    families.add(
                        FAMILY_MAP.get(
                            tool,
                            tool.upper(),
                        )
                    )

                    ts = (
                        row["timestamp_sort"]
                    )

                    if ts:
                        timestamps.append(ts)

                    if tool == "hayabusa":
                        has_detection = True


                for edge in component_edges:

                    relationships.add(
                        edge[
                            "relationship_type"
                        ]
                    )

                    if (
                        edge["confidence"]
                        == "MEDIUM"
                    ):
                        has_medium = True


                confidence = (
                    "HIGH"
                    if has_medium
                    else "VERY_HIGH"
                )


                start_timestamp = (
                    min(timestamps)
                    if timestamps
                    else None
                )

                end_timestamp = (
                    max(timestamps)
                    if timestamps
                    else None
                )


                correlation.execute(
                    """
                    INSERT INTO clusters (
                        cluster_id,
                        cluster_run_id,
                        case_id,

                        cluster_confidence,

                        start_timestamp,
                        end_timestamp,

                        event_count,
                        edge_count,

                        independent_family_count,

                        source_tools_json,
                        evidence_families_json,
                        relationship_types_json,

                        has_detection_enrichment,

                        created_utc
                    )
                    VALUES (
                        ?, ?, ?,
                        ?,
                        ?, ?,
                        ?, ?,
                        ?,
                        ?, ?, ?,
                        ?,
                        ?
                    )
                    """,
                    (
                        cluster_id,
                        cluster_run_id,
                        CASE,

                        confidence,

                        start_timestamp,
                        end_timestamp,

                        len(members),
                        len(component_edges),

                        len(families),

                        json.dumps(
                            sorted(tools)
                        ),

                        json.dumps(
                            sorted(families)
                        ),

                        json.dumps(
                            sorted(
                                relationships
                            )
                        ),

                        1
                        if has_detection
                        else 0,

                        utc_now(),
                    ),
                )


                original_core_members = (
                    core_components[root]
                )


                for uid in members:

                    row = evidence_rows[uid]

                    role = (
                        "CORE"
                        if uid
                        in original_core_members
                        else "MEDIUM_ATTACHMENT"
                    )

                    tool = row[
                        "source_tool"
                    ]

                    family = (
                        FAMILY_MAP.get(
                            tool,
                            tool.upper(),
                        )
                    )

                    correlation.execute(
                        """
                        INSERT INTO
                        cluster_events (
                            cluster_id,
                            event_uid,
                            source_tool,
                            evidence_family,
                            membership_role
                        )
                        VALUES (
                            ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            cluster_id,
                            uid,
                            tool,
                            family,
                            role,
                        ),
                    )

                    clustered_events.add(uid)


                for edge in component_edges:

                    correlation.execute(
                        """
                        INSERT INTO
                        cluster_edges (
                            cluster_id,
                            edge_uid,
                            relationship_type,
                            confidence
                        )
                        VALUES (
                            ?, ?, ?, ?
                        )
                        """,
                        (
                            cluster_id,
                            edge["edge_uid"],
                            edge[
                                "relationship_type"
                            ],
                            edge["confidence"],
                        ),
                    )

                    clustered_edges.add(
                        edge["edge_uid"]
                    )


                cluster_count += 1


            correlation.commit()


        except Exception as exc:

            correlation.rollback()

            correlation.execute(
                """
                UPDATE cluster_runs
                SET
                    status = 'FAILED',
                    completed_utc = ?,
                    error_message = ?
                WHERE cluster_run_id = ?
                """,
                (
                    utc_now(),
                    str(exc),
                    cluster_run_id,
                ),
            )

            correlation.commit()

            raise


        correlation.execute(
            """
            UPDATE cluster_runs
            SET
                status = 'COMPLETED',
                completed_utc = ?,
                cluster_count = ?,
                clustered_event_count = ?,
                clustered_edge_count = ?,
                error_message = NULL
            WHERE cluster_run_id = ?
            """,
            (
                utc_now(),
                cluster_count,
                len(clustered_events),
                len(clustered_edges),
                cluster_run_id,
            ),
        )

        correlation.commit()


        # ---------------------------------------------------------
        # Results
        # ---------------------------------------------------------

        print()
        print("=" * 72)
        print("EVIDENCE CLUSTER RESULTS")
        print("=" * 72)

        print(
            f"Clusters:          "
            f"{cluster_count:,}"
        )

        print(
            f"Clustered events:  "
            f"{len(clustered_events):,}"
        )

        print(
            f"Clustered edges:   "
            f"{len(clustered_edges):,}"
        )


        print()
        print(
            "CLUSTERS BY INDEPENDENT "
            "EVIDENCE FAMILY COUNT"
        )


        for row in correlation.execute(
            """
            SELECT
                independent_family_count,
                COUNT(*) AS count
            FROM clusters
            WHERE cluster_run_id = ?
            GROUP BY
                independent_family_count
            ORDER BY
                independent_family_count
            """,
            (cluster_run_id,),
        ):

            print(
                f"{row['independent_family_count']} "
                f"families: "
                f"{row['count']:,}"
            )


        print()
        print("TOP MULTI-FAMILY CLUSTERS")


        rows = correlation.execute(
            """
            SELECT
                cluster_id,
                cluster_confidence,
                start_timestamp,
                end_timestamp,
                event_count,
                edge_count,
                independent_family_count,
                source_tools_json,
                evidence_families_json,
                relationship_types_json
            FROM clusters
            WHERE cluster_run_id = ?
            ORDER BY
                independent_family_count DESC,
                event_count DESC,
                edge_count DESC
            LIMIT 20
            """,
            (cluster_run_id,),
        ).fetchall()


        for row in rows:

            print()
            print(
                "Cluster: "
                f"{row['cluster_id']}"
            )

            print(
                "  confidence: "
                f"{row['cluster_confidence']}"
            )

            print(
                "  events: "
                f"{row['event_count']}"
            )

            print(
                "  edges: "
                f"{row['edge_count']}"
            )

            print(
                "  independent families: "
                f"{row['independent_family_count']}"
            )

            print(
                "  tools: "
                f"{row['source_tools_json']}"
            )

            print(
                "  families: "
                f"{row['evidence_families_json']}"
            )

            print(
                "  relationships: "
                f"{row['relationship_types_json']}"
            )

            print(
                "  time: "
                f"{row['start_timestamp']} "
                f"-> "
                f"{row['end_timestamp']}"
            )


        final_integrity = (
            correlation.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
        )


        print()
        print(
            "Correlation DB integrity: "
            f"{final_integrity}"
        )


        if final_integrity != "ok":
            raise RuntimeError(
                "Correlation DB integrity "
                "failure after clustering."
            )


    finally:
        correlation.close()


finally:
    evidence.close()


print()
print("=" * 72)
print("EVIDENCE CLUSTERS V1: COMPLETE")
print("=" * 72)

print()
print("evidence.db:       UNCHANGED")
print("correlation.db:    edges + clusters")
print()
print(
    "Hayabusa is treated as EVTX "
    "detection enrichment, not an "
    "independent evidence family."
)
print()
print(
    "Medium edges cannot independently "
    "create or merge high-confidence "
    "clusters."
)
print()
print(
    "NEXT: Findings / Investigation Engine v1"
)
