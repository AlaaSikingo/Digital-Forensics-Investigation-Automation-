import argparse
import hashlib
import json
import sqlite3
from collections import defaultdict
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

CORRELATION_VERSION = "1.2"
CANDIDATE_VERSION = "1.1"

FAMILY_MAP = {
    "evtxecmd": "EVTX",
    "hayabusa": "EVTX",
    "mftecmd": "MFT",
    "pecmd": "PREFETCH",
    "recmd": "REGISTRY",
    "lecmd": "LNK",
}


class UnionFind:
    def __init__(self):
        self.parent = {}

    def add(self, item):
        if item not in self.parent:
            self.parent[item] = item

    def find(self, item):
        if self.parent[item] != item:
            self.parent[item] = self.find(
                self.parent[item]
            )
        return self.parent[item]

    def union(self, a, b):
        self.add(a)
        self.add(b)

        ra = self.find(a)
        rb = self.find(b)

        if ra != rb:
            self.parent[rb] = ra


def open_evidence():
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


def open_correlation():
    conn = sqlite3.connect(
        str(CORRELATION_DB)
    )

    conn.row_factory = sqlite3.Row

    return conn


print("=" * 72)
print("CROSS-ARTIFACT CANDIDATE CLUSTERS V1")
print("=" * 72)

if not EVIDENCE_DB.is_file():
    raise RuntimeError(
        f"Missing evidence DB: {EVIDENCE_DB}"
    )

if not CORRELATION_DB.is_file():
    raise RuntimeError(
        f"Missing correlation DB: {CORRELATION_DB}"
    )


evidence = open_evidence()
correlation = open_correlation()

try:

    evidence_count = evidence.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    evidence_integrity = evidence.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    correlation_integrity = correlation.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    print()
    print("DATABASE BASELINE")
    print(
        f"Evidence events:      {evidence_count:,}"
    )
    print(
        f"Evidence integrity:   {evidence_integrity}"
    )
    print(
        f"Correlation integrity:{correlation_integrity}"
    )


    if CASE == "CASE-001" and evidence_count != 975501:
        raise RuntimeError(
            f"Expected 975501 evidence events, "
            f"got {evidence_count}"
        )

    if evidence_count <= 0:
        raise RuntimeError(
            "Evidence database contains no events."
        )

    if evidence_integrity != "ok":
        raise RuntimeError(
            "Evidence DB integrity failed."
        )

    if correlation_integrity != "ok":
        raise RuntimeError(
            "Correlation DB integrity failed."
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
        (CORRELATION_VERSION,),
    ).fetchone()


    if run is None:
        raise RuntimeError(
            "Completed Correlation Engine v1 "
            "run not found."
        )


    run_id = run["run_id"]

    print()
    print("CORRELATION RUN")
    print(f"Run ID: {run_id}")
    print(f"Edges:  {run['edge_count']:,}")


    medium_edges = correlation.execute(
        """
        SELECT
            edge_uid,
            event_uid_a,
            event_uid_b,
            source_tool_a,
            source_tool_b,
            relationship_type,
            score,
            confidence,
            time_delta_seconds,
            shared_keys_json
        FROM edges
        WHERE run_id = ?
          AND confidence = 'MEDIUM'
        """,
        (run_id,),
    ).fetchall()


    accepted = []

    for edge in medium_edges:

        family_a = FAMILY_MAP.get(
            edge["source_tool_a"],
            edge["source_tool_a"].upper(),
        )

        family_b = FAMILY_MAP.get(
            edge["source_tool_b"],
            edge["source_tool_b"].upper(),
        )

        if family_a == family_b:
            continue

        if edge["relationship_type"] not in {
            "SHARED_EXECUTABLE_NEAR_TIME",
            "SHARED_PATH_NEAR_TIME",
        }:
            continue

        accepted.append(edge)


    print()
    print("CANDIDATE INPUT")
    print(
        f"Medium edges:                "
        f"{len(medium_edges):,}"
    )
    print(
        f"Independent cross-artifact:  "
        f"{len(accepted):,}"
    )


    if CASE == "CASE-001":
        if len(accepted) != 42:
            raise RuntimeError(
                "Expected 42 cross-artifact MEDIUM "
                f"edges, got {len(accepted)}"
            )


    uf = UnionFind()

    for edge in accepted:
        uf.union(
            edge["event_uid_a"],
            edge["event_uid_b"],
        )


    components = defaultdict(set)

    for event_uid in uf.parent:
        root = uf.find(event_uid)
        components[root].add(event_uid)


    edges_by_component = defaultdict(list)

    for edge in accepted:
        root = uf.find(
            edge["event_uid_a"]
        )
        edges_by_component[root].append(edge)


    print(
        f"Connected components:        "
        f"{len(components):,}"
    )


    correlation.executescript(
        """
        CREATE TABLE IF NOT EXISTS
        candidate_clusters (
            candidate_id TEXT PRIMARY KEY,
            correlation_run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            candidate_version TEXT NOT NULL,
            confidence TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            edge_count INTEGER NOT NULL,
            independent_family_count INTEGER NOT NULL,
            start_timestamp TEXT,
            end_timestamp TEXT,
            source_tools_json TEXT NOT NULL,
            evidence_families_json TEXT NOT NULL,
            relationship_types_json TEXT NOT NULL,
            shared_keys_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS
        candidate_cluster_events (
            candidate_id TEXT NOT NULL,
            event_uid TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            evidence_family TEXT NOT NULL,
            PRIMARY KEY (
                candidate_id,
                event_uid
            )
        );

        CREATE TABLE IF NOT EXISTS
        candidate_cluster_edges (
            candidate_id TEXT NOT NULL,
            edge_uid TEXT NOT NULL,
            PRIMARY KEY (
                candidate_id,
                edge_uid
            )
        );

        CREATE INDEX IF NOT EXISTS
        idx_candidate_cluster_events_uid
        ON candidate_cluster_events(event_uid);

        CREATE INDEX IF NOT EXISTS
        idx_candidate_cluster_family
        ON candidate_cluster_events(
            evidence_family
        );
        """
    )

    correlation.commit()


    existing = correlation.execute(
        """
        SELECT COUNT(*)
        FROM candidate_clusters
        WHERE correlation_run_id = ?
          AND candidate_version = ?
        """,
        (
            run_id,
            CANDIDATE_VERSION,
        ),
    ).fetchone()[0]


    if existing:
        print()
        print(
            f"Candidate clusters already exist: "
            f"{existing:,}"
        )
        print("No rebuild performed.")

    else:

        created = 0
        stored_events = 0
        stored_edges = 0

        correlation.execute("BEGIN")

        try:

            for root, members in components.items():

                component_edges = (
                    edges_by_component[root]
                )

                placeholders = ",".join(
                    "?"
                    for _ in members
                )

                rows = evidence.execute(
                    f"""
                    SELECT
                        event_uid,
                        source_tool,
                        timestamp_sort,
                        timestamp,
                        artifact_type,
                        event_type,
                        executable,
                        path,
                        target_path,
                        description
                    FROM events
                    WHERE event_uid
                    IN ({placeholders})
                    """,
                    tuple(members),
                ).fetchall()


                if len(rows) != len(members):
                    raise RuntimeError(
                        "Candidate references missing "
                        "from evidence.db."
                    )


                tools = {
                    row["source_tool"]
                    for row in rows
                }


                families = {
                    FAMILY_MAP.get(
                        row["source_tool"],
                        row["source_tool"].upper(),
                    )
                    for row in rows
                }


                if len(families) < 2:
                    continue


                timestamps = [
                    row["timestamp_sort"]
                    for row in rows
                    if row["timestamp_sort"]
                ]


                relationship_types = {
                    edge["relationship_type"]
                    for edge in component_edges
                }


                shared_keys = []

                for edge in component_edges:
                    try:
                        value = json.loads(
                            edge["shared_keys_json"]
                        )
                    except Exception:
                        value = {}

                    if value:
                        shared_keys.append(value)


                identity = (
                    run_id
                    + "|"
                    + CANDIDATE_VERSION
                    + "|"
                    + "|".join(
                        sorted(members)
                    )
                )

                candidate_id = hashlib.sha256(
                    identity.encode("utf-8")
                ).hexdigest()


                correlation.execute(
                    """
                    INSERT INTO candidate_clusters (
                        candidate_id,
                        correlation_run_id,
                        case_id,
                        candidate_version,
                        confidence,
                        event_count,
                        edge_count,
                        independent_family_count,
                        start_timestamp,
                        end_timestamp,
                        source_tools_json,
                        evidence_families_json,
                        relationship_types_json,
                        shared_keys_json
                    )
                    VALUES (
                        ?, ?, ?, ?,
                        'MEDIUM',
                        ?, ?, ?,
                        ?, ?,
                        ?, ?, ?, ?
                    )
                    """,
                    (
                        candidate_id,
                        run_id,
                        CASE,
                        CANDIDATE_VERSION,
                        len(rows),
                        len(component_edges),
                        len(families),
                        min(timestamps)
                            if timestamps
                            else None,
                        max(timestamps)
                            if timestamps
                            else None,
                        json.dumps(
                            sorted(tools)
                        ),
                        json.dumps(
                            sorted(families)
                        ),
                        json.dumps(
                            sorted(
                                relationship_types
                            )
                        ),
                        json.dumps(
                            shared_keys,
                            ensure_ascii=False,
                        ),
                    ),
                )


                for row in rows:

                    family = FAMILY_MAP.get(
                        row["source_tool"],
                        row["source_tool"].upper(),
                    )

                    correlation.execute(
                        """
                        INSERT INTO
                        candidate_cluster_events (
                            candidate_id,
                            event_uid,
                            source_tool,
                            evidence_family
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            candidate_id,
                            row["event_uid"],
                            row["source_tool"],
                            family,
                        ),
                    )

                    stored_events += 1


                for edge in component_edges:

                    correlation.execute(
                        """
                        INSERT INTO
                        candidate_cluster_edges (
                            candidate_id,
                            edge_uid
                        )
                        VALUES (?, ?)
                        """,
                        (
                            candidate_id,
                            edge["edge_uid"],
                        ),
                    )

                    stored_edges += 1


                created += 1


            correlation.commit()

        except Exception:
            correlation.rollback()
            raise


        print()
        print("CANDIDATE STORAGE")
        print(
            f"Candidate clusters: {created:,}"
        )
        print(
            f"Candidate events:   {stored_events:,}"
        )
        print(
            f"Candidate edges:    {stored_edges:,}"
        )


    total_candidates = correlation.execute(
        """
        SELECT COUNT(*)
        FROM candidate_clusters
        WHERE correlation_run_id = ?
          AND candidate_version = ?
        """,
        (
            run_id,
            CANDIDATE_VERSION,
        ),
    ).fetchone()[0]


    print()
    print("=" * 72)
    print("CANDIDATE CLUSTER RESULTS")
    print("=" * 72)

    print(
        f"Candidate clusters: {total_candidates:,}"
    )


    family_distribution = correlation.execute(
        """
        SELECT
            independent_family_count,
            COUNT(*) AS count
        FROM candidate_clusters
        WHERE correlation_run_id = ?
          AND candidate_version = ?
        GROUP BY independent_family_count
        ORDER BY independent_family_count
        """,
        (
            run_id,
            CANDIDATE_VERSION,
        ),
    ).fetchall()


    print()
    print("INDEPENDENT FAMILY DISTRIBUTION")

    for row in family_distribution:
        print(
            f"{row['independent_family_count']} "
            f"families: {row['count']:,}"
        )


    print()
    print("TOP CANDIDATES")


    candidates = correlation.execute(
        """
        SELECT
            candidate_id,
            confidence,
            event_count,
            edge_count,
            independent_family_count,
            start_timestamp,
            end_timestamp,
            source_tools_json,
            evidence_families_json,
            relationship_types_json,
            shared_keys_json
        FROM candidate_clusters
        WHERE correlation_run_id = ?
          AND candidate_version = ?
        ORDER BY
            edge_count DESC,
            event_count DESC,
            start_timestamp
        LIMIT 15
        """,
        (
            run_id,
            CANDIDATE_VERSION,
        ),
    ).fetchall()


    for row in candidates:

        print()
        print(
            f"Candidate: {row['candidate_id']}"
        )

        print(
            f"  confidence: {row['confidence']}"
        )

        print(
            f"  events: {row['event_count']}"
        )

        print(
            f"  edges: {row['edge_count']}"
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
            "  shared keys: "
            f"{row['shared_keys_json']}"
        )

        print(
            f"  time: {row['start_timestamp']} "
            f"-> {row['end_timestamp']}"
        )


    final_integrity = correlation.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    print()
    print(
        "Correlation DB integrity: "
        f"{final_integrity}"
    )


    if final_integrity != "ok":
        raise RuntimeError(
            "Correlation DB integrity failure."
        )


finally:
    correlation.close()
    evidence.close()


print()
print("=" * 72)
print("CROSS-ARTIFACT CANDIDATES V1: COMPLETE")
print("=" * 72)

print()
print("Core clusters:       stored")
print("Cross-artifact candidates: stored")
print("Automatic findings:  NOT CREATED")
print("evidence.db:         UNCHANGED")
print()
print("NEXT PHASE: FINDINGS / INVESTIGATION ENGINE V1")

