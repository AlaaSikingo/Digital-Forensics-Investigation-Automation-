import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.0"

WORKSPACE_ROOT = Path(
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace")
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def load_existing_8b_results(
    qwen_dir,
):

    completed = set()

    if not qwen_dir.is_dir():
        return completed

    for path in qwen_dir.glob(
        "*.json"
    ):

        if path.name.lower() == "index.json":
            continue

        try:

            with path.open(
                "r",
                encoding="utf-8",
            ) as handle:

                payload = json.load(
                    handle
                )

            analysis = payload.get(
                "analysis",
                {}
            )

            finding_id = analysis.get(
                "finding_id",
                ""
            ).strip()

            if finding_id:
                completed.add(
                    finding_id
                )

        except Exception:
            # Ignore incomplete/corrupt
            # result files.
            continue

    return completed


def route_finding(row):

    severity = (
        row["severity"]
        or "UNKNOWN"
    ).upper()

    families = int(
        row[
            "independent_family_count"
        ]
        or 0
    )

    evidence_count = int(
        row[
            "evidence_count"
        ]
        or 0
    )

    reasons = []

    # Investigation-effort score only.
    # This is never a maliciousness score.
    #
    # Routing uses generic properties only:
    #   - normalized severity
    #   - independent evidence-family count
    #   - evidence-set size
    #
    # No finding type, executable, Event ID,
    # product, case, user or detection name
    # participates in routing.

    severity_points = {
        "CRITICAL": 120,
        "HIGH": 90,
        "MEDIUM": 50,
        "UNASSESSED": 20,
        "LOW": 10,
        "INFO": 0,
        "UNKNOWN": 0,
    }

    score = severity_points.get(
        severity,
        0,
    )

    if severity in {
        "CRITICAL",
        "HIGH",
    }:
        reasons.append(
            "Higher-severity evidence requires deeper review"
        )

    if families >= 2:
        score += 25
        reasons.append(
            "Multiple independent evidence families"
        )

    if evidence_count >= 10:
        score += 5
        reasons.append(
            "Larger supporting evidence set"
        )

    if severity in {
        "CRITICAL",
        "HIGH",
    }:
        route = "DEEP_8B"

    elif (
        families >= 2
        or severity == "MEDIUM"
    ):
        route = "FAST_4B"

    else:
        route = "STORE_ONLY"

    if not reasons:
        reasons.append(
            "No higher-effort generic routing criteria met"
        )

    return {
        "planned_route":
            route,

        "routing_score":
            score,

        "reasons":
            reasons,
    }


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

FINDINGS_DB = (
    CASE_DIR
    / "findings.db"
)

TRIAGE_DB = (
    CASE_DIR
    / "triage.db"
)

QWEN_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen_v1"
)


print("=" * 72)
print("FAST TRIAGE ENGINE V1")
print("=" * 72)

print()
print(f"Case:       {CASE}")
print(f"Findings:   {FINDINGS_DB}")
print(f"Triage DB:  {TRIAGE_DB}")


if not FINDINGS_DB.is_file():

    raise RuntimeError(
        f"findings.db missing: "
        f"{FINDINGS_DB}"
    )


findings = open_readonly(
    FINDINGS_DB
)


try:

    integrity = findings.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    if integrity != "ok":

        raise RuntimeError(
            "findings.db integrity "
            "failure"
        )


    run = findings.execute(
        """
        SELECT
            run_id,
            finding_count
        FROM runs
        WHERE status = 'COMPLETED'
        ORDER BY completed_utc DESC
        LIMIT 1
        """
    ).fetchone()


    if run is None:

        raise RuntimeError(
            "Completed findings run "
            "not found"
        )


    findings_run_id = (
        run["run_id"]
    )


    rows = findings.execute(
        """
        SELECT
            finding_id,
            finding_type,
            state,
            confidence,
            severity,
            title,
            independent_family_count,
            evidence_count,
            start_timestamp,
            end_timestamp
        FROM findings
        WHERE run_id = ?
        """,
        (
            findings_run_id,
        ),
    ).fetchall()


    expected_count = int(
        run["finding_count"]
        or 0
    )


    if len(rows) != expected_count:

        raise RuntimeError(
            "Finding count mismatch: "
            f"run={expected_count}, "
            f"rows={len(rows)}"
        )


finally:

    findings.close()


existing_8b = (
    load_existing_8b_results(
        QWEN_DIR
    )
)


print()
print("INPUT")

print(
    f"Findings discovered: "
    f"{len(rows):,}"
)

print(
    f"Existing valid 8B analyses: "
    f"{len(existing_8b):,}"
)


triage = sqlite3.connect(
    str(TRIAGE_DB)
)

triage.row_factory = (
    sqlite3.Row
)


try:

    triage.executescript(
        """
        CREATE TABLE IF NOT EXISTS
        triage_runs (

            run_id TEXT PRIMARY KEY,

            case_id TEXT NOT NULL,

            findings_run_id TEXT NOT NULL,

            engine_version TEXT NOT NULL,

            created_utc TEXT NOT NULL,

            finding_count INTEGER
                NOT NULL
        );


        CREATE TABLE IF NOT EXISTS
        triage_routes (

            run_id TEXT NOT NULL,

            finding_id TEXT NOT NULL,

            finding_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            confidence TEXT NOT NULL,

            title TEXT NOT NULL,

            independent_family_count
                INTEGER NOT NULL,

            evidence_count INTEGER
                NOT NULL,

            routing_score INTEGER
                NOT NULL,

            planned_route TEXT
                NOT NULL,

            status TEXT NOT NULL,

            reasons_json TEXT NOT NULL,

            start_timestamp TEXT,

            end_timestamp TEXT,

            PRIMARY KEY (
                run_id,
                finding_id
            )
        );


        CREATE INDEX IF NOT EXISTS
        idx_triage_route
        ON triage_routes(
            planned_route
        );


        CREATE INDEX IF NOT EXISTS
        idx_triage_status
        ON triage_routes(
            status
        );


        CREATE INDEX IF NOT EXISTS
        idx_triage_score
        ON triage_routes(
            routing_score
        );
        """
    )


    run_identity = (
        CASE
        + "|"
        + findings_run_id
        + "|"
        + VERSION
    )


    triage_run_id = (
        hashlib.sha256(
            run_identity.encode(
                "utf-8"
            )
        ).hexdigest()
    )


    # Rebuild routing safely so that
    # newly completed 8B results are
    # detected on every run.

    triage.execute(
        """
        DELETE FROM triage_routes
        WHERE run_id = ?
        """,
        (
            triage_run_id,
        ),
    )


    triage.execute(
        """
        INSERT OR REPLACE INTO
        triage_runs (
            run_id,
            case_id,
            findings_run_id,
            engine_version,
            created_utc,
            finding_count
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            triage_run_id,
            CASE,
            findings_run_id,
            VERSION,
            utc_now(),
            len(rows),
        ),
    )


    for row in rows:

        route = route_finding(
            row
        )

        finding_id = (
            row["finding_id"]
        )


        if finding_id in existing_8b:

            status = (
                "ANALYZED_8B"
            )

        else:

            status = "PENDING"


        triage.execute(
            """
            INSERT INTO
            triage_routes (
                run_id,
                finding_id,
                finding_type,
                severity,
                confidence,
                title,
                independent_family_count,
                evidence_count,
                routing_score,
                planned_route,
                status,
                reasons_json,
                start_timestamp,
                end_timestamp
            )
            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                triage_run_id,

                finding_id,

                row["finding_type"],

                row["severity"],

                row["confidence"],

                row["title"],

                row[
                    "independent_family_count"
                ],

                row[
                    "evidence_count"
                ],

                route[
                    "routing_score"
                ],

                route[
                    "planned_route"
                ],

                status,

                json.dumps(
                    route["reasons"],
                    ensure_ascii=False,
                ),

                row[
                    "start_timestamp"
                ],

                row[
                    "end_timestamp"
                ],
            ),
        )


    triage.commit()


    integrity = triage.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    if integrity != "ok":

        raise RuntimeError(
            "triage.db integrity "
            "failure"
        )


    print()
    print("=" * 72)
    print("FAST TRIAGE RESULTS")
    print("=" * 72)


    print()
    print("PLANNED ROUTES")


    for row in triage.execute(
        """
        SELECT
            planned_route,
            COUNT(*) AS count
        FROM triage_routes
        WHERE run_id = ?
        GROUP BY planned_route
        ORDER BY
            CASE planned_route
                WHEN 'DEEP_8B' THEN 1
                WHEN 'FAST_4B' THEN 2
                WHEN 'STORE_ONLY' THEN 3
                ELSE 4
            END
        """,
        (
            triage_run_id,
        ),
    ):

        print(
            f"{row['planned_route']:<15} "
            f"{row['count']:,}"
        )


    print()
    print("EXECUTION STATUS")


    for row in triage.execute(
        """
        SELECT
            status,
            COUNT(*) AS count
        FROM triage_routes
        WHERE run_id = ?
        GROUP BY status
        ORDER BY status
        """,
        (
            triage_run_id,
        ),
    ):

        print(
            f"{row['status']:<15} "
            f"{row['count']:,}"
        )


    pending_8b = triage.execute(
        """
        SELECT COUNT(*)
        FROM triage_routes
        WHERE run_id = ?
          AND planned_route =
              'DEEP_8B'
          AND status =
              'PENDING'
        """,
        (
            triage_run_id,
        ),
    ).fetchone()[0]


    pending_4b = triage.execute(
        """
        SELECT COUNT(*)
        FROM triage_routes
        WHERE run_id = ?
          AND planned_route =
              'FAST_4B'
          AND status =
              'PENDING'
        """,
        (
            triage_run_id,
        ),
    ).fetchone()[0]


    store_only = triage.execute(
        """
        SELECT COUNT(*)
        FROM triage_routes
        WHERE run_id = ?
          AND planned_route =
              'STORE_ONLY'
          AND status =
              'PENDING'
        """,
        (
            triage_run_id,
        ),
    ).fetchone()[0]


    already_8b = triage.execute(
        """
        SELECT COUNT(*)
        FROM triage_routes
        WHERE run_id = ?
          AND status =
              'ANALYZED_8B'
        """,
        (
            triage_run_id,
        ),
    ).fetchone()[0]


    print()
    print("WORK REMAINING")

    print(
        f"Already analyzed by 8B: "
        f"{already_8b:,}"
    )

    print(
        f"Pending deep 8B:        "
        f"{pending_8b:,}"
    )

    print(
        f"Pending fast 4B:        "
        f"{pending_4b:,}"
    )

    print(
        f"Store only:             "
        f"{store_only:,}"
    )


    print()
    print("TOP PENDING FINDINGS")


    pending = triage.execute(
        """
        SELECT
            severity,
            planned_route,
            routing_score,
            independent_family_count,
            evidence_count,
            title,
            finding_id
        FROM triage_routes
        WHERE run_id = ?
          AND status = 'PENDING'
        ORDER BY
            CASE planned_route
                WHEN 'DEEP_8B' THEN 1
                WHEN 'FAST_4B' THEN 2
                WHEN 'STORE_ONLY' THEN 3
                ELSE 4
            END,
            routing_score DESC,
            evidence_count DESC
        LIMIT 20
        """,
        (
            triage_run_id,
        ),
    ).fetchall()


    for row in pending:

        print()

        print(
            f"{row['planned_route']} | "
            f"{row['severity']} | "
            f"score={row['routing_score']}"
        )

        print(
            f"  {row['title']}"
        )

        print(
            "  families: "
            f"{row['independent_family_count']}"
        )

        print(
            "  evidence: "
            f"{row['evidence_count']}"
        )

        print(
            "  finding_id: "
            f"{row['finding_id']}"
        )


    print()
    print(
        f"Triage DB integrity: "
        f"{integrity}"
    )


finally:

    triage.close()


print()
print("=" * 72)
print("FAST TRIAGE ENGINE V1: COMPLETE")
print("=" * 72)

print()
print("LLM calls performed: 0")
print("Threat determination: NONE")
print()
print(
    "Routing score is investigation "
    "priority only."
)
print(
    "It is NOT a maliciousness score."
)
print()
print("NEXT:")
print("FAST_4B -> Qwen3 4B triage")
print("DEEP_8B -> Qwen3 8B deep investigation")
