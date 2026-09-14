import argparse
import json
import sqlite3
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

FINDINGS_DB = (
    CASE_DIR
    / "findings.db"
)

OUTPUT_DIR = (
    CASE_DIR
    / "investigation"
    / "contexts_v1"
)


CONTEXT_VERSION = "1.0"


SEVERITY_ORDER = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "UNASSESSED": 4,
    "LOW": 5,
    "INFO": 6,
    "UNKNOWN": 7,
}


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


def parse_json(value, default):

    if not value:
        return default

    try:
        return json.loads(value)

    except Exception:
        return default


def fetch_events(
    evidence,
    event_uids,
):

    if not event_uids:
        return {}

    placeholders = ",".join(
        "?"
        for _ in event_uids
    )

    rows = evidence.execute(
        f"""
        SELECT
            event_uid,
            schema_version,
            case_id,

            timestamp,
            timestamp_sort,
            timestamp_type,
            timestamp_source,

            artifact_type,
            event_type,
            source_tool,

            hostname,
            username,

            executable,
            process_id,
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
        tuple(event_uids),
    ).fetchall()

    return {
        row["event_uid"]: dict(row)
        for row in rows
    }


def fetch_attributes(
    evidence,
    event_uids,
):

    if not event_uids:
        return {}

    placeholders = ",".join(
        "?"
        for _ in event_uids
    )

    result = {
        uid: {}
        for uid in event_uids
    }

    rows = evidence.execute(
        f"""
        SELECT
            event_uid,
            attribute_key,
            attribute_value
        FROM attributes
        WHERE event_uid
          IN ({placeholders})
        ORDER BY
            event_uid,
            attribute_key
        """,
        tuple(event_uids),
    )

    for row in rows:

        result.setdefault(
            row["event_uid"],
            {},
        )

        result[
            row["event_uid"]
        ][
            row["attribute_key"]
        ] = row["attribute_value"]

    return result


def fetch_provenance(
    evidence,
    event_uids,
):

    if not event_uids:
        return {}

    placeholders = ",".join(
        "?"
        for _ in event_uids
    )

    rows = evidence.execute(
        f"""
        SELECT
            event_uid,
            parser,
            parser_output,
            source_evidence,
            source_row
        FROM provenance
        WHERE event_uid
          IN ({placeholders})
        """,
        tuple(event_uids),
    )

    return {
        row["event_uid"]: {
            "parser":
                row["parser"],

            "parser_output":
                row["parser_output"],

            "source_evidence":
                row["source_evidence"],

            "source_row":
                row["source_row"],
        }
        for row in rows
    }


def fetch_edges(
    correlation,
    event_uids,
):

    if not event_uids:
        return []

    placeholders = ",".join(
        "?"
        for _ in event_uids
    )

    query = f"""
        SELECT
            edge_uid,

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
            reason
        FROM edges
        WHERE event_uid_a
              IN ({placeholders})
           OR event_uid_b
              IN ({placeholders})
        ORDER BY
            score DESC,
            time_delta_seconds ASC
    """

    params = (
        tuple(event_uids)
        + tuple(event_uids)
    )

    rows = correlation.execute(
        query,
        params,
    ).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        item["shared_keys"] = (
            parse_json(
                item.pop(
                    "shared_keys_json"
                ),
                {},
            )
        )

        results.append(item)

    return results


def fetch_source_context(
    correlation,
    finding,
):

    source_kind = finding[
        "source_kind"
    ]

    source_id = finding[
        "source_id"
    ]

    if (
        source_kind
        == "CANDIDATE_CLUSTER"
    ):

        row = correlation.execute(
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
            WHERE candidate_id = ?
            """,
            (source_id,),
        ).fetchone()

        if row is None:
            return None

        result = dict(row)

        for key in (
            "source_tools_json",
            "evidence_families_json",
            "relationship_types_json",
            "shared_keys_json",
        ):

            clean_key = key.replace(
                "_json",
                "",
            )

            result[clean_key] = (
                parse_json(
                    result.pop(key),
                    [],
                )
            )

        result[
            "source_kind"
        ] = "CANDIDATE_CLUSTER"

        return result


    if (
        source_kind
        == "CORE_CLUSTER"
    ):

        row = correlation.execute(
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
                relationship_types_json,
                has_detection_enrichment
            FROM clusters
            WHERE cluster_id = ?
            """,
            (source_id,),
        ).fetchone()

        if row is None:
            return None

        result = dict(row)

        for key in (
            "source_tools_json",
            "evidence_families_json",
            "relationship_types_json",
        ):

            clean_key = key.replace(
                "_json",
                "",
            )

            result[clean_key] = (
                parse_json(
                    result.pop(key),
                    [],
                )
            )

        result[
            "source_kind"
        ] = "CORE_CLUSTER"

        return result


    return None


def build_rag_hints(
    finding,
    events,
):

    hints = []

    def add(value):

        value = (
            str(value or "")
            .strip()
        )

        if not value:
            return

        if value not in hints:
            hints.append(value)


    add(finding["title"])
    add(finding["finding_type"])

    for value in parse_json(
        finding[
            "detection_rules_json"
        ],
        [],
    ):
        add(value)

    for value in parse_json(
        finding[
            "executables_json"
        ],
        [],
    ):
        add(value)


    for event in events.values():

        add(
            event[
                "detection_rule"
            ]
        )

        add(
            event[
                "executable"
            ]
        )

        if event[
            "windows_event_id"
        ]:

            add(
                "Windows Event ID "
                + str(
                    event[
                        "windows_event_id"
                    ]
                )
            )

        add(
            event[
                "provider"
            ]
        )

        add(
            event[
                "channel"
            ]
        )

        add(
            event[
                "registry_key"
            ]
        )


    return hints[:30]


def atomic_write_json(
    path,
    payload,
):

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temp.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            payload,
            handle,
            ensure_ascii=False,
            indent=2,
        )

        handle.write("\n")

    temp.replace(path)


print("=" * 72)
print("QWEN INVESTIGATION CONTEXT / EVIDENCE RETRIEVAL V1")
print("=" * 72)


for path in (
    EVIDENCE_DB,
    CORRELATION_DB,
    FINDINGS_DB,
):

    if not path.is_file():
        raise RuntimeError(
            f"Required database missing: {path}"
        )


evidence = open_readonly(
    EVIDENCE_DB
)

correlation = open_readonly(
    CORRELATION_DB
)

findings = open_readonly(
    FINDINGS_DB
)


try:

    evidence_integrity = evidence.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    correlation_integrity = (
        correlation.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
    )

    findings_integrity = findings.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    print()
    print("DATABASE INTEGRITY")
    print(
        f"evidence.db:    "
        f"{evidence_integrity}"
    )
    print(
        f"correlation.db: "
        f"{correlation_integrity}"
    )
    print(
        f"findings.db:    "
        f"{findings_integrity}"
    )


    if any(
        value != "ok"
        for value in (
            evidence_integrity,
            correlation_integrity,
            findings_integrity,
        )
    ):
        raise RuntimeError(
            "Database integrity failure."
        )


    finding_run = findings.execute(
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


    if finding_run is None:
        raise RuntimeError(
            "Completed findings run missing."
        )


    finding_run_id = (
        finding_run["run_id"]
    )


    finding_rows = findings.execute(
        """
        SELECT *
        FROM findings
        WHERE run_id = ?
        """,
        (finding_run_id,),
    ).fetchall()


    finding_rows = sorted(
        finding_rows,
        key=lambda row: (
            SEVERITY_ORDER.get(
                row["severity"],
                99,
            ),
            -row[
                "independent_family_count"
            ],
            -row[
                "evidence_count"
            ],
            row[
                "start_timestamp"
            ] or "",
        ),
    )


    print()
    print("FINDINGS INPUT")
    print(
        f"Run ID:   {finding_run_id}"
    )
    print(
        f"Findings: {len(finding_rows):,}"
    )


    if (
        len(finding_rows)
        != finding_run[
            "finding_count"
        ]
    ):
        raise RuntimeError(
            "Findings count mismatch."
        )


    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    index = {
        "context_version":
            CONTEXT_VERSION,

        "case_id":
            CASE,

        "findings_run_id":
            finding_run_id,

        "package_count":
            0,

        "packages":
            [],
    }


    package_count = 0
    evidence_links_total = 0
    correlation_links_total = 0


    for priority, finding_row in enumerate(
        finding_rows,
        start=1,
    ):

        finding = dict(
            finding_row
        )

        finding_id = finding[
            "finding_id"
        ]


        member_rows = findings.execute(
            """
            SELECT
                event_uid,
                source_tool,
                evidence_family,
                evidence_role
            FROM finding_evidence
            WHERE finding_id = ?
            ORDER BY
                evidence_family,
                source_tool,
                event_uid
            """,
            (finding_id,),
        ).fetchall()


        members = [
            dict(row)
            for row in member_rows
        ]


        event_uids = [
            row["event_uid"]
            for row in members
        ]


        event_rows = fetch_events(
            evidence,
            event_uids,
        )


        if (
            len(event_rows)
            != len(event_uids)
        ):
            raise RuntimeError(
                f"{finding_id}: missing "
                "evidence event."
            )


        attributes = fetch_attributes(
            evidence,
            event_uids,
        )


        provenance = fetch_provenance(
            evidence,
            event_uids,
        )


        if (
            len(provenance)
            != len(event_uids)
        ):
            raise RuntimeError(
                f"{finding_id}: missing "
                "provenance."
            )


        evidence_items = []


        for member in members:

            uid = member[
                "event_uid"
            ]

            event = dict(
                event_rows[uid]
            )


            evidence_items.append({
                "event_uid":
                    uid,

                "evidence_family":
                    member[
                        "evidence_family"
                    ],

                "evidence_role":
                    member[
                        "evidence_role"
                    ],

                "normalized_event":
                    event,

                "attributes":
                    attributes.get(
                        uid,
                        {},
                    ),

                "provenance":
                    provenance[
                        uid
                    ],
            })


        edges = fetch_edges(
            correlation,
            event_uids,
        )


        source_context = (
            fetch_source_context(
                correlation,
                finding,
            )
        )


        independent_families = (
            sorted({
                member[
                    "evidence_family"
                ]
                for member in members
            })
        )


        package = {
            "context_version":
                CONTEXT_VERSION,

            "case_id":
                CASE,

            "priority":
                priority,

            "finding": {
                "finding_id":
                    finding_id,

                "finding_type":
                    finding[
                        "finding_type"
                    ],

                "state":
                    finding[
                        "state"
                    ],

                "severity":
                    finding[
                        "severity"
                    ],

                "confidence":
                    finding[
                        "confidence"
                    ],

                "title":
                    finding[
                        "title"
                    ],

                "summary":
                    finding[
                        "summary"
                    ],

                "start_timestamp":
                    finding[
                        "start_timestamp"
                    ],

                "end_timestamp":
                    finding[
                        "end_timestamp"
                    ],

                "independent_family_count":
                    finding[
                        "independent_family_count"
                    ],

                "evidence_count":
                    finding[
                        "evidence_count"
                    ],

                "source_kind":
                    finding[
                        "source_kind"
                    ],

                "source_id":
                    finding[
                        "source_id"
                    ],

                "detection_rules":
                    parse_json(
                        finding[
                            "detection_rules_json"
                        ],
                        [],
                    ),

                "executables":
                    parse_json(
                        finding[
                            "executables_json"
                        ],
                        [],
                    ),

                "paths":
                    parse_json(
                        finding[
                            "paths_json"
                        ],
                        [],
                    ),
            },

            "evidence_independence": {
                "independent_families":
                    independent_families,

                "independent_family_count":
                    len(
                        independent_families
                    ),

                "important_rule":
                    (
                        "Hayabusa and EvtxECmd "
                        "both belong to the EVTX "
                        "evidence family and must "
                        "not be counted as two "
                        "independent sources."
                    ),
            },

            "source_context":
                source_context,

            "evidence":
                evidence_items,

            "correlation_edges":
                edges,

            "rag_search_hints":
                build_rag_hints(
                    finding,
                    event_rows,
                ),

            "analysis_guardrails": [
                (
                    "Separate observed facts "
                    "from analytical inference."
                ),
                (
                    "Do not determine "
                    "maliciousness solely from "
                    "a detection-rule title or "
                    "severity."
                ),
                (
                    "Do not count Hayabusa and "
                    "EvtxECmd as independent "
                    "corroboration when they "
                    "represent the same EVTX "
                    "evidence."
                ),
                (
                    "Every factual case claim "
                    "must reference supporting "
                    "event_uid values."
                ),
                (
                    "Preserve uncertainty when "
                    "the evidence does not "
                    "support a conclusion."
                ),
                (
                    "Recommend additional "
                    "evidence collection when "
                    "needed rather than "
                    "inventing missing facts."
                ),
            ],
        }


        output_file = OUTPUT_DIR / (
            f"{priority:03d}_"
            f"{finding_id}.json"
        )


        atomic_write_json(
            output_file,
            package,
        )


        index[
            "packages"
        ].append({
            "priority":
                priority,

            "finding_id":
                finding_id,

            "finding_type":
                finding[
                    "finding_type"
                ],

            "severity":
                finding[
                    "severity"
                ],

            "confidence":
                finding[
                    "confidence"
                ],

            "title":
                finding[
                    "title"
                ],

            "independent_family_count":
                finding[
                    "independent_family_count"
                ],

            "evidence_count":
                len(
                    evidence_items
                ),

            "correlation_edge_count":
                len(edges),

            "file":
                output_file.name,
        })


        package_count += 1

        evidence_links_total += (
            len(evidence_items)
        )

        correlation_links_total += (
            len(edges)
        )


    index[
        "package_count"
    ] = package_count


    index_path = (
        OUTPUT_DIR
        / "index.json"
    )


    atomic_write_json(
        index_path,
        index,
    )


    print()
    print("=" * 72)
    print("INVESTIGATION CONTEXT RESULTS")
    print("=" * 72)

    print(
        f"Context packages:    "
        f"{package_count:,}"
    )

    print(
        f"Evidence references: "
        f"{evidence_links_total:,}"
    )

    print(
        f"Correlation links:   "
        f"{correlation_links_total:,}"
    )

    print(
        f"Output directory:    "
        f"{OUTPUT_DIR}"
    )


    print()
    print("TOP CONTEXT PACKAGES")


    for item in (
        index["packages"][:10]
    ):

        print()

        print(
            f"Priority {item['priority']}: "
            f"{item['severity']}"
        )

        print(
            f"  {item['title']}"
        )

        print(
            "  families: "
            f"{item['independent_family_count']}"
        )

        print(
            "  evidence: "
            f"{item['evidence_count']}"
        )

        print(
            "  correlations: "
            f"{item['correlation_edge_count']}"
        )

        print(
            "  file: "
            f"{item['file']}"
        )


    if CASE == "CASE-001" and package_count != 27:
        raise RuntimeError(
            f"Expected 27 context packages, "
            f"got {package_count}"
        )


    if CASE == "CASE-001" and evidence_links_total != 78:
        raise RuntimeError(
            "Expected 78 finding evidence "
            f"references, got "
            f"{evidence_links_total}"
        )


finally:

    findings.close()
    correlation.close()
    evidence.close()


print()
print("=" * 72)
print("QWEN INVESTIGATION CONTEXT V1: COMPLETE")
print("=" * 72)

print()
print("evidence.db:     READ-ONLY / UNCHANGED")
print("correlation.db:  READ-ONLY / UNCHANGED")
print("findings.db:     READ-ONLY / UNCHANGED")
print()
print(f"{package_count} bounded investigation packages created.")
print()
print("NEXT: QWEN INVESTIGATOR V1")
