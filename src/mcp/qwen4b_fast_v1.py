import argparse
import json
import sqlite3
import time
import urllib.request
from pathlib import Path


MODEL = "qwen3:4b-instruct"
OLLAMA_URL = "http://localhost:11434"

WORKSPACE_ROOT = Path(
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace")
)

REQUEST_TIMEOUT = 600
MAX_RETRIES = 2


OUTPUT_SCHEMA = {
    "type": "object",

    "properties": {

        "assessment": {
            "type": "string",
            "enum": [
                "LIKELY_BENIGN",
                "NEEDS_REVIEW",
                "SUSPICIOUS",
                "INSUFFICIENT_EVIDENCE"
            ]
        },

        "priority": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH"
            ]
        },

        "confidence": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH"
            ]
        },

        "escalate_to_8b": {
            "type": "boolean"
        },

        "reason": {
            "type": "string",
            "maxLength": 140
        },

        "evidence_indexes": {
            "type": "array",
            "maxItems": 3,

            "items": {
                "type": "integer",
                "minimum": 0
            }
        }
    },

    "required": [
        "assessment",
        "priority",
        "confidence",
        "escalate_to_8b",
        "reason",
        "evidence_indexes"
    ],

    "additionalProperties": False
}

SYSTEM_PROMPT = r"""
You are performing FAST DFIR TRIAGE.

You are NOT writing a forensic report.

Your job is only to decide whether this finding can remain at
fast-triage level or requires deeper analysis by a larger model.

STRICT RULES:

1. Use only the supplied case evidence.
2. Do not invent missing facts.
3. A Hayabusa rule title is not proof of malicious activity.
4. Hayabusa and EvtxECmd may represent the same EVTX event and
   must not be counted as independent evidence.
5. Cross-artifact evidence may increase investigation value, but
   does not automatically indicate maliciousness.
6. Do not classify an executable as benign or malicious from general
   product or operating-system knowledge. Use supplied evidence only.
7. A detection title, description, or enrichment label is not an
   independently observed fact.
8. Public-IP RDP or administrative activity requires review but is not
   by itself proof of compromise.
9. Use SUSPICIOUS only when supplied event fields show concrete
   suspicious behavior beyond the detection title or rule severity.
10. Use LIKELY_BENIGN only when supplied case evidence positively
    supports a benign explanation; absence of malicious evidence alone
    is not enough.
11. When legitimacy or intent cannot be determined from supplied
    evidence, prefer NEEDS_REVIEW.
12. Keep the reason extremely concise: maximum 15 words.
7. Return no more than 3 supporting evidence_indexes.
8. Select evidence by zero-based index from the supplied evidence array. Do not reproduce event_uid values.
8. Do not output chain-of-thought.
9. Return JSON only.

Assessment guidance:

LIKELY_BENIGN:
Evidence does not currently justify escalation.

NEEDS_REVIEW:
Activity requires analyst attention but there is no strong
suspicious evidence yet.

SUSPICIOUS:
Evidence contains behavior that warrants deep investigation.

INSUFFICIENT_EVIDENCE:
The supplied evidence cannot support a reliable determination.

Set escalate_to_8b=true when:
- assessment is SUSPICIOUS, OR
- the evidence is materially ambiguous and deeper analysis is needed.

Do NOT escalate solely because a detection rule has MEDIUM severity.
"""


def read_json(path):
    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


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


def _short(value, limit=220):

    if value is None:
        return ""

    value = str(value).strip()

    if len(value) <= limit:
        return value

    return value[:limit] + "...[truncated]"


def _selected_attributes(
    attributes,
    max_chars=900,
):

    if not isinstance(
        attributes,
        dict,
    ):
        return {}

    selected = {}
    used = 0

    for key in sorted(
        attributes,
        key=lambda value: str(value),
    ):

        value = attributes[key]

        if value is None:
            continue

        if isinstance(
            value,
            (dict, list, tuple),
        ):
            try:
                clean_value = json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            except Exception:
                clean_value = str(value)
        else:
            clean_value = str(value)

        clean_value = clean_value.strip()

        if not clean_value:
            continue

        clean_value = _short(
            clean_value,
            260,
        )

        entry_size = (
            len(str(key))
            + len(clean_value)
        )

        if (
            selected
            and used + entry_size > max_chars
        ):
            break

        selected[
            str(key)
        ] = clean_value

        used += entry_size

    return selected


def _compact_correlation_edges(
    edges,
    max_chars=1800,
):

    if not isinstance(
        edges,
        list,
    ):
        return []

    result = []
    used = 0

    for edge in edges:

        if not isinstance(
            edge,
            dict,
        ):
            continue

        compact = {}

        for key in sorted(
            edge,
            key=lambda value: str(value),
        ):

            value = edge[key]

            if value is None:
                continue

            if isinstance(
                value,
                (dict, list, tuple),
            ):
                try:
                    value = json.dumps(
                        value,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                except Exception:
                    value = str(value)

            compact[
                str(key)
            ] = _short(
                value,
                220,
            )

        encoded = json.dumps(
            compact,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        if (
            result
            and used + len(encoded) > max_chars
        ):
            break

        result.append(
            compact
        )

        used += len(encoded)

    return result


def build_fast_package(package):

    finding = package.get(
        "finding",
        {},
    )

    source_context = (
        package.get(
            "source_context"
        )
        or {}
    )

    compact_source_context = {}

    for key in (
        "source_kind",
        "confidence",
        "cluster_confidence",
        "event_count",
        "edge_count",
        "independent_family_count",
        "start_timestamp",
        "end_timestamp",
        "source_tools",
        "evidence_families",
        "relationship_types",
        "has_detection_enrichment",
    ):

        if key in source_context:

            compact_source_context[key] = (
                source_context[key]
            )


    compact_evidence = []

    for evidence_index, item in enumerate(
        package.get(
            "evidence",
            [],
        )
    ):

        event = item.get(
            "normalized_event",
            {},
        )

        provenance = item.get(
            "provenance",
            {},
        )

        compact_evidence.append(
            {
                "i":
                    evidence_index,

                "evidence_family":
                    item.get(
                        "evidence_family",
                        "",
                    ),

                "evidence_role":
                    item.get(
                        "evidence_role",
                        "",
                    ),

                "source_tool":
                    _short(
                        event.get(
                            "source_tool"
                        ),
                        60,
                    ),

                "timestamp":
                    _short(
                        event.get(
                            "timestamp"
                        ),
                        80,
                    ),

                "event_type":
                    _short(
                        event.get(
                            "event_type"
                        ),
                        100,
                    ),

                "hostname":
                    _short(
                        event.get(
                            "hostname"
                        ),
                        100,
                    ),

                "username":
                    _short(
                        event.get(
                            "username"
                        ),
                        100,
                    ),

                "executable":
                    _short(
                        event.get(
                            "executable"
                        ),
                        220,
                    ),

                "process_id":
                    _short(
                        event.get(
                            "process_id"
                        ),
                        40,
                    ),

                "command_line":
                    _short(
                        event.get(
                            "command_line"
                        ),
                        300,
                    ),

                "path":
                    _short(
                        event.get(
                            "path"
                        ),
                        260,
                    ),

                "target_path":
                    _short(
                        event.get(
                            "target_path"
                        ),
                        260,
                    ),

                "windows_event_id":
                    _short(
                        event.get(
                            "windows_event_id"
                        ),
                        30,
                    ),

                "provider":
                    _short(
                        event.get(
                            "provider"
                        ),
                        140,
                    ),

                "channel":
                    _short(
                        event.get(
                            "channel"
                        ),
                        120,
                    ),

                "registry_key":
                    _short(
                        event.get(
                            "registry_key"
                        ),
                        260,
                    ),

                "registry_value_name":
                    _short(
                        event.get(
                            "registry_value_name"
                        ),
                        160,
                    ),

                "registry_value_data":
                    _short(
                        event.get(
                            "registry_value_data"
                        ),
                        260,
                    ),

                "detection_rule":
                    _short(
                        event.get(
                            "detection_rule"
                        ),
                        180,
                    ),

                "severity":
                    _short(
                        event.get(
                            "severity"
                        ),
                        40,
                    ),

                "description":
                    _short(
                        event.get(
                            "description"
                        ),
                        240,
                    ),

                "selected_attributes":
                    _selected_attributes(
                        item.get(
                            "attributes",
                            {},
                        )
                    ),

                "provenance":
                    {
                        "parser":
                            _short(
                                provenance.get(
                                    "parser"
                                ),
                                80,
                            ),

                        "source_evidence":
                            _short(
                                provenance.get(
                                    "source_evidence"
                                ),
                                220,
                            ),

                        "source_row":
                            provenance.get(
                                "source_row"
                            ),
                    },
            }
        )


    return {
        "finding":
            {
                "finding_type":
                    finding.get(
                        "finding_type"
                    ),

                "severity":
                    finding.get(
                        "severity"
                    ),

                "confidence":
                    finding.get(
                        "confidence"
                    ),

                "title":
                    finding.get(
                        "title"
                    ),

                "summary":
                    _short(
                        finding.get(
                            "summary"
                        ),
                        500,
                    ),

                "start_timestamp":
                    finding.get(
                        "start_timestamp"
                    ),

                "end_timestamp":
                    finding.get(
                        "end_timestamp"
                    ),

                "independent_family_count":
                    finding.get(
                        "independent_family_count"
                    ),

                "evidence_count":
                    finding.get(
                        "evidence_count"
                    ),

                "detection_rules":
                    finding.get(
                        "detection_rules",
                        [],
                    )[:10],

                "executables":
                    finding.get(
                        "executables",
                        [],
                    )[:10],
            },

        "evidence_independence":
            package.get(
                "evidence_independence",
                {},
            ),

        "source_context":
            compact_source_context,

        "correlation_edges":
            _compact_correlation_edges(
                package.get(
                    "correlation_edges",
                    [],
                )
            ),

        "evidence":
            compact_evidence,

        "rag_search_hints":
            package.get(
                "rag_search_hints",
                [],
            )[:8],
    }


def ollama_chat(package):

    triage_package = (
        build_fast_package(
            package
        )
    )

    compact_package = json.dumps(
        triage_package,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    print(
        "Fast context characters: "
        f"{len(compact_package):,}"
    )

    if len(compact_package) > 18000:

        raise RuntimeError(
            "Fast triage context still "
            "exceeds safe size: "
            f"{len(compact_package)} chars"
        )

    prompt = (
        "Perform fast DFIR triage on "
        "this bounded evidence summary.\n\n"
        "This is triage only, not a full "
        "forensic report.\n"
        "Return only the required JSON.\n\n"
        "EVIDENCE:\n"
        + compact_package
    )

    payload = {
        "model": MODEL,

        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],

        "stream": False,

        "think": False,

        "keep_alive": "30m",

        "format": OUTPUT_SCHEMA,

        "options": {
            "temperature": 0,
            "num_ctx": 8192,
            "num_predict": 360,
        },
    }

    request = urllib.request.Request(
        OLLAMA_URL + "/api/chat",

        data=json.dumps(
            payload
        ).encode("utf-8"),

        headers={
            "Content-Type":
                "application/json"
        },

        method="POST",
    )

    with urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT,
    ) as response:

        body = json.loads(
            response.read().decode(
                "utf-8"
            )
        )

    total_ns = int(body.get("total_duration") or 0)
    load_ns = int(body.get("load_duration") or 0)

    prompt_count = int(
        body.get("prompt_eval_count") or 0
    )
    prompt_ns = int(
        body.get("prompt_eval_duration") or 0
    )

    eval_count = int(
        body.get("eval_count") or 0
    )
    eval_ns = int(
        body.get("eval_duration") or 0
    )

    total_s = total_ns / 1_000_000_000
    load_s = load_ns / 1_000_000_000
    prompt_s = prompt_ns / 1_000_000_000
    eval_s = eval_ns / 1_000_000_000

    prompt_tps = (
        prompt_count / prompt_s
        if prompt_s > 0
        else 0.0
    )

    eval_tps = (
        eval_count / eval_s
        if eval_s > 0
        else 0.0
    )

    print(
        "Ollama metrics: "
        f"prompt={prompt_count} tok / "
        f"{prompt_s:.2f}s "
        f"({prompt_tps:.2f} tok/s) | "
        f"output={eval_count} tok / "
        f"{eval_s:.2f}s "
        f"({eval_tps:.2f} tok/s) | "
        f"load={load_s:.2f}s | "
        f"total={total_s:.2f}s"
    )

    model_result = json.loads(
        body[
            "message"
        ][
            "content"
        ]
    )

    evidence = package.get(
        "evidence",
        [],
    )

    indexes = model_result.get(
        "evidence_indexes",
        [],
    )

    supporting_event_uids = []

    for index in indexes:

        if not isinstance(index, int):
            raise RuntimeError(
                "Non-integer evidence index returned."
            )

        if (
            index < 0
            or
            index >= len(evidence)
        ):
            raise RuntimeError(
                "Evidence index out of range."
            )

        event_uid = evidence[
            index
        ].get(
            "event_uid"
        )

        if not event_uid:
            raise RuntimeError(
                "Selected evidence has no event_uid."
            )

        if event_uid not in supporting_event_uids:
            supporting_event_uids.append(
                event_uid
            )

    return {
        "finding_id":
            package[
                "finding"
            ][
                "finding_id"
            ],

        "assessment":
            model_result[
                "assessment"
            ],

        "priority":
            model_result[
                "priority"
            ],

        "confidence":
            model_result[
                "confidence"
            ],

        "escalate_to_8b":
            model_result[
                "escalate_to_8b"
            ],

        "reason":
            model_result[
                "reason"
            ],

        "supporting_event_uids":
            supporting_event_uids,
    }


def validate_result(
    result,
    package,
):

    required = {
        "finding_id",
        "assessment",
        "priority",
        "confidence",
        "escalate_to_8b",
        "reason",
        "supporting_event_uids",
    }

    missing = required - set(result)

    if missing:
        raise RuntimeError(
            "Missing fields: "
            + ", ".join(
                sorted(missing)
            )
        )

    expected_id = (
        package[
            "finding"
        ][
            "finding_id"
        ]
    )

    if (
        result["finding_id"]
        != expected_id
    ):
        raise RuntimeError(
            "Wrong finding_id returned."
        )

    valid_uids = {
        item["event_uid"]
        for item in package[
            "evidence"
        ]
    }

    unknown = (
        set(
            result[
                "supporting_event_uids"
            ]
        )
        - valid_uids
    )

    if unknown:
        raise RuntimeError(
            "Unknown event_uid returned."
        )

    if (
        result["assessment"]
        == "SUSPICIOUS"
        and
        result[
            "escalate_to_8b"
        ] is not True
    ):
        raise RuntimeError(
            "SUSPICIOUS result must "
            "escalate to 8B."
        )

    return True


parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

CASE_DIR = (
    WORKSPACE_ROOT
    / CASE
)

TRIAGE_DB = (
    CASE_DIR
    / "triage.db"
)

CONTEXT_DIR = (
    CASE_DIR
    / "investigation"
    / "contexts_v1"
)

CONTEXT_INDEX = (
    CONTEXT_DIR
    / "index.json"
)

OUTPUT_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen4b_fast_v1"
)


print("=" * 72)
print("QWEN3 4B FAST INVESTIGATOR V1")
print("=" * 72)

print()
print(f"Case:   {CASE}")
print(f"Model:  {MODEL}")
print(f"Triage: {TRIAGE_DB}")
print(f"Output: {OUTPUT_DIR}")


if not TRIAGE_DB.is_file():
    raise RuntimeError(
        "triage.db missing"
    )

if not CONTEXT_INDEX.is_file():
    raise RuntimeError(
        "Context index missing"
    )


index = read_json(
    CONTEXT_INDEX
)

package_map = {
    item["finding_id"]: item
    for item in index[
        "packages"
    ]
}


conn = sqlite3.connect(
    str(TRIAGE_DB)
)

conn.row_factory = sqlite3.Row


try:

    integrity = conn.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    if integrity != "ok":
        raise RuntimeError(
            "triage.db integrity failure"
        )


    triage_run = conn.execute(
        """
        SELECT
            run_id
        FROM triage_runs
        WHERE case_id = ?
        ORDER BY created_utc DESC
        LIMIT 1
        """,
        (CASE,),
    ).fetchone()


    if triage_run is None:
        raise RuntimeError(
            "Triage run not found"
        )


    run_id = triage_run["run_id"]


    pending = conn.execute(
        """
        SELECT
            finding_id,
            title,
            severity,
            routing_score
        FROM triage_routes
        WHERE run_id = ?
          AND planned_route = 'FAST_4B'
          AND status = 'PENDING'
        ORDER BY
            routing_score DESC,
            finding_id
        """,
        (run_id,),
    ).fetchall()


    print()
    print("FAST TRIAGE INPUT")
    print(
        f"Pending FAST_4B: "
        f"{len(pending):,}"
    )


    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    completed = 0
    escalated = 0
    not_escalated = 0
    failed = 0


    for number, route in enumerate(
        pending,
        start=1,
    ):

        finding_id = (
            route["finding_id"]
        )


        print()
        print("-" * 72)

        print(
            f"[{number:02d}/{len(pending):02d}] "
            f"{route['severity']} | "
            f"{route['title']}"
        )


        package_meta = (
            package_map.get(
                finding_id
            )
        )

        if package_meta is None:
            raise RuntimeError(
                "Context package mapping "
                f"missing for {finding_id}"
            )


        context_path = (
            CONTEXT_DIR
            / package_meta["file"]
        )

        result_path = (
            OUTPUT_DIR
            / (
                f"{finding_id}.json"
            )
        )


        # ----------------------------------------------------
        # Resume support.
        # ----------------------------------------------------

        if result_path.is_file():

            try:

                existing_payload = (
                    read_json(
                        result_path
                    )
                )

                package = read_json(
                    context_path
                )

                existing_result = (
                    existing_payload[
                        "analysis"
                    ]
                )

                validate_result(
                    existing_result,
                    package,
                )

                if existing_result[
                    "escalate_to_8b"
                ]:

                    status = (
                        "ESCALATE_8B"
                    )

                    escalated += 1

                else:

                    status = (
                        "FAST_4B_COMPLETE"
                    )

                    not_escalated += 1


                conn.execute(
                    """
                    UPDATE triage_routes
                    SET status = ?
                    WHERE run_id = ?
                      AND finding_id = ?
                    """,
                    (
                        status,
                        run_id,
                        finding_id,
                    ),
                )

                conn.commit()

                completed += 1

                print(
                    "Existing valid result: "
                    "SKIPPED"
                )

                continue


            except Exception:

                print(
                    "Existing result invalid. "
                    "Reanalyzing."
                )


        package = read_json(
            context_path
        )


        result = None
        last_error = None

        started = time.time()


        for attempt in range(
            1,
            MAX_RETRIES + 1,
        ):

            try:

                print(
                    f"4B attempt "
                    f"{attempt}/{MAX_RETRIES}..."
                )

                result = ollama_chat(
                    package
                )

                validate_result(
                    result,
                    package,
                )

                last_error = None
                break


            except Exception as exc:

                last_error = exc

                print(
                    "Attempt failed: "
                    f"{exc}"
                )


        elapsed = round(
            time.time()
            - started,
            2,
        )


        if result is None:

            failed += 1

            print(
                f"FAILED: {last_error}"
            )

            continue


        if result[
            "escalate_to_8b"
        ]:

            status = (
                "ESCALATE_8B"
            )

            escalated += 1

        else:

            status = (
                "FAST_4B_COMPLETE"
            )

            not_escalated += 1


        payload = {
            "version": "1.0",

            "case_id": CASE,

            "model": MODEL,

            "elapsed_seconds":
                elapsed,

            "source_context":
                context_path.name,

            "analysis":
                result,
        }


        atomic_write_json(
            result_path,
            payload,
        )


        conn.execute(
            """
            UPDATE triage_routes
            SET status = ?
            WHERE run_id = ?
              AND finding_id = ?
            """,
            (
                status,
                run_id,
                finding_id,
            ),
        )

        conn.commit()


        completed += 1


        print(
            f"Assessment: "
            f"{result['assessment']}"
        )

        print(
            f"Priority:   "
            f"{result['priority']}"
        )

        print(
            f"Confidence: "
            f"{result['confidence']}"
        )

        print(
            f"Escalate:   "
            f"{result['escalate_to_8b']}"
        )

        print(
            f"Duration:   "
            f"{elapsed}s"
        )


    print()
    print("=" * 72)
    print("FAST 4B INVESTIGATION RESULTS")
    print("=" * 72)

    print(
        f"Processed:         "
        f"{completed:,}"
    )

    print(
        f"Escalate to 8B:    "
        f"{escalated:,}"
    )

    print(
        f"No 8B escalation:  "
        f"{not_escalated:,}"
    )

    print(
        f"Failed:            "
        f"{failed:,}"
    )


    print()
    print("CURRENT TRIAGE STATUS")


    for row in conn.execute(
        """
        SELECT
            status,
            COUNT(*) AS count
        FROM triage_routes
        WHERE run_id = ?
        GROUP BY status
        ORDER BY status
        """,
        (run_id,),
    ):

        print(
            f"{row['status']:<20} "
            f"{row['count']:,}"
        )


    integrity = conn.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]


    print()
    print(
        f"Triage DB integrity: "
        f"{integrity}"
    )


finally:

    conn.close()


print()
print("=" * 72)
print("QWEN3 4B FAST INVESTIGATOR V1: COMPLETE")
print("=" * 72)

print()
print("Only FAST_4B findings were processed.")
print("No evidence/correlation/findings DB was modified.")
print()
print("NEXT:")
print("ESCALATE_8B -> Qwen3:8B Deep Investigator")
print("FAST_4B_COMPLETE -> no deep model required")






