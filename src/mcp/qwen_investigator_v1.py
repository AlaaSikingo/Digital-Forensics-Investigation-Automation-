import argparse
import json
import sqlite3
import re
import time
import urllib.request
import urllib.error
from pathlib import Path

from case_config import require_existing_case


parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

CASE_DIR = require_existing_case(
    CASE
)

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen3:8b"

TRIAGE_DB = (
    CASE_DIR
    / "triage.db"
)

CONTEXT_DIR = (
    CASE_DIR
    / "investigation"
    / "contexts_v1"
)

OUTPUT_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen_v1"
)

INDEX_PATH = CONTEXT_DIR / "index.json"

REQUEST_TIMEOUT = 900

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
                "HIGH_PRIORITY_REVIEW",
                "INSUFFICIENT_EVIDENCE"
            ]
        },

        "priority": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
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

        "executive_summary": {
            "type": "string"
        },

        "observed_facts": {
            "type": "array",
            "maxItems": 4,

            "items": {
                "type": "object",

                "properties": {
                    "fact": {
                        "type": "string"
                    },

                    "evidence_indexes": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 8,

                        "items": {
                            "type": "integer",
                            "minimum": 0
                        }
                    }
                },

                "required": [
                    "fact",
                    "evidence_indexes"
                ],

                "additionalProperties": False
            }
        },

        "analytical_assessment": {
            "type": "array",
            "maxItems": 2,

            "items": {
                "type": "object",

                "properties": {
                    "assessment": {
                        "type": "string"
                    },

                    "evidence_indexes": {
                        "type": "array",
                        "maxItems": 8,

                        "items": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },

                    "confidence": {
                        "type": "string",
                        "enum": [
                            "LOW",
                            "MEDIUM",
                            "HIGH"
                        ]
                    }
                },

                "required": [
                    "assessment",
                    "evidence_indexes",
                    "confidence"
                ],

                "additionalProperties": False
            }
        },

        "alternative_explanations": {
            "type": "array",
            "maxItems": 2,

            "items": {
                "type": "string"
            }
        },

        "evidence_gaps": {
            "type": "array",
            "maxItems": 3,

            "items": {
                "type": "string"
            }
        },

        "recommended_next_steps": {
            "type": "array",
            "maxItems": 3,

            "items": {
                "type": "object",

                "properties": {

                    "action": {
                        "type": "string"
                    },

                    "reason": {
                        "type": "string"
                    },

                    "target_evidence": {
                        "type": "string"
                    }
                },

                "required": [
                    "action",
                    "reason",
                    "target_evidence"
                ],

                "additionalProperties": False
            }
        },

        "final_disposition": {
            "type": "string",

            "enum": [
                "NO_ESCALATION_YET",
                "CONTINUE_INVESTIGATION",
                "ESCALATE_FOR_ANALYST_REVIEW"
            ]
        },

        "requires_analyst_review": {
            "type": "boolean",
            "enum": [
                True
            ]
        }
    },

    "required": [
        "assessment",
        "priority",
        "confidence",
        "executive_summary",
        "observed_facts",
        "analytical_assessment",
        "alternative_explanations",
        "evidence_gaps",
        "recommended_next_steps",
        "final_disposition",
        "requires_analyst_review"
    ],

    "additionalProperties": False
}
SYSTEM_PROMPT = r"""
You are a Digital Forensics and Incident Response investigator.

You are analyzing a bounded evidence package from a forensic case.

STRICT RULES:

1. Use only evidence provided in the package.
2. Do not invent events, users, IPs, commands, files, or timelines.
3. Separate OBSERVED FACTS from ANALYTICAL INFERENCE.
4. Every observed case fact must reference one or more evidence_indexes.
5. A Hayabusa detection title or severity is not proof that activity is malicious.
6. Hayabusa and EvtxECmd may describe the same underlying EVTX event.
   They MUST NOT be counted as independent evidence sources.
7. Preserve uncertainty.
8. If evidence is insufficient, explicitly say so.
9. Recommend the next evidence that should be examined.
10. Do not claim malware, compromise, persistence, lateral movement,
    privilege escalation, or attacker activity unless the supplied evidence
    supports that conclusion.
11. Do not output chain-of-thought or hidden reasoning.
12. Return JSON only.
12a. Evidence records contain zero-based "i" values.
12b. Reference supplied evidence only through evidence_indexes.
12c. Do not reproduce event_uid or finding_id values.
13. Be concise. This is a finding-level deep assessment, not a full report.
14. observed_facts: maximum 4 items; include only material facts.
15. analytical_assessment: maximum 2 items; include the strongest supported inferences.
16. alternative_explanations: maximum 2 items.
17. evidence_gaps: maximum 3 items; include only gaps that could change the assessment.
18. recommended_next_steps: maximum 3 items; prioritize highest-value evidence actions.
19. Keep executive_summary to 2 short sentences maximum.
20. Keep each fact, inference, explanation, gap, action, and reason concise.
21. Do not repeat the same evidence in multiple facts unless necessary.
22. Do not omit materially important evidence merely to produce fewer items.

The output JSON MUST have exactly this structure:

{
  "assessment": "",
  "priority": "",
  "confidence": "",
  "executive_summary": "",
  "observed_facts": [
    {
      "fact": "",
      "evidence_indexes": []
    }
  ],
  "analytical_assessment": [
    {
      "assessment": "",
      "evidence_indexes": [],
      "confidence": ""
    }
  ],
  "alternative_explanations": [],
  "evidence_gaps": [],
  "recommended_next_steps": [
    {
      "action": "",
      "reason": "",
      "target_evidence": ""
    }
  ],
  "final_disposition": "",
  "requires_analyst_review": true
}

Allowed assessment values:

LIKELY_BENIGN
NEEDS_REVIEW
SUSPICIOUS
HIGH_PRIORITY_REVIEW
INSUFFICIENT_EVIDENCE

Allowed priority values:

LOW
MEDIUM
HIGH
CRITICAL

Allowed confidence values:

LOW
MEDIUM
HIGH

Allowed final_disposition values:

NO_ESCALATION_YET
CONTINUE_INVESTIGATION
ESCALATE_FOR_ANALYST_REVIEW

requires_analyst_review must always be true.
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


def ollama_chat(
    system_prompt,
    user_prompt,
):

    payload = {
        "model": MODEL,

        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],

        "stream": False,

        # Qwen3 supports native non-thinking mode in Ollama.
        # This is the primary CPU performance optimization.
        "think": False,

        "format": OUTPUT_SCHEMA,

        # Keep the model resident between sequential findings.
        "keep_alive": "30m",

        "options": {
            "temperature": 0.0,

            # Preserve enough context for larger evidence packages.
            "num_ctx": 8192,

            # Finding-level investigation should be concise.
            # Prevent multi-thousand-token responses.
            "num_predict": 1400,
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

    content = (
        body.get(
            "message",
            {}
        ).get(
            "content",
            ""
        )
    )


    return content.strip()


def extract_json(text):

    text = text.strip()


    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.I | re.S,
    ).strip()


    if text.startswith("```"):

        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.I,
        )

        text = re.sub(
            r"\s*```$",
            "",
            text,
        )


    try:
        return json.loads(text)

    except json.JSONDecodeError:

        start = text.find("{")
        end = text.rfind("}")

        if (
            start >= 0
            and end > start
        ):

            return json.loads(
                text[
                    start:end + 1
                ]
            )

        raise


def reconstruct_model_result(
    model_result,
    package,
):

    evidence = package.get(
        "evidence",
        []
    )


    def indexes_to_uids(indexes):

        if not isinstance(
            indexes,
            list
        ):
            raise RuntimeError(
                "evidence_indexes must be a list."
            )

        uids = []

        for index in indexes:

            if (
                isinstance(index, bool)
                or not isinstance(index, int)
            ):
                raise RuntimeError(
                    "Invalid evidence index type."
                )

            if (
                index < 0
                or index >= len(evidence)
            ):
                raise RuntimeError(
                    f"Evidence index out of range: {index}"
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

            if event_uid not in uids:
                uids.append(
                    event_uid
                )

        return uids


    result = dict(
        model_result
    )

    result["finding_id"] = (
        package[
            "finding"
        ][
            "finding_id"
        ]
    )


    observed_facts = []

    for fact in model_result.get(
        "observed_facts",
        []
    ):

        observed_facts.append({
            "fact":
                fact.get(
                    "fact",
                    ""
                ),

            "event_uids":
                indexes_to_uids(
                    fact.get(
                        "evidence_indexes",
                        []
                    )
                ),
        })

    result[
        "observed_facts"
    ] = observed_facts


    analytical = []

    for item in model_result.get(
        "analytical_assessment",
        []
    ):

        analytical.append({
            "assessment":
                item.get(
                    "assessment",
                    ""
                ),

            "supporting_event_uids":
                indexes_to_uids(
                    item.get(
                        "evidence_indexes",
                        []
                    )
                ),

            "confidence":
                item.get(
                    "confidence"
                ),
        })

    result[
        "analytical_assessment"
    ] = analytical


    return result



def validate_result(
    result,
    package,
):

    required = {
        "finding_id",
        "assessment",
        "priority",
        "confidence",
        "executive_summary",
        "observed_facts",
        "analytical_assessment",
        "alternative_explanations",
        "evidence_gaps",
        "recommended_next_steps",
        "final_disposition",
        "requires_analyst_review",
    }


    missing = (
        required
        - set(result)
    )


    if missing:
        raise RuntimeError(
            "Missing result fields: "
            + ", ".join(
                sorted(missing)
            )
        )


    expected_finding_id = (
        package[
            "finding"
        ][
            "finding_id"
        ]
    )


    if (
        result["finding_id"]
        != expected_finding_id
    ):
        raise RuntimeError(
            "Qwen returned wrong finding_id"
        )


    if result["assessment"] not in {
        "LIKELY_BENIGN",
        "NEEDS_REVIEW",
        "SUSPICIOUS",
        "HIGH_PRIORITY_REVIEW",
        "INSUFFICIENT_EVIDENCE",
    }:
        raise RuntimeError(
            "Invalid assessment"
        )


    if result["priority"] not in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        raise RuntimeError(
            "Invalid priority"
        )


    if result["confidence"] not in {
        "LOW",
        "MEDIUM",
        "HIGH",
    }:
        raise RuntimeError(
            "Invalid confidence"
        )


    if result[
        "final_disposition"
    ] not in {
        "NO_ESCALATION_YET",
        "CONTINUE_INVESTIGATION",
        "ESCALATE_FOR_ANALYST_REVIEW",
    }:
        raise RuntimeError(
            "Invalid final disposition"
        )


    if (
        result[
            "requires_analyst_review"
        ]
        is not True
    ):
        raise RuntimeError(
            "requires_analyst_review "
            "must be true"
        )


    valid_uids = {
        item["event_uid"]
        for item in package[
            "evidence"
        ]
    }


    for fact in result[
        "observed_facts"
    ]:

        uids = fact.get(
            "event_uids",
            [],
        )

        if not uids:
            raise RuntimeError(
                "Observed fact has no "
                "event_uid"
            )


        unknown = (
            set(uids)
            - valid_uids
        )

        if unknown:
            raise RuntimeError(
                "Observed fact references "
                "unknown event_uid"
            )


    for item in result[
        "analytical_assessment"
    ]:

        uids = item.get(
            "supporting_event_uids",
            [],
        )


        unknown = (
            set(uids)
            - valid_uids
        )

        if unknown:
            raise RuntimeError(
                "Analytical assessment "
                "references unknown "
                "event_uid"
            )


    return True


def build_user_prompt(
    package,
):

    prompt_package = json.loads(
        json.dumps(
            package,
            ensure_ascii=False,
        )
    )

    finding = prompt_package.get(
        "finding",
        {}
    )

    if isinstance(
        finding,
        dict
    ):
        finding.pop(
            "finding_id",
            None,
        )

    for evidence_index, item in enumerate(
        prompt_package.get(
            "evidence",
            []
        )
    ):
        item["i"] = evidence_index

        item.pop(
            "event_uid",
            None,
        )

    evidence_package = json.dumps(
        prompt_package,
        ensure_ascii=False,

        # Compact model-facing package.
        # Full provenance remains in the original package.
        separators=(",", ":"),
    )


    return (
        "Analyze the following DFIR "
        "evidence package.\n\n"
        "Do not use outside facts.\n"
        "Do not assume a detection means "
        "compromise.\n"
        "Return only the required JSON.\n\n"
        "EVIDENCE PACKAGE:\n"
        + evidence_package
    )


print("=" * 72)
print("QWEN INVESTIGATOR V1")
print("=" * 72)

print()
print(f"Model:       {MODEL}")
print(f"Ollama:      {OLLAMA_URL}")
print(f"Context dir: {CONTEXT_DIR}")
print(f"Output dir:  {OUTPUT_DIR}")
print()
print("Execution mode: SEQUENTIAL ONLY")


if not INDEX_PATH.is_file():
    raise RuntimeError(
        f"Missing context index: "
        f"{INDEX_PATH}"
    )


index = read_json(
    INDEX_PATH
)


packages = index.get(
    "packages",
    []
)


if not TRIAGE_DB.is_file():
    raise RuntimeError(
        f"Missing triage database: "
        f"{TRIAGE_DB}"
    )


triage_conn = sqlite3.connect(
    str(TRIAGE_DB)
)

triage_conn.row_factory = sqlite3.Row


try:

    integrity = triage_conn.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    if integrity != "ok":
        raise RuntimeError(
            "triage.db integrity failure"
        )


    triage_run = triage_conn.execute(
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
            "No triage run found for case."
        )


    TRIAGE_RUN_ID = (
        triage_run["run_id"]
    )


    deep_routes = triage_conn.execute(
        """
        SELECT
            finding_id,
            title,
            severity,
            planned_route,
            status,
            routing_score
        FROM triage_routes
        WHERE run_id = ?
          AND (
                (
                    planned_route = 'DEEP_8B'
                    AND status = 'PENDING'
                )
                OR
                status = 'ESCALATE_8B'
              )
        ORDER BY
            routing_score DESC,
            finding_id
        """,
        (TRIAGE_RUN_ID,),
    ).fetchall()


finally:

    triage_conn.close()


deep_finding_ids = {
    row["finding_id"]
    for row in deep_routes
}


package_map = {
    item["finding_id"]: item
    for item in packages
}


missing_contexts = sorted(
    finding_id
    for finding_id
    in deep_finding_ids
    if finding_id not in package_map
)


if missing_contexts:
    raise RuntimeError(
        "Missing investigation context for "
        "deep finding(s): "
        + ", ".join(
            missing_contexts
        )
    )


packages = [
    package_map[
        row["finding_id"]
    ]
    for row in deep_routes
]


print()
print("DEEP TRIAGE INPUT")
print(
    f"Pending selective 8B: "
    f"{len(packages):,}"
)


for row in deep_routes:

    print(
        f"  {row['status']} | "
        f"{row['severity']} | "
        f"{row['title']}"
    )


def mark_analyzed_8b(
    finding_id,
):

    conn = sqlite3.connect(
        str(TRIAGE_DB)
    )

    try:

        conn.execute(
            """
            UPDATE triage_routes
            SET status = 'ANALYZED_8B'
            WHERE run_id = ?
              AND finding_id = ?
            """,
            (
                TRIAGE_RUN_ID,
                finding_id,
            ),
        )

        conn.commit()

    finally:

        conn.close()


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ------------------------------------------------------------
# Verify Ollama before selective deep analyses.
# ------------------------------------------------------------

print()
print("OLLAMA CONNECTIVITY")

try:

    request = urllib.request.Request(
        OLLAMA_URL + "/api/tags",
        method="GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:

        tags = json.loads(
            response.read().decode(
                "utf-8"
            )
        )

except Exception as exc:

    raise RuntimeError(
        f"Ollama unavailable: {exc}"
    )


available_models = {
    item.get("name", "")
    for item in tags.get(
        "models",
        []
    )
}


if (
    MODEL not in available_models
    and not any(
        name.startswith(
            MODEL + ":"
        )
        for name in available_models
    )
):
    print(
        "Available models:"
    )

    for name in sorted(
        available_models
    ):
        print(
            f"  {name}"
        )

    raise RuntimeError(
        f"{MODEL} is not available "
        "in Ollama."
    )


print("Ollama: PASS")
print(f"{MODEL}: AVAILABLE")


results_index = {
    "version": "1.0",
    "case_id": CASE,
    "model": MODEL,
    "package_count": len(
        packages
    ),
    "completed": 0,
    "failed": 0,
    "results": [],
}


completed = 0
failed = 0


print()
print("=" * 72)
print("STARTING INVESTIGATION")
print("=" * 72)


for number, package_meta in enumerate(
    packages,
    start=1,
):

    priority = package_meta[
        "priority"
    ]

    finding_id = package_meta[
        "finding_id"
    ]

    context_file = (
        CONTEXT_DIR
        / package_meta["file"]
    )

    result_file = (
        OUTPUT_DIR
        / (
            f"{priority:03d}_"
            f"{finding_id}.json"
        )
    )


    print()
    print("-" * 72)

    print(
        f"[{number:02d}/{len(packages):02d}] "
        f"{package_meta['severity']} | "
        f"{package_meta['title']}"
    )


    # --------------------------------------------------------
    # Resume support.
    # --------------------------------------------------------

    if result_file.is_file():

        try:

            existing = read_json(
                result_file
            )

            package = read_json(
                context_file
            )

            validate_result(
                existing[
                    "analysis"
                ],
                package,
            )


            print(
                "Existing valid result: "
                "SKIPPED"
            )

            completed += 1

            mark_analyzed_8b(
                finding_id
            )

            results_index[
                "results"
            ].append({
                "priority":
                    priority,

                "finding_id":
                    finding_id,

                "status":
                    "COMPLETED",

                "file":
                    result_file.name,

                "assessment":
                    existing[
                        "analysis"
                    ][
                        "assessment"
                    ],

                "investigation_priority":
                    existing[
                        "analysis"
                    ][
                        "priority"
                    ],
            })

            continue

        except Exception:

            print(
                "Existing result invalid. "
                "Reanalyzing."
            )


    package = read_json(
        context_file
    )


    user_prompt = (
        build_user_prompt(
            package
        )
    )


    start_time = time.time()

    last_error = None
    analysis = None


    for attempt in range(
        1,
        MAX_RETRIES + 1,
    ):

        try:

            print(
                f"Qwen analysis attempt "
                f"{attempt}/{MAX_RETRIES}..."
            )


            raw = ollama_chat(
                SYSTEM_PROMPT,
                user_prompt,
            )


            model_analysis = extract_json(
                raw
            )


            analysis = reconstruct_model_result(
                model_analysis,
                package,
            )


            validate_result(
                analysis,
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


            if attempt < MAX_RETRIES:

                user_prompt += (
                    "\n\nYour previous response "
                    "did not satisfy the required "
                    "JSON schema or evidence UID "
                    "constraints. Return corrected "
                    "JSON only."
                )


    elapsed = round(
        time.time()
        - start_time,
        2,
    )


    if analysis is None:

        failed += 1

        print(
            f"FAILED after "
            f"{elapsed} seconds"
        )

        print(
            f"Error: {last_error}"
        )


        results_index[
            "results"
        ].append({
            "priority":
                priority,

            "finding_id":
                finding_id,

            "status":
                "FAILED",

            "error":
                str(last_error),
        })


        atomic_write_json(
            OUTPUT_DIR
            / "index.json",
            results_index,
        )

        continue


    result_payload = {
        "version": "1.0",

        "case_id": CASE,

        "model": MODEL,

        "source_context_file":
            context_file.name,

        "elapsed_seconds":
            elapsed,

        "analysis":
            analysis,
    }


    atomic_write_json(
        result_file,
        result_payload,
    )


    mark_analyzed_8b(
        finding_id
    )


    completed += 1


    results_index[
        "results"
    ].append({
        "priority":
            priority,

        "finding_id":
            finding_id,

        "status":
            "COMPLETED",

        "file":
            result_file.name,

        "assessment":
            analysis[
                "assessment"
            ],

        "investigation_priority":
            analysis[
                "priority"
            ],

        "confidence":
            analysis[
                "confidence"
            ],

        "final_disposition":
            analysis[
                "final_disposition"
            ],

        "elapsed_seconds":
            elapsed,
    })


    results_index[
        "completed"
    ] = completed

    results_index[
        "failed"
    ] = failed


    atomic_write_json(
        OUTPUT_DIR
        / "index.json",
        results_index,
    )


    print(
        f"Assessment:  "
        f"{analysis['assessment']}"
    )

    print(
        f"Priority:    "
        f"{analysis['priority']}"
    )

    print(
        f"Confidence:  "
        f"{analysis['confidence']}"
    )

    print(
        f"Disposition: "
        f"{analysis['final_disposition']}"
    )

    print(
        f"Duration:    {elapsed}s"
    )


results_index[
    "completed"
] = completed

results_index[
    "failed"
] = failed


atomic_write_json(
    OUTPUT_DIR
    / "index.json",
    results_index,
)


print()
print("=" * 72)
print("QWEN INVESTIGATOR V1 RESULTS")
print("=" * 72)

print(
    f"Completed: {completed:,}"
)

print(
    f"Failed:    {failed:,}"
)

print(
    f"Output:    {OUTPUT_DIR}"
)


assessment_counts = {}

for item in results_index[
    "results"
]:

    if item.get(
        "status"
    ) != "COMPLETED":
        continue

    assessment = item.get(
        "assessment",
        "UNKNOWN",
    )

    assessment_counts[
        assessment
    ] = (
        assessment_counts.get(
            assessment,
            0,
        )
        + 1
    )


print()
print("ASSESSMENTS")

for key in (
    "HIGH_PRIORITY_REVIEW",
    "SUSPICIOUS",
    "NEEDS_REVIEW",
    "INSUFFICIENT_EVIDENCE",
    "LIKELY_BENIGN",
):

    print(
        f"{key:<25} "
        f"{assessment_counts.get(key, 0):,}"
    )


if failed:

    print()
    print(
        "Some findings failed. "
        "Re-running this script will "
        "resume and skip valid results."
    )


print()
print("=" * 72)
print("QWEN INVESTIGATOR V1: COMPLETE")
print("=" * 72)

print()
print("Evidence DB:      UNCHANGED")
print("Correlation DB:   UNCHANGED")
print("Findings DB:      UNCHANGED")
print()
print("Qwen outputs are analytical assessments,")
print("not final analyst determinations.")
print()
print("NEXT: RAG ENRICHMENT + CASE-LEVEL INVESTIGATION SYNTHESIS")



