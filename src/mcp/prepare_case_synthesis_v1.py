import argparse
import json
from pathlib import Path


WORKSPACE_ROOT = Path(
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace")
)


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


def short(
    value,
    limit=500,
):

    if value is None:
        return ""

    value = str(value).strip()

    if len(value) <= limit:
        return value

    return (
        value[:limit]
        + "...[truncated]"
    )


def load_analysis_map(
    directory,
):

    result = {}

    if not directory.is_dir():
        return result

    for path in directory.glob(
        "*.json"
    ):

        if path.name.lower() == "index.json":
            continue

        try:

            payload = read_json(
                path
            )

            analysis = payload.get(
                "analysis",
                {}
            )

            finding_id = analysis.get(
                "finding_id"
            )

            if finding_id:

                result[
                    finding_id
                ] = {
                    "file":
                        path.name,

                    "payload":
                        payload,
                }

        except Exception:
            continue

    return result


def load_rag_map(
    directory,
):

    result = {}

    if not directory.is_dir():
        return result

    for path in directory.glob(
        "*.json"
    ):

        if path.name.lower() == "index.json":
            continue

        try:

            payload = read_json(
                path
            )

            finding_id = (
                payload.get(
                    "finding_id"
                )
                or payload.get(
                    "finding",
                    {}
                ).get(
                    "finding_id"
                )
            )

            if finding_id:

                result[
                    finding_id
                ] = {
                    "file":
                        path.name,

                    "payload":
                        payload,
                }

        except Exception:
            continue

    return result


def compact_8b(
    payload,
):

    analysis = payload.get(
        "analysis",
        {}
    )

    return {
        "model":
            payload.get(
                "model"
            ),

        "assessment":
            analysis.get(
                "assessment"
            ),

        "priority":
            analysis.get(
                "priority"
            ),

        "confidence":
            analysis.get(
                "confidence"
            ),

        "executive_summary":
            short(
                analysis.get(
                    "executive_summary"
                ),
                900,
            ),

        "observed_facts":
            analysis.get(
                "observed_facts",
                []
            )[:6],

        "analytical_assessment":
            analysis.get(
                "analytical_assessment",
                []
            )[:4],

        "alternative_explanations":
            analysis.get(
                "alternative_explanations",
                []
            )[:3],

        "evidence_gaps":
            analysis.get(
                "evidence_gaps",
                []
            )[:5],

        "recommended_next_steps":
            analysis.get(
                "recommended_next_steps",
                []
            )[:5],

        "final_disposition":
            analysis.get(
                "final_disposition"
            ),
    }


def compact_4b(
    payload,
):

    analysis = payload.get(
        "analysis",
        {}
    )

    return {
        "model":
            payload.get(
                "model"
            ),

        "assessment":
            analysis.get(
                "assessment"
            ),

        "priority":
            analysis.get(
                "priority"
            ),

        "confidence":
            analysis.get(
                "confidence"
            ),

        "escalate_to_8b":
            analysis.get(
                "escalate_to_8b"
            ),

        "reason":
            short(
                analysis.get(
                    "reason"
                ),
                300,
            ),

        "supporting_event_uids":
            analysis.get(
                "supporting_event_uids",
                []
            )[:3],
    }


def extract_rag_references(
    payload,
):

    candidates = []

    for key in (
        "historical_references",
        "references",
        "results",
        "matches",
        "retrieved",
    ):

        value = payload.get(
            key
        )

        if isinstance(
            value,
            list,
        ):

            candidates = value
            break

    if not candidates:

        for value in payload.values():

            if (
                isinstance(
                    value,
                    list,
                )
                and value
                and isinstance(
                    value[0],
                    dict,
                )
            ):

                first = value[0]

                if (
                    "score" in first
                    or "similarity" in first
                    or "reference_type" in first
                ):

                    candidates = value
                    break

    compact = []

    for item in candidates[:4]:

        compact.append({
            "reference_type":
                "historical_reference",

            "historical_only":
                True,

            "case_fact":
                False,

            "score":
                item.get(
                    "score",
                    item.get(
                        "similarity"
                    )
                ),

            "document":
                (
                    item.get(
                        "document"
                    )
                    or item.get(
                        "document_id"
                    )
                    or item.get(
                        "source"
                    )
                    or item.get(
                        "title"
                    )
                ),

            "chunk_id":
                item.get(
                    "chunk_id"
                ),

            "text_excerpt":
                short(
                    (
                        item.get(
                            "text"
                        )
                        or item.get(
                            "retrieved_text"
                        )
                        or item.get(
                            "content"
                        )
                        or ""
                    ),
                    450,
                ),
        })

    return compact


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

INVESTIGATION_DIR = (
    CASE_DIR
    / "investigation"
)

CONTEXT_DIR = (
    INVESTIGATION_DIR
    / "contexts_v1"
)

CONTEXT_INDEX = (
    CONTEXT_DIR
    / "index.json"
)

QWEN8_DIR = (
    INVESTIGATION_DIR
    / "qwen_v1"
)

QWEN4_DIR = (
    INVESTIGATION_DIR
    / "qwen4b_fast_v1"
)

RAG_DIR = (
    INVESTIGATION_DIR
    / "rag_v1"
    / "results"
)

OUTPUT_DIR = (
    INVESTIGATION_DIR
    / "case_synthesis_v1"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "case_synthesis_input.json"
)


print("=" * 72)
print("CASE SYNTHESIS PREPARATION V1")
print("=" * 72)

print()
print(f"Case:     {CASE}")
print(f"Contexts: {CONTEXT_DIR}")
print(f"8B:       {QWEN8_DIR}")
print(f"4B:       {QWEN4_DIR}")
print(f"RAG:      {RAG_DIR}")
print(f"Output:   {OUTPUT_FILE}")


if not CONTEXT_INDEX.is_file():

    raise RuntimeError(
        "Context index missing"
    )


context_index = read_json(
    CONTEXT_INDEX
)

packages = context_index.get(
    "packages",
    []
)


qwen8_map = load_analysis_map(
    QWEN8_DIR
)

qwen4_map = load_analysis_map(
    QWEN4_DIR
)

rag_map = load_rag_map(
    RAG_DIR
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


synthesis_findings = []

all_event_uids = set()

count_8b = 0
count_4b = 0
count_no_ai = 0
count_rag = 0


for package_meta in packages:

    finding_id = (
        package_meta[
            "finding_id"
        ]
    )

    context_path = (
        CONTEXT_DIR
        / package_meta[
            "file"
        ]
    )

    context = read_json(
        context_path
    )

    finding = context.get(
        "finding",
        {}
    )

    evidence = context.get(
        "evidence",
        []
    )


    event_uids = []

    for item in evidence:

        uid = item.get(
            "event_uid"
        )

        if uid:

            event_uids.append(
                uid
            )

            all_event_uids.add(
                uid
            )


    ai_source = "NONE"
    ai_analysis = None


    if finding_id in qwen8_map:

        ai_source = "QWEN3_8B_DEEP"

        ai_analysis = compact_8b(
            qwen8_map[
                finding_id
            ][
                "payload"
            ]
        )

        count_8b += 1


    elif finding_id in qwen4_map:

        ai_source = "QWEN3_4B_FAST"

        ai_analysis = compact_4b(
            qwen4_map[
                finding_id
            ][
                "payload"
            ]
        )

        count_4b += 1


    else:

        count_no_ai += 1


    historical_references = []


    if finding_id in rag_map:

        historical_references = (
            extract_rag_references(
                rag_map[
                    finding_id
                ][
                    "payload"
                ]
            )
        )

        count_rag += 1


    synthesis_findings.append({

        "finding_id":
            finding_id,

        "priority":
            package_meta.get(
                "priority"
            ),

        "severity":
            (
                finding.get(
                    "severity"
                )
                or package_meta.get(
                    "severity"
                )
            ),

        "confidence":
            finding.get(
                "confidence"
            ),

        "finding_type":
            finding.get(
                "finding_type"
            ),

        "title":
            finding.get(
                "title"
            ),

        "summary":
            short(
                finding.get(
                    "summary"
                ),
                700,
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
            len(
                event_uids
            ),

        "event_uids":
            event_uids,

        "case_evidence_authority":
            True,

        "ai_assessment_source":
            ai_source,

        "ai_assessment":
            ai_analysis,

        "historical_references":
            historical_references,

        "historical_reference_rules": {
            "case_fact":
                False,

            "can_establish_maliciousness":
                False,

            "similarity_is_evidence":
                False,

            "authoritative_chronology":
                False,
        },
    })


synthesis_findings.sort(
    key=lambda item: (
        item.get(
            "priority"
        )
        if isinstance(
            item.get(
                "priority"
            ),
            int,
        )
        else 999999
    )
)


payload = {

    "version":
        "1.0",

    "case_id":
        CASE,

    "purpose":
        "Input for evidence-grounded case-level DFIR synthesis",

    "case_fact_policy": {

        "current_case_evidence_authoritative":
            True,

        "historical_reference_is_case_fact":
            False,

        "historical_similarity_is_evidence":
            False,

        "ai_assessment_is_final_analyst_determination":
            False,

        "event_uid_grounding_required":
            True,

        "hayabusa_evtx_independent":
            False,
    },


    "case_statistics": {

        "finding_count":
            len(
                synthesis_findings
            ),

        "unique_event_uid_count":
            len(
                all_event_uids
            ),

        "qwen8_deep_count":
            count_8b,

        "qwen4_fast_count":
            count_4b,

        "without_ai_count":
            count_no_ai,

        "rag_enriched_finding_count":
            count_rag,
    },


    "synthesis_guardrails": [

        "Only CURRENT CASE evidence may establish CASE facts.",

        "Every stated CASE fact must cite one or more event_uid values.",

        "Historical RAG material is contextual knowledge only.",

        "Historical similarity cannot establish compromise or maliciousness.",

        "Do not treat Hayabusa and EvtxECmd representations of the same EVTX event as independent evidence.",

        "Do not infer attack sequence from timestamps alone.",

        "Separate observed facts from analytical inference.",

        "Preserve uncertainty and alternative explanations.",

        "Explicitly identify missing evidence and recommended next investigative actions."
    ],


    "findings":
        synthesis_findings,
}


atomic_write_json(
    OUTPUT_FILE,
    payload,
)


size = OUTPUT_FILE.stat().st_size


print()
print("=" * 72)
print("CASE SYNTHESIS PREPARATION RESULTS")
print("=" * 72)

print(
    f"Findings:             "
    f"{len(synthesis_findings):,}"
)

print(
    f"Unique event_uids:    "
    f"{len(all_event_uids):,}"
)

print(
    f"8B assessments:       "
    f"{count_8b:,}"
)

print(
    f"4B assessments:       "
    f"{count_4b:,}"
)

print(
    f"Without AI:           "
    f"{count_no_ai:,}"
)

print(
    f"RAG-enriched findings:"
    f" {count_rag:,}"
)

print(
    f"Output bytes:         "
    f"{size:,}"
)

print()
print("Qwen calls: 0")
print("Databases modified: 0")

print()
print("=" * 72)
print("CASE SYNTHESIS PREPARATION V1: COMPLETE")
print("=" * 72)
