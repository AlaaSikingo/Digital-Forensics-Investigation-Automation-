import argparse
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path


WORKSPACE_ROOT = Path(
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace")
)


ASSESSMENT_RANK = {
    "HIGH_PRIORITY_REVIEW": 5,
    "SUSPICIOUS": 4,
    "NEEDS_REVIEW": 3,
    "INSUFFICIENT_EVIDENCE": 2,
    "LIKELY_BENIGN": 1,
}


PRIORITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


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


def dedupe_strings(values):
    result = []
    seen = set()

    for value in values:

        if not value:
            continue

        if isinstance(value, dict):
            value = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
            )

        text = str(value).strip()

        if not text:
            continue

        key = text.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(text)

    return result


def normalize_text(value):

    text = str(
        value or ""
    ).strip().lower()

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    text = re.sub(
        r"[^\w\\./:$%-]+",
        " ",
        text,
    )

    return text.strip()


def dedupe_fact_records(
    records,
):

    result = []
    index = {}

    for item in records:

        fact = str(
            item.get(
                "fact",
                ""
            )
        ).strip()

        if not fact:
            continue

        key = normalize_text(
            fact
        )

        if not key:
            continue

        if key not in index:

            new_item = {
                "fact":
                    fact,

                "event_uids":
                    [],

                "source":
                    item.get(
                        "source"
                    ),
            }

            result.append(
                new_item
            )

            index[key] = (
                len(result) - 1
            )

        target = result[
            index[key]
        ]

        for uid in item.get(
            "event_uids",
            []
        ):

            if (
                uid
                and uid not in
                target[
                    "event_uids"
                ]
            ):

                target[
                    "event_uids"
                ].append(
                    uid
                )

    return result


def clean_recommendation(
    value,
):

    item = value

    if isinstance(
        item,
        str,
    ):

        stripped = (
            item.strip()
        )

        if (
            stripped.startswith(
                "{"
            )
            and stripped.endswith(
                "}"
            )
        ):

            try:

                item = json.loads(
                    stripped
                )

            except Exception:

                item = stripped


    if isinstance(
        item,
        dict,
    ):

        action = str(
            item.get(
                "action",
                ""
            )
        ).strip()

        reason = str(
            item.get(
                "reason",
                ""
            )
        ).strip()

        if (
            action
            and reason
        ):

            return (
                f"{action} "
                f"Reason: {reason}"
            )

        if action:
            return action

        return ""


    text = str(
        item or ""
    ).strip()


    text = re.sub(
        r',?\s*"target_evidence"\s*:\s*"[^"]*"',
        "",
        text,
        flags=re.IGNORECASE,
    )


    text = re.sub(
        r"\bevidence_indexes?\s*:\s*"
        r"\[[^\]]*\]",
        "",
        text,
        flags=re.IGNORECASE,
    )


    text = re.sub(
        r"\bevidence_indexes?\s*:\s*\d+",
        "",
        text,
        flags=re.IGNORECASE,
    )


    text = re.sub(
        r"\bevidence_index_?\d+\b",
        "",
        text,
        flags=re.IGNORECASE,
    )


    return text.strip(
        " ,{}"
    )


def dedupe_recommendations(
    values,
):

    result = []
    seen = set()

    for value in values:

        text = clean_recommendation(
            value
        )

        if not text:
            continue

        action = text.split(
            "Reason:",
            1,
        )[0]

        key = normalize_text(
            action
        )

        if not key:
            continue

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            text
        )

    return result


def classify_finding_theme(
    title,
):

    value = str(
        title or ""
    ).lower()


    if "service" in value:

        return (
            "Service / Execution Activity"
        )


    if (
        "rdp" in value
        or "remote logon" in value
        or "remote access" in value
    ):

        return (
            "Remote Access Activity"
        )


    if any(
        token in value
        for token in (
            "admin",
            "group",
            "password",
            "account",
            "ntlm",
        )
    ):

        return (
            "Identity / Privilege Activity"
        )


    if any(
        token in value
        for token in (
            "firewall",
            "wmi",
            "dc shadow",
        )
    ):

        return (
            "System / Configuration Activity"
        )


    return (
        "Other Investigation Activity"
    )


def build_theme_summary(
    findings,
):

    themes = {}

    for item in findings:

        theme = (
            classify_finding_theme(
                item.get(
                    "title"
                )
            )
        )

        entry = themes.setdefault(
            theme,
            {
                "theme":
                    theme,

                "finding_count":
                    0,

                "event_uids":
                    [],

                "representative_findings":
                    [],
            },
        )


        entry[
            "finding_count"
        ] += 1


        title = item.get(
            "title"
        )

        if (
            title
            and title not in
            entry[
                "representative_findings"
            ]
            and len(
                entry[
                    "representative_findings"
                ]
            ) < 3
        ):

            entry[
                "representative_findings"
            ].append(
                title
            )


        for uid in item.get(
            "event_uids",
            []
        ):

            if (
                uid
                and uid not in
                entry[
                    "event_uids"
                ]
            ):

                entry[
                    "event_uids"
                ].append(
                    uid
                )


    result = list(
        themes.values()
    )


    result.sort(
        key=lambda x: (
            x[
                "finding_count"
            ],
            len(
                x[
                    "event_uids"
                ]
            ),
        ),
        reverse=True,
    )


    return result


def load_grounded_timeline(
    case_dir,
    findings,
    limit=None,
):

    db = (
        case_dir
        / "evidence.db"
    )


    if not db.is_file():

        return []


    wanted = []

    for item in findings:

        for uid in item.get(
            "event_uids",
            []
        ):

            if (
                uid
                and uid not in wanted
            ):

                wanted.append(
                    uid
                )


    if not wanted:

        return []


    conn = sqlite3.connect(
        "file:"
        + str(db)
        + "?mode=ro",
        uri=True,
    )

    conn.row_factory = (
        sqlite3.Row
    )


    rows = {}


    try:

        for start in range(
            0,
            len(wanted),
            800,
        ):

            batch = wanted[
                start:start + 800
            ]

            placeholders = ",".join(
                "?"
                for _ in batch
            )

            sql = f"""
                SELECT
                    event_uid,
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
                    command_line,
                    path,
                    target_path,
                    windows_event_id,
                    provider,
                    detection_rule,
                    description
                FROM events
                WHERE event_uid IN (
                    {placeholders}
                )
            """


            for row in conn.execute(
                sql,
                batch,
            ):

                rows[
                    row[
                        "event_uid"
                    ]
                ] = dict(
                    row
                )

    finally:

        conn.close()


    timeline = []

    seen = set()


    for finding in findings:

        candidates = []


        for uid in finding.get(
            "event_uids",
            []
        ):

            row = rows.get(
                uid
            )

            if not row:
                continue


            if not row.get(
                "timestamp_sort"
            ):
                continue


            candidates.append(
                row
            )


        if not candidates:

            continue


        candidates.sort(
            key=lambda x: (
                x.get(
                    "timestamp_sort"
                )
                or "",
                0
                if (
                    x.get(
                        "source_tool"
                    )
                    == "evtxecmd"
                )
                else 1,
            )
        )


        row = candidates[
            0
        ]


        key = (
            row.get(
                "timestamp_sort"
            ),
            normalize_text(
                finding.get(
                    "title"
                )
            ),
        )


        if key in seen:

            continue


        seen.add(
            key
        )


        timeline.append({

            "timestamp":
                row.get(
                    "timestamp"
                )
                or row.get(
                    "timestamp_sort"
                ),

            "timestamp_sort":
                row.get(
                    "timestamp_sort"
                ),

            "timestamp_type":
                row.get(
                    "timestamp_type"
                ),

            "timestamp_source":
                row.get(
                    "timestamp_source"
                ),

            "theme":
                classify_finding_theme(
                    finding.get(
                        "title"
                    )
                ),

            "finding":
                finding.get(
                    "title"
                ),

            "assessment":
                finding.get(
                    "assessment"
                ),

            "priority":
                finding.get(
                    "priority"
                ),

            "hostname":
                row.get(
                    "hostname"
                ),

            "windows_event_id":
                row.get(
                    "windows_event_id"
                ),

            "provider":
                row.get(
                    "provider"
                ),

            "event_uid":
                row.get(
                    "event_uid"
                ),

            "source_tool":
                row.get(
                    "source_tool"
                ),
        })


    timeline.sort(
        key=lambda x:
            x.get(
                "timestamp_sort"
            )
            or ""
    )


    if limit is None:
        return timeline

    return timeline[
        :limit
    ]


def build_related_activity(
    timeline,
):

    from datetime import datetime

    parsed = []

    for item in timeline:

        value = item.get(
            "timestamp_sort"
        )

        if not value:
            continue

        try:
            dt = datetime.fromisoformat(
                value
            )
        except Exception:
            continue

        parsed.append(
            (
                dt,
                item,
            )
        )

    parsed.sort(
        key=lambda x: x[0]
    )

    if len(parsed) < 2:
        return []


    windows = []
    current = [
        parsed[0]
    ]


    # Group grounded findings occurring within
    # 15 minutes of the preceding finding.
    for entry in parsed[1:]:

        previous_time = (
            current[-1][0]
        )

        current_time = (
            entry[0]
        )

        delta = (
            current_time
            - previous_time
        ).total_seconds()


        if (
            delta >= 0
            and delta <= 900
        ):

            current.append(
                entry
            )

        else:

            if len(current) >= 2:
                windows.append(
                    current
                )

            current = [
                entry
            ]


    if len(current) >= 2:

        windows.append(
            current
        )


    result = []


    for window in windows:

        themes = []

        titles = []

        event_uids = []

        hosts = []


        for _, item in window:

            theme = item.get(
                "theme"
            )

            if (
                theme
                and theme not in themes
            ):
                themes.append(
                    theme
                )


            title = item.get(
                "finding"
            )

            if (
                title
                and title not in titles
            ):
                titles.append(
                    title
                )


            uid = item.get(
                "event_uid"
            )

            if (
                uid
                and uid not in event_uids
            ):
                event_uids.append(
                    uid
                )


            host = item.get(
                "hostname"
            )

            if (
                host
                and host not in hosts
            ):
                hosts.append(
                    host
                )


        if len(titles) < 2:
            continue


        start_time = (
            window[0][1].get(
                "timestamp"
            )
        )

        end_time = (
            window[-1][1].get(
                "timestamp"
            )
        )


        result.append({

            "start_time":
                start_time,

            "end_time":
                end_time,

            "finding_count":
                len(window),

            "themes":
                themes,

            "hosts":
                hosts,

            "findings":
                titles[:6],

            "event_uids":
                event_uids,

            "note":
                (
                    "These grounded findings occurred within "
                    "the same temporal activity window. "
                    "Temporal proximity does not establish "
                    "causation or a common actor."
                ),
        })


    return result[:12]


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

INPUT_FILE = (
    CASE_DIR
    / "investigation"
    / "case_synthesis_v1"
    / "case_synthesis_input.json"
)

OUTPUT_FILE = (
    CASE_DIR
    / "investigation"
    / "case_synthesis_v1"
    / "case_synthesis_deterministic.json"
)


if not INPUT_FILE.is_file():
    raise RuntimeError(
        f"Missing input: {INPUT_FILE}"
    )


source = read_json(
    INPUT_FILE
)

findings = source.get(
    "findings",
    []
)


if not findings:
    findings = []


assessment_counts = Counter()
priority_counts = Counter()

all_event_uids = set()

key_findings = []
observed_facts = []

evidence_gaps = []
recommended_steps = []

deep_count = 0
fast_count = 0


for item in findings:

    finding_id = item.get(
        "finding_id"
    )

    title = item.get(
        "title"
    )

    event_uids = list(
        dict.fromkeys(
            item.get(
                "event_uids",
                []
            )
        )
    )

    all_event_uids.update(
        event_uids
    )

    ai_source = item.get(
        "ai_assessment_source"
    )

    ai = (
        item.get(
            "ai_assessment"
        )
        or {}
    )

    assessment = (
        ai.get(
            "assessment"
        )
        or "INSUFFICIENT_EVIDENCE"
    )

    priority = (
        ai.get(
            "priority"
        )
        or item.get(
            "severity"
        )
        or "MEDIUM"
    )

    confidence = (
        ai.get(
            "confidence"
        )
        or item.get(
            "confidence"
        )
        or "LOW"
    )


    assessment_counts[
        assessment
    ] += 1

    priority_counts[
        priority
    ] += 1


    if ai_source == "QWEN3_8B_DEEP":

        deep_count += 1

        for fact in ai.get(
            "observed_facts",
            []
        ):

            fact_uids = fact.get(
                "event_uids",
                []
            )

            if not fact_uids:
                continue

            observed_facts.append({
                "fact":
                    fact.get(
                        "fact",
                        ""
                    ),

                "event_uids":
                    fact_uids,

                "source":
                    "QWEN3_8B_DEEP",
            })


        evidence_gaps.extend(
            ai.get(
                "evidence_gaps",
                []
            )
        )

        recommended_steps.extend(
            ai.get(
                "recommended_next_steps",
                []
            )
        )


    elif ai_source == "QWEN3_4B_FAST":
        fast_count += 1



    # -------------------------------------------------------------
    # Deterministic finding facts
    #
    # These summaries originate from current-case deterministic
    # findings, not from historical RAG and not from an LLM.
    # Preserve them as grounded observed facts when event_uids exist.
    # -------------------------------------------------------------

    finding_type = (
        item.get("finding_type")
        or ""
    )

    deterministic_summary = str(
        item.get("summary")
        or ""
    ).strip()

    if (
        event_uids
        and deterministic_summary
        and finding_type in {
            "POWERSHELL_HISTORY_LEAD",
            "CORE_CROSS_ARTIFACT_LEAD",
            "CROSS_ARTIFACT_ACTIVITY_LEAD",
        }
    ):
        observed_facts.append({
            "fact":
                deterministic_summary,

            "event_uids":
                event_uids,

            "source":
                "DETERMINISTIC_FINDING_SUMMARY",
        })


    key_findings.append({

        "finding_id":
            finding_id,

        "title":
            title,

        "finding_type":
            item.get(
                "finding_type"
            ),

        "severity":
            item.get(
                "severity"
            ),

        "assessment":
            assessment,

        "priority":
            priority,

        "confidence":
            confidence,

        "ai_source":
            ai_source,

        "event_uids":
            event_uids,

        "historical_reference_count":
            len(
                item.get(
                    "historical_references",
                    []
                )
            ),
    })


key_findings.sort(
    key=lambda x: (
        ASSESSMENT_RANK.get(
            x["assessment"],
            0,
        ),
        PRIORITY_RANK.get(
            x["priority"],
            0,
        ),
        len(
            x["event_uids"]
        ),
    ),
    reverse=True,
)


# Generic empty-investigation handling.
#
# A valid evidence set may produce zero investigation findings.
# That is not a pipeline failure and must not be interpreted as benign.
# Preserve the absence of actionable findings as insufficient evidence.
#
if not assessment_counts:
    assessment_counts["INSUFFICIENT_EVIDENCE"] = 1

if not priority_counts:
    priority_counts["LOW"] = 1


overall_assessment = max(
    assessment_counts,
    key=lambda value:
        ASSESSMENT_RANK.get(
            value,
            0,
        ),
)


overall_priority = max(
    priority_counts,
    key=lambda value:
        PRIORITY_RANK.get(
            value,
            0,
        ),
)


if deep_count > 0:
    overall_confidence = "HIGH"
else:
    overall_confidence = "MEDIUM"


observed_facts = dedupe_fact_records(
    observed_facts
)

evidence_gaps = dedupe_strings(
    evidence_gaps
)[:12]

recommended_steps = dedupe_recommendations(
    recommended_steps
)[:12]

priority_evidence_themes = build_theme_summary(
    key_findings
)

evidence_timeline = load_grounded_timeline(
    CASE_DIR,
    key_findings,
    limit=None,
)

possible_related_activity = build_related_activity(
    evidence_timeline
)


if not evidence_gaps:

    evidence_gaps = [
        "Case-level relationships between findings require analyst validation against the underlying forensic evidence."
    ]


if not recommended_steps:

    recommended_steps = [
        "Review the highest-priority findings and their referenced event_uid evidence.",
        "Validate administrative or benign explanations for account, service, RDP, and WMI activity.",
        "Acquire additional endpoint, authentication, network, and timeline evidence where available."
    ]


payload = {

    "version":
        "1.0",

    "case_id":
        CASE,

    "synthesis_mode":
        "DETERMINISTIC_FROM_EXISTING_AI_ASSESSMENTS",

    "additional_qwen_calls":
        0,

    "overall_assessment":
        overall_assessment,

    "priority":
        overall_priority,

    "confidence":
        overall_confidence,

    "executive_summary":
        (
            f"Analysis of the available current-case forensic evidence "
            f"identified {len(findings)} investigation findings grounded "
            f"in {len(all_event_uids)} unique event_uids. "
            f"The evidence includes investigation activity associated with "
            f"{', '.join(theme['theme'] for theme in priority_evidence_themes[:4])}. "
            f"The highest existing analytical assessment is "
            f"{overall_assessment}, with investigation priority "
            f"{overall_priority}. "
            f"The observed events and AI-assisted assessments require "
            f"analyst validation against the referenced current-case "
            f"evidence before any final incident determination."
        ),

    "assessment_counts":
        dict(
            assessment_counts
        ),

    "priority_counts":
        dict(
            priority_counts
        ),

    "observed_case_facts":
        observed_facts,

    "priority_evidence_themes":
        priority_evidence_themes,

    "evidence_timeline":
        evidence_timeline,

    "key_findings":
        key_findings,

    "possible_related_activity":
        possible_related_activity,

    "possible_related_activity_note":
        (
            "No sufficiently grounded current-case temporal relationship "
            "sequence could be constructed automatically. Relationships "
            "between findings require analyst validation using "
            "current-case evidence and event_uid grounding."
        ),

    "alternative_explanations": [
        "Legitimate or administrative activity may explain some observed current-case events. Any such explanation must be validated against the available artifact families and referenced event_uid evidence.",
        "Legitimate Windows execution may explain some cross-artifact executable correlations.",
        "Detection-rule severity alone does not establish malicious activity."
    ],

    "evidence_gaps":
        evidence_gaps,

    "recommended_next_steps":
        recommended_steps,

    "case_fact_policy": {
        "event_uid_grounding_required":
            True,

        "historical_reference_is_case_fact":
            False,

        "historical_similarity_is_evidence":
            False,

        "hayabusa_evtx_independent":
            False,

        "ai_assessment_is_final_analyst_determination":
            False,
    },

    "analyst_conclusion":
        (
            f"The available current-case evidence contains "
            f"{assessment_counts.get('SUSPICIOUS', 0)} findings assessed "
            f"as SUSPICIOUS and "
            f"{assessment_counts.get('NEEDS_REVIEW', 0)} findings requiring "
            f"additional review. Grounded investigation findings span "
            f"the evidence themes summarized in this report. "
            f"Any temporal relationship shown is an investigative "
            f"hypothesis rather than proof of causation. Existing AI "
            f"assessments remain investigative aids and must be validated "
            f"against the referenced event_uid evidence before final "
            f"forensic determination."
        ),

    "requires_analyst_review":
        True,
}


atomic_write_json(
    OUTPUT_FILE,
    payload,
)


print("=" * 72)
print("DETERMINISTIC CASE SYNTHESIS V1")
print("=" * 72)

print()
print(
    f"Case:              {CASE}"
)

print(
    f"Findings:          {len(findings):,}"
)

print(
    f"Unique event_uids: {len(all_event_uids):,}"
)

print(
    f"Deep 8B inputs:    {deep_count:,}"
)

print(
    f"Fast 4B inputs:    {fast_count:,}"
)

print()
print(
    f"Assessment:        {overall_assessment}"
)

print(
    f"Priority:          {overall_priority}"
)

print(
    f"Confidence:        {overall_confidence}"
)

print()
print("ASSESSMENT COUNTS")

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


print()
print(
    f"Observed grounded facts: "
    f"{len(observed_facts):,}"
)

print(
    f"Evidence gaps:          "
    f"{len(evidence_gaps):,}"
)

print(
    f"Recommended steps:      "
    f"{len(recommended_steps):,}"
)

print()
print("Additional Qwen calls: 0")
print("Databases modified:    0")

print()
print(
    f"Output: {OUTPUT_FILE}"
)

print()
print("=" * 72)
print("DETERMINISTIC CASE SYNTHESIS V1: COMPLETE")
print("=" * 72)
