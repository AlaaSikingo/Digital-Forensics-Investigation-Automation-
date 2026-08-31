import argparse
import json
from pathlib import Path
from datetime import datetime, timezone


WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")


def read_json(path):

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        return json.load(handle)


def write_text(
    path,
    text,
):

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp.write_text(
        text,
        encoding="utf-8",
    )

    temp.replace(path)


def now_utc():

    return datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def md_escape(value):

    if value is None:
        return ""

    return str(value).replace(
        "|",
        "\\|",
    )


def report_normalize(value):

    return " ".join(
        str(value or "")
        .strip()
        .lower()
        .split()
    )


def group_evidence_gaps_for_report(
    values,
):

    buckets = {
        "Service origin and configuration context": [],
        "Network and file-system corroboration": [],
        "User and process attribution": [],
        "Account and privilege-change context": [],
        "Additional logs and supporting artifacts": [],
        "Timing and follow-on activity": [],
        "Other evidence gaps": [],
    }


    for value in values:

        text = str(
            value or ""
        ).strip()

        if not text:
            continue

        low = report_normalize(
            text
        )


        if (
            "service" in low
            and any(
                token in low
                for token in (
                    "origin",
                    "purpose",
                    "configuration",
                )
            )
        ):

            bucket = (
                "Service origin and configuration context"
            )


        elif (
            "network" in low
            or "file system" in low
            or "filesystem" in low
        ):

            bucket = (
                "Network and file-system corroboration"
            )


        elif (
            "user or process" in low
            or "process context" in low
            or "source of the user" in low
        ):

            bucket = (
                "User and process attribution"
            )


        elif (
            "add the user" in low
            or "group membership" in low
            or "account" in low
        ):

            bucket = (
                "Account and privilege-change context"
            )


        elif (
            "timestamp" in low
            or "subsequent actions" in low
            or "follow" in low
        ):

            bucket = (
                "Timing and follow-on activity"
            )


        elif (
            "additional logs" in low
            or "artifacts" in low
            or "additional evidence" in low
        ):

            bucket = (
                "Additional logs and supporting artifacts"
            )


        else:

            bucket = (
                "Other evidence gaps"
            )


        if text not in buckets[
            bucket
        ]:

            buckets[
                bucket
            ].append(
                text
            )


    result = []

    for title, items in buckets.items():

        if not items:
            continue

        result.append({
            "title":
                title,

            "details":
                items,
        })


    return result


def group_recommendations_for_report(
    values,
):

    buckets = {
        "Validate suspicious services and service configuration": [],
        "Review service execution and command-line context": [],
        "Review related Windows event activity": [],
        "Validate account and privilege activity": [],
        "Review authentication and user activity": [],
        "Other investigation actions": [],
    }


    for value in values:

        text = str(
            value or ""
        ).strip()

        if not text:
            continue

        low = report_normalize(
            text
        )


        if (
            "service" in low
            and any(
                token in low
                for token in (
                    "configuration",
                    "behavior",
                    "modification",
                )
            )
        ):

            bucket = (
                "Validate suspicious services and service configuration"
            )


        elif (
            "command-line" in low
            or "command line" in low
            or (
                "service" in low
                and "installation" in low
            )
        ):

            bucket = (
                "Review service execution and command-line context"
            )


        elif (
            "event log" in low
            or "related events" in low
            or "other suspicious service" in low
        ):

            bucket = (
                "Review related Windows event activity"
            )


        elif (
            "domain admins" in low
            or "add the user" in low
            or "group" in low
            or "privilege" in low
        ):

            bucket = (
                "Validate account and privilege activity"
            )


        elif (
            "administrator" in low
            or "user access" in low
            or "user account" in low
            or "logon" in low
        ):

            bucket = (
                "Review authentication and user activity"
            )


        else:

            bucket = (
                "Other investigation actions"
            )


        if text not in buckets[
            bucket
        ]:

            buckets[
                bucket
            ].append(
                text
            )


    result = []

    for title, items in buckets.items():

        if not items:
            continue

        result.append({
            "title":
                title,

            "details":
                items,
        })


    return result



parser = argparse.ArgumentParser()

parser.add_argument(
    "--case",
    required=True,
)

args = parser.parse_args()

CASE = args.case.strip()

if not CASE:

    raise RuntimeError(
        "Case ID cannot be empty."
    )


CASE_DIR = (
    WORKSPACE_ROOT
    / CASE
)

SYNTHESIS_FILE = (
    CASE_DIR
    / "investigation"
    / "case_synthesis_v1"
    / "case_synthesis_deterministic.json"
)

REPORT_DIR = (
    CASE_DIR
    / "report"
)

REPORT_FILE = (
    REPORT_DIR
    / f"{CASE}_DFIR_Report.md"
)


if not SYNTHESIS_FILE.is_file():

    raise RuntimeError(
        f"Missing synthesis file: "
        f"{SYNTHESIS_FILE}"
    )


data = read_json(
    SYNTHESIS_FILE
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


lines = []


def add(text=""):

    lines.append(text)


add(
    f"# Digital Forensics & Incident Response Report"
)

add()

add(
    f"**Case ID:** {CASE}"
)

add(
    f"**Generated:** {now_utc()}"
)

add(
    "**Report Status:** Analytical Draft — Analyst Validation Required"
)

add()

add("---")

add()

add("# 1. Executive Summary")

add()

add(
    data.get(
        "executive_summary",
        ""
    )
)

add()

add(
    f"**Overall Assessment:** "
    f"{data.get('overall_assessment')}"
)

add(
    f"**Investigation Priority:** "
    f"{data.get('priority')}"
)

add(
    f"**Analytical Confidence:** "
    f"{data.get('confidence')}"
)

add()

add(
    "This report is based on current-case forensic evidence, "
    "normalized event data, correlation results, finding-level AI "
    "assessments, and historical RAG references. Historical references "
    "are contextual only and are not treated as current-case evidence."
)

add()

add("# 2. Investigation Scope")

add()

add(
    f"- Total investigation findings: "
    f"{len(data.get('key_findings', []))}"
)

event_uids = set()

for item in data.get(
    "key_findings",
    []
):

    event_uids.update(
        item.get(
            "event_uids",
            []
        )
    )


add(
    f"- Unique grounded event_uids: "
    f"{len(event_uids)}"
)

add(
    f"- Deep Qwen3:8B finding assessments: "
    f"{data.get('assessment_counts', {}).get('SUSPICIOUS', 0)} "
    f"suspicious findings included in synthesis"
)

add(
    "- Fast Qwen3:4B triage assessments were used for "
    "remaining non-deep findings."
)

add()

add("# 3. Assessment Distribution")

add()

add(
    "| Assessment | Count |"
)

add(
    "|---|---:|"
)

for key in (
    "HIGH_PRIORITY_REVIEW",
    "SUSPICIOUS",
    "NEEDS_REVIEW",
    "INSUFFICIENT_EVIDENCE",
    "LIKELY_BENIGN",
):

    count = (
        data.get(
            "assessment_counts",
            {}
        ).get(
            key,
            0,
        )
    )

    add(
        f"| {key} | {count} |"
    )


add()

add("## 3.1 Priority Evidence Themes")

add()

themes = data.get(
    "priority_evidence_themes",
    []
)

if themes:

    add(
        "| Theme | Findings | Grounded event_uids | Representative Findings |"
    )

    add(
        "|---|---:|---:|---|"
    )

    for item in themes:

        representatives = "; ".join(
            item.get(
                "representative_findings",
                []
            )
        )

        add(
            "| "
            + md_escape(
                item.get(
                    "theme"
                )
            )
            + " | "
            + str(
                item.get(
                    "finding_count",
                    0
                )
            )
            + " | "
            + str(
                len(
                    item.get(
                        "event_uids",
                        []
                    )
                )
            )
            + " | "
            + md_escape(
                representatives
            )
            + " |"
        )

else:

    add(
        "No priority evidence themes were automatically constructed."
    )


add()

add("## 3.2 E01-Grounded Evidence Timeline")

add()

add(
    "The timeline below is derived only from timestamps associated "
    "with grounded event_uids represented by the investigation findings. "
    "Chronological ordering alone does not establish causation."
)

add()

timeline = data.get(
    "evidence_timeline",
    []
)

if timeline:

    add(
        "| Evidence Time | Theme | Finding | Host | Event ID | event_uid |"
    )

    add(
        "|---|---|---|---|---|---|"
    )

    for item in timeline:

        add(
            "| "
            + md_escape(
                item.get(
                    "timestamp"
                )
            )
            + " | "
            + md_escape(
                item.get(
                    "theme"
                )
            )
            + " | "
            + md_escape(
                item.get(
                    "finding"
                )
            )
            + " | "
            + md_escape(
                item.get(
                    "hostname"
                )
            )
            + " | "
            + md_escape(
                item.get(
                    "windows_event_id"
                )
            )
            + " | `"
            + str(
                item.get(
                    "event_uid",
                    ""
                )
            )
            + "` |"
        )

else:

    add(
        "No grounded finding timestamps were available for automatic timeline construction."
    )


add()

add("# 4. Observed Case Facts")

add()

facts = data.get(
    "observed_case_facts",
    []
)

if facts:

    for number, fact in enumerate(
        facts,
        start=1,
    ):

        add(
            f"## 4.{number}"
        )

        add()

        add(
            fact.get(
                "fact",
                ""
            )
        )

        add()

        add(
            "**Supporting event_uids:**"
        )

        for uid in fact.get(
            "event_uids",
            []
        ):

            add(
                f"- `{uid}`"
            )

        add()

else:

    add(
        "No case-level observed facts were automatically created."
    )

    add()


add("# 5. Key Investigation Findings")

add()

add(
    "| # | Severity | Assessment | Priority | Confidence | Finding | AI Source |"
)

add(
    "|---:|---|---|---|---|---|---|"
)


for number, item in enumerate(
    data.get(
        "key_findings",
        []
    ),
    start=1,
):

    add(
        "| "
        + str(number)
        + " | "
        + md_escape(
            item.get(
                "severity"
            )
        )
        + " | "
        + md_escape(
            item.get(
                "assessment"
            )
        )
        + " | "
        + md_escape(
            item.get(
                "priority"
            )
        )
        + " | "
        + md_escape(
            item.get(
                "confidence"
            )
        )
        + " | "
        + md_escape(
            item.get(
                "title"
            )
        )
        + " | "
        + md_escape(
            item.get(
                "ai_source"
            )
        )
        + " |"
    )


add()

add("# 6. Finding Evidence References")

add()


for number, item in enumerate(
    data.get(
        "key_findings",
        []
    ),
    start=1,
):

    add(
        f"## 6.{number} "
        f"{item.get('title', '')}"
    )

    add()

    add(
        f"**Finding ID:** "
        f"`{item.get('finding_id', '')}`"
    )

    add()

    add(
        f"**Assessment:** "
        f"{item.get('assessment', '')}"
    )

    add(
        f"**Priority:** "
        f"{item.get('priority', '')}"
    )

    add(
        f"**Confidence:** "
        f"{item.get('confidence', '')}"
    )

    add()

    add(
        "**Supporting event_uids:**"
    )

    uids = item.get(
        "event_uids",
        []
    )

    if uids:

        for uid in uids:

            add(
                f"- `{uid}`"
            )

    else:

        add(
            "- None recorded"
        )

    add()


add("# 7. Possible Related Activity - E01 Evidence Only")

add()

related = data.get(
    "possible_related_activity",
    []
)

if related:

    add(
        "The following groups represent grounded findings that occurred "
        "within the same temporal activity window. Temporal proximity "
        "does not establish causation or a common actor."
    )

    add()

    add(
        "| Time Window | Findings | Themes | Host(s) |"
    )

    add(
        "|---|---:|---|---|"
    )

    for item in related:

        window = (
            f"{item.get('start_time', '')} "
            f"to "
            f"{item.get('end_time', '')}"
        )

        themes = "; ".join(
            item.get(
                "themes",
                []
            )
        )

        hosts = "; ".join(
            item.get(
                "hosts",
                []
            )
        )

        add(
            "| "
            + md_escape(window)
            + " | "
            + str(
                item.get(
                    "finding_count",
                    0
                )
            )
            + " | "
            + md_escape(themes)
            + " | "
            + md_escape(hosts)
            + " |"
        )

        add()

        findings = item.get(
            "findings",
            []
        )

        if findings:

            add(
                "**Findings represented in this window:**"
            )

            for finding in findings:

                add(
                    f"- {finding}"
                )

            add()

else:

    add(
        data.get(
            "possible_related_activity_note",
            "No automatic temporal activity windows were created."
        )
    )

add()


add("# 8. Alternative Explanations")

add()

for item in data.get(
    "alternative_explanations",
    []
):

    add(
        f"- {item}"
    )

add()


add("# 9. Evidence Gaps")

add()

gap_groups = group_evidence_gaps_for_report(
    data.get(
        "evidence_gaps",
        []
    )
)

if gap_groups:

    add(
        "The following evidence gaps consolidate related gaps "
        "identified across the finding-level assessments. "
        "The underlying AI-generated gaps remain unchanged "
        "in the synthesis data."
    )

    add()

    for number, group in enumerate(
        gap_groups,
        start=1,
    ):

        add(
            f"## 9.{number} "
            + group[
                "title"
            ]
        )

        add()

        for detail in group.get(
            "details",
            []
        ):

            add(
                f"- {detail}"
            )

        add()

else:

    add(
        "No evidence gaps were identified."
    )

add()


add("# 10. Recommended Next Investigation Steps")

add()

step_groups = group_recommendations_for_report(
    data.get(
        "recommended_next_steps",
        []
    )
)

if step_groups:

    add(
        "Recommended actions are grouped below to reduce repetition "
        "while preserving the original finding-level investigation "
        "recommendations."
    )

    add()

    for number, group in enumerate(
        step_groups,
        start=1,
    ):

        add(
            f"## 10.{number} "
            + group[
                "title"
            ]
        )

        add()

        for detail in group.get(
            "details",
            []
        ):

            add(
                f"- {detail}"
            )

        add()

else:

    add(
        "No additional investigation steps were identified."
    )

add()


add("# 11. Analytical Conclusion")

add()

add(
    data.get(
        "analyst_conclusion",
        ""
    )
)

add()


add("# 12. Evidence and Analytical Safeguards")

add()

policy = data.get(
    "case_fact_policy",
    {}
)

add(
    f"- event_uid grounding required: "
    f"{policy.get('event_uid_grounding_required')}"
)

add(
    f"- Historical references treated as case facts: "
    f"{policy.get('historical_reference_is_case_fact')}"
)

add(
    f"- Historical similarity treated as evidence: "
    f"{policy.get('historical_similarity_is_evidence')}"
)

add(
    f"- Hayabusa and EvtxECmd counted as independent evidence: "
    f"{policy.get('hayabusa_evtx_independent')}"
)

add(
    f"- AI assessment treated as final analyst determination: "
    f"{policy.get('ai_assessment_is_final_analyst_determination')}"
)

add()


add("# 13. Analyst Review Requirement")

add()

add(
    "This report is an AI-assisted forensic investigation draft. "
    "All conclusions, classifications, timelines, and recommended actions "
    "must be validated by a qualified DFIR analyst against the referenced "
    "current-case evidence before being treated as final."
)

add()


write_text(
    REPORT_FILE,
    "\n".join(lines),
)


print("=" * 72)
print("FINAL DFIR REPORT GENERATOR V1")
print("=" * 72)

print()
print(
    f"Case:       {CASE}"
)

print(
    f"Assessment: {data.get('overall_assessment')}"
)

print(
    f"Priority:   {data.get('priority')}"
)

print(
    f"Confidence: {data.get('confidence')}"
)

print(
    f"Findings:   "
    f"{len(data.get('key_findings', []))}"
)

print(
    f"Event UIDs: "
    f"{len(event_uids)}"
)

print()
print(
    f"Report: "
    f"{REPORT_FILE}"
)

print()
print("Qwen calls: 0")
print("Databases modified: 0")

print()
print("=" * 72)
print("FINAL DFIR REPORT GENERATOR V1: COMPLETE")
print("=" * 72)
