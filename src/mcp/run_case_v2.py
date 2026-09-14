import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


WORKSPACE_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace"))
MCP_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src" / "mcp"))
RAG_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "rag"))

PYTHON = (
    MCP_ROOT
    / ".venv"
    / "Scripts"
    / "python.exe"
)

RAG_PYTHON = (
    RAG_ROOT
    / ".venv"
    / "Scripts"
    / "python.exe"
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def atomic_json(path, payload):

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    temp.replace(path)


def run_stage(
    name,
    script,
    arguments,
    cwd,
    marker,
    dry_run,
):

    if marker.is_file():

        print(
            f"{name:<30} SKIP "
            "(completion marker)"
        )

        return


    command = [
        str(PYTHON),
        "-u",
        str(script),
        *[
            str(value)
            for value in arguments
        ],
    ]


    print(
        f"{name:<30} RUN"
    )

    if dry_run:

        print(
            "  "
            + " ".join(command)
        )

        return


    result = subprocess.run(
        command,
        cwd=str(cwd),
        check=False,
    )


    if result.returncode != 0:

        raise RuntimeError(
            f"{name} failed with "
            f"exit code "
            f"{result.returncode}"
        )


    atomic_json(
        marker,
        {
            "stage":
                name,

            "completed_utc":
                utc_now(),

            "script":
                script.name,

            "case_id":
                CASE,
        },
    )


def run_rag(
    marker,
    dry_run,
):

    if marker.is_file():

        print(
            f"{'RAG enrichment':<30} "
            "SKIP (completion marker)"
        )

        return


    command = [
        str(RAG_PYTHON),
        "-u",
        str(
            RAG_ROOT
            / "rag_enrich_v1.py"
        ),
        "--case-dir",
        str(CASE_DIR),
        "--important",
    ]


    print(
        f"{'RAG enrichment':<30} RUN"
    )

    if dry_run:

        print(
            "  "
            + " ".join(command)
        )

        return


    result = subprocess.run(
        command,
        cwd=str(RAG_ROOT),
        check=False,
    )

    if result.returncode != 0:

        raise RuntimeError(
            "RAG enrichment failed."
        )


    atomic_json(
        marker,
        {
            "stage":
                "RAG enrichment",

            "completed_utc":
                utc_now(),

            "case_id":
                CASE,
        },
    )


def valid_sqlite(path):

    if not path.is_file():
        return False

    try:

        uri = (
            "file:"
            + path.resolve().as_posix()
            + "?mode=ro"
        )

        conn = sqlite3.connect(
            uri,
            uri=True,
            timeout=5,
        )

        conn.execute(
            "SELECT 1"
        ).fetchone()

        conn.close()

        return True

    except Exception:

        return False


def bootstrap_existing_case():

    # --------------------------------------------------------
    # Important:
    # Existing completed CASE-001 must NEVER be reprocessed
    # simply because stage markers did not previously exist.
    # --------------------------------------------------------

    final_outputs = all([
        valid_sqlite(EVIDENCE_DB),
        valid_sqlite(CORRELATION_DB),
        valid_sqlite(FINDINGS_DB),
        CONTEXT_INDEX.is_file(),
        TRIAGE_DB.is_file(),
        SYNTHESIS_DETERMINISTIC.is_file(),
        FINAL_REPORT.is_file(),
    ])


    if not final_outputs:
        return False


    bootstrap = {
        "finish_normalization":
            EVIDENCE_DB.is_file(),

        "correlation":
            CORRELATION_DB.is_file(),

        "build_clusters":
            CORRELATION_DB.is_file(),

        "build_candidate_clusters":
            CORRELATION_DB.is_file(),

        "findings":
            FINDINGS_DB.is_file(),

        "investigation_context":
            CONTEXT_INDEX.is_file(),

        "fast_triage":
            TRIAGE_DB.is_file(),

        "qwen4_fast":
            any(
                QWEN4_DIR.glob("*.json")
            )
            if QWEN4_DIR.is_dir()
            else False,

        "rag":
            any(
                RAG_DIR.glob("*.json")
            )
            if RAG_DIR.is_dir()
            else False,

        "prepare_synthesis":
            SYNTHESIS_INPUT.is_file(),

        "deterministic_synthesis":
            SYNTHESIS_DETERMINISTIC.is_file(),

        "final_report":
            FINAL_REPORT.is_file(),
    }


    created = 0

    for stage, complete in bootstrap.items():

        marker = (
            STATE_DIR
            / f"{stage}.json"
        )

        if (
            complete
            and not marker.is_file()
        ):

            atomic_json(
                marker,
                {
                    "stage":
                        stage,

                    "case_id":
                        CASE,

                    "completed_utc":
                        utc_now(),

                    "bootstrap":
                        True,

                    "reason":
                        "Existing validated output",
                },
            )

            created += 1


    if created:

        print()
        print(
            f"Bootstrapped {created} "
            "completion markers from "
            "existing validated outputs."
        )


    return True


parser = argparse.ArgumentParser(
    description=(
        "DFIR-AI reusable case "
        "orchestrator v2"
    )
)

parser.add_argument(
    "--case",
    required=True,
)

parser.add_argument(
    "--dry-run",
    action="store_true",
)

parser.add_argument(
    "--skip-ai",
    action="store_true",
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
).resolve()


try:

    CASE_DIR.relative_to(
        WORKSPACE_ROOT.resolve()
    )

except ValueError:

    raise RuntimeError(
        "Case path escapes workspace."
    )


if not CASE_DIR.is_dir():

    raise RuntimeError(
        f"Case directory missing: "
        f"{CASE_DIR}"
    )


STATE_DIR = (
    CASE_DIR
    / ".pipeline_state"
)

STATE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


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

CONTEXT_INDEX = (
    CASE_DIR
    / "investigation"
    / "contexts_v1"
    / "index.json"
)

TRIAGE_DB = (
    CASE_DIR
    / "triage.db"
)

QWEN4_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen4b_fast_v1"
)

QWEN8_DIR = (
    CASE_DIR
    / "investigation"
    / "qwen_v1"
)

RAG_DIR = (
    CASE_DIR
    / "investigation"
    / "rag_v1"
    / "results"
)

SYNTHESIS_INPUT = (
    CASE_DIR
    / "investigation"
    / "case_synthesis_v1"
    / "case_synthesis_input.json"
)

SYNTHESIS_DETERMINISTIC = (
    CASE_DIR
    / "investigation"
    / "case_synthesis_v1"
    / "case_synthesis_deterministic.json"
)

FINAL_REPORT = (
    CASE_DIR
    / "report"
    / f"{CASE}_DFIR_Report_V2.md"
)


print("=" * 72)
print("DFIR-AI CASE ORCHESTRATOR V2")
print("=" * 72)

print()
print(f"Case:    {CASE}")
print(f"Dry run: {args.dry_run}")
print(f"Skip AI: {args.skip_ai}")


# ============================================================
# BOOTSTRAP EXISTING COMPLETED CASE
# ============================================================

bootstrap_existing_case()


# ============================================================
# REQUIRED STARTING POINT
# ============================================================

if not EVIDENCE_DB.is_file():

    raise RuntimeError(
        "evidence.db does not exist. "
        "Collection/parsing/base normalization "
        "must complete before this v2 pipeline."
    )


# ============================================================
# STAGE 1 - FINAL NORMALIZATION
# ============================================================

run_stage(
    "Finish normalization",
    MCP_ROOT
    / "finish_normalization.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "finish_normalization.json",
    args.dry_run,
)


# ============================================================
# EARLY DETERMINISTIC FORENSIC TELEMETRY
# ============================================================

run_stage(
    "System telemetry",
    MCP_ROOT
    / "system_telemetry_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "system_telemetry.json",
    args.dry_run,
)

run_stage(
    "SAM telemetry",
    MCP_ROOT
    / "sam_telemetry_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "sam_telemetry.json",
    args.dry_run,
)


# ============================================================
# STAGE 2 - CORRELATION
# ============================================================

run_stage(
    "Correlation",
    MCP_ROOT
    / "correlation.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "correlation.json",
    args.dry_run,
)


# ============================================================
# STAGE 3 - CORE CLUSTERS
# ============================================================

run_stage(
    "Core clusters",
    MCP_ROOT
    / "build_clusters.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "build_clusters.json",
    args.dry_run,
)


# ============================================================
# STAGE 4 - CANDIDATE CLUSTERS
# ============================================================

run_stage(
    "Candidate clusters",
    MCP_ROOT
    / "build_candidate_clusters.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "build_candidate_clusters.json",
    args.dry_run,
)


# ============================================================
# STAGE 5 - FINDINGS
# ============================================================

run_stage(
    "Findings",
    MCP_ROOT
    / "findings_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "findings.json",
    args.dry_run,
)


# ============================================================
# STAGE 6 - INVESTIGATION CONTEXT
# ============================================================

run_stage(
    "Investigation contexts",
    MCP_ROOT
    / "investigation_context.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "investigation_context.json",
    args.dry_run,
)


# ============================================================
# STAGE 7 - FAST TRIAGE
# ============================================================

run_stage(
    "Fast triage",
    MCP_ROOT
    / "fast_triage_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "fast_triage.json",
    args.dry_run,
)


# ============================================================
# STAGE 8 - QWEN 4B FAST TRIAGE
# ============================================================

if args.skip_ai:

    print(
        f"{'Qwen4 fast':<30} "
        "SKIP (--skip-ai)"
    )

else:

    run_stage(
        "Qwen4 fast",
        MCP_ROOT
        / "qwen4b_fast_v1.py",
        [
            "--case",
            CASE,
        ],
        MCP_ROOT,
        STATE_DIR
        / "qwen4_fast.json",
        args.dry_run,
    )


# ============================================================
# STAGE 9 - RAG ENRICHMENT
# ============================================================

run_rag(
    STATE_DIR
    / "rag.json",
    args.dry_run,
)


# ============================================================
# STAGE 10 - RAG-AWARE DEEP PREPARATION
# ============================================================

run_stage(
    "Prepare deep analysis",
    MCP_ROOT
    / "prepare_rag_aware_deep_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "prepare_deep.json",
    args.dry_run,
)


# ============================================================
# STAGE 11 - SELECTIVE QWEN 8B
# ============================================================

if args.skip_ai:

    print(
        f"{'Qwen8 selective':<30} "
        "SKIP (--skip-ai)"
    )

else:

    run_stage(
        "Qwen8 selective",
        MCP_ROOT
        / "qwen_investigator_v1.py",
        [
            "--case",
            CASE,
        ],
        MCP_ROOT,
        STATE_DIR
        / "qwen8_selective.json",
        args.dry_run,
    )


# ============================================================
# STAGE 12 - SYNTHESIS PREPARATION
# ============================================================

run_stage(
    "Prepare synthesis",
    MCP_ROOT
    / "prepare_case_synthesis_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "prepare_synthesis.json",
    args.dry_run,
)


# ============================================================
# STAGE 13 - DETERMINISTIC SYNTHESIS
# ============================================================

run_stage(
    "Case synthesis",
    MCP_ROOT
    / "case_synthesis_deterministic_v1.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "deterministic_synthesis.json",
    args.dry_run,
)


# ============================================================
# STAGE 14 - FINAL REPORT
# ============================================================

run_stage(
    "Final report",
    MCP_ROOT
    / "generate_final_report_v2.py",
    [
        "--case",
        CASE,
    ],
    MCP_ROOT,
    STATE_DIR
    / "final_report.json",
    args.dry_run,
)


print()
print("=" * 72)
print("ORCHESTRATOR V2 RESULT")
print("=" * 72)


if args.dry_run:

    print("Mode: DRY RUN")

else:

    if not FINAL_REPORT.is_file():

        raise RuntimeError(
            "Final report missing after pipeline."
        )

    synthesis = json.loads(
        SYNTHESIS_DETERMINISTIC.read_text(
            encoding="utf-8"
        )
    )

    print(
        f"Assessment: "
        f"{synthesis.get('overall_assessment')}"
    )

    print(
        f"Priority:   "
        f"{synthesis.get('priority')}"
    )

    print(
        f"Confidence: "
        f"{synthesis.get('confidence')}"
    )

    print(
        f"Report:     "
        f"{FINAL_REPORT}"
    )


print()
print(
    "Qwen policy: SEQUENTIAL ONLY"
)

print(
    "32K case-level Qwen8: DISABLED"
)

print(
    "Original evidence modification: NEVER"
)

print(
    f"State directory: {STATE_DIR}"
)

print()
print("=" * 72)
print("DFIR-AI CASE ORCHESTRATOR V2: COMPLETE")
print("=" * 72)

