import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent

PYTHON = (
    ROOT
    / ".venv"
    / "Scripts"
    / "python.exe"
)


parser = argparse.ArgumentParser(
    description=(
        "DFIR-AI Full Case Pipeline v1"
    )
)

parser.add_argument(
    "--case",
    required=True,
)

parser.add_argument(
    "--image",
    required=True,
)

parser.add_argument(
    "--profile",
    default="windows_standard",
)

parser.add_argument(
    "--skip-ai",
    action="store_true",
)

args = parser.parse_args()


CASE = args.case.strip()

IMAGE = Path(
    args.image
).resolve()

PROFILE = args.profile.strip()


if not CASE:

    raise RuntimeError(
        "Case ID cannot be empty."
    )


if not IMAGE.is_file():

    raise RuntimeError(
        f"Forensic image does not exist: "
        f"{IMAGE}"
    )


print("=" * 72)
print("DFIR-AI FULL CASE PIPELINE V1")
print("=" * 72)

print()
print(f"Case:    {CASE}")
print(f"Image:   {IMAGE}")
print(f"Profile: {PROFILE}")

print()
print("=" * 72)
print("PHASE 1 - IMAGE TO EVIDENCE.DB")
print("=" * 72)


prepare_command = [
    str(PYTHON),
    "-u",
    str(
        ROOT
        / "prepare_case_from_image_v1.py"
    ),
    "--case",
    CASE,
    "--image",
    str(IMAGE),
    "--profile",
    PROFILE,
]


result = subprocess.run(
    prepare_command,
    cwd=str(ROOT),
    check=False,
)


if result.returncode != 0:

    raise RuntimeError(
        "Image preparation phase failed "
        f"with exit code "
        f"{result.returncode}"
    )


print()
print("=" * 72)
print("PHASE 2 - INVESTIGATION PIPELINE")
print("=" * 72)


investigation_command = [
    str(PYTHON),
    "-u",
    str(
        ROOT
        / "run_case_v2.py"
    ),
    "--case",
    CASE,
]


if args.skip_ai:

    investigation_command.append(
        "--skip-ai"
    )


result = subprocess.run(
    investigation_command,
    cwd=str(ROOT),
    check=False,
)


if result.returncode != 0:

    raise RuntimeError(
        "Investigation phase failed "
        f"with exit code "
        f"{result.returncode}"
    )


report = (
    (Path(__file__).resolve().parents[2] / "workspace")
    / CASE
    / "report"
    / f"{CASE}_DFIR_Report.md"
)


if not args.skip_ai:

    if not report.is_file():

        raise RuntimeError(
            "Pipeline completed but final "
            "report is missing."
        )


print()
print("=" * 72)
print("FULL CASE PIPELINE RESULT")
print("=" * 72)

print()
print(
    f"Case:   {CASE}"
)

if report.is_file():

    print(
        f"Report: {report}"
    )

else:

    print(
        "Report: not generated "
        "(AI/synthesis may have been skipped)"
    )


print()
print(
    "Original evidence modification: NEVER"
)

print(
    "Qwen execution: SEQUENTIAL ONLY"
)

print()
print("=" * 72)
print("DFIR-AI FULL CASE PIPELINE V1: COMPLETE")
print("=" * 72)
