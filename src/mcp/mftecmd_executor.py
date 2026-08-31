from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    require_action,
)


MFTECMD_EXE = (Path(__file__).resolve().parents[2] / "tools" / "windows" / "EZTools" / "MFTECmd.exe")

ALLOWED_SOURCE_ROOTS = [
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "evidence"),
    (Path(__file__).resolve().parents[2] / "workspace"),
]


def _validate_mft_source(source_path: str) -> Path:
    source = Path(source_path).resolve()

    if not source.exists():
        raise PolicyError(
            f"$MFT source does not exist: {source}"
        )

    if not source.is_file():
        raise PolicyError(
            "MFTECmd AUTO analysis requires a single $MFT file"
        )

    allowed = False

    for root in ALLOWED_SOURCE_ROOTS:
        root = root.resolve()

        try:
            source.relative_to(root)
            allowed = True
            break
        except ValueError:
            continue

    if not allowed:
        raise PolicyError(
            f"MFTECmd AUTO analysis only accepts approved offline evidence paths: {source}"
        )

    if source.name.lower() not in {
        "$mft",
        "mft",
    }:
        raise PolicyError(
            "MFTECmd AUTO action currently accepts only $MFT artifacts"
        )

    return source


def validate_mftecmd_request(source_path: str) -> dict:
    tool = require_action(
        tool_id="eztools",
        action="offline_mft_analysis",
        required_policy="AUTO",
    )

    source = _validate_mft_source(source_path)

    return {
        "tool": tool,
        "source": str(source),
    }


def run_mftecmd(
    source_path: str,
    case_id: str,
) -> dict:

    try:
        validated = validate_mftecmd_request(source_path)

        source = Path(validated["source"])
        tool = validated["tool"]

        output_root = get_case_output_directory(
            case_id=case_id,
            tool_name=r"parsed\mftecmd",
        )

        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")

        output_name = f"mftecmd_{timestamp}.csv"
        output_file = output_root / output_name

        if output_file.exists():
            raise PolicyError(
                f"MFTECmd output already exists: {output_file}"
            )

        executable = MFTECMD_EXE.resolve()

        if not executable.exists():
            raise PolicyError(
                f"MFTECmd executable not found: {executable}"
            )

        command = [
            str(executable),
            "-f",
            str(source),
            "--csv",
            str(output_root),
            "--csvf",
            output_name,
        ]

        completed = subprocess.run(
            command,
            cwd=str(executable.parent),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )

        return {
            "success": (
                completed.returncode == 0
                and output_file.exists()
                and output_file.stat().st_size > 0
            ),
            "tool": "eztools",
            "component": "MFTECmd",
            "tool_version": "2026.5.0",
            "action": "offline_mft_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "output_file": str(output_file),
            "output_size_bytes": (
                output_file.stat().st_size
                if output_file.exists()
                else 0
            ),
            "exit_code": completed.returncode,
            "stdout": (completed.stdout or "")[-8000:],
            "stderr": (completed.stderr or "")[-8000:],
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "eztools",
            "component": "MFTECmd",
            "error_type": "TIMEOUT",
            "error": "MFTECmd timed out after 1800 seconds",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "eztools",
            "component": "MFTECmd",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "eztools",
            "component": "MFTECmd",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }

