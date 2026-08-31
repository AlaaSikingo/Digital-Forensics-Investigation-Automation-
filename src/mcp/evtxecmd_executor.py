from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    require_action,
)


EVTXECMD_EXE = (Path(__file__).resolve().parents[2] / "tools" / "windows" / "EZTools" / "EvtxeCmd" / "EvtxECmd.exe")

OFFLINE_EVIDENCE_ROOTS = [
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "kape_offline"),
    (Path(__file__).resolve().parents[2] / "workspace"),
]


def _validate_evtx_source(source_path: str) -> tuple[Path, str]:
    source = Path(source_path).resolve()

    if not source.exists():
        raise PolicyError(f"EVTX source does not exist: {source}")

    allowed = False

    for root in OFFLINE_EVIDENCE_ROOTS:
        root = root.resolve()

        try:
            source.relative_to(root)
            allowed = True
            break
        except ValueError:
            continue

    if not allowed:
        raise PolicyError(
            f"EvtxECmd AUTO analysis only accepts approved offline evidence paths: {source}"
        )

    if source.is_file():
        if source.suffix.lower() != ".evtx":
            raise PolicyError("EvtxECmd AUTO analysis only accepts .evtx files")
        return source, "file"

    if source.is_dir():
        if not any(source.rglob("*.evtx")):
            raise PolicyError(
                "No .evtx files were found in the supplied directory"
            )
        return source, "directory"

    raise PolicyError("Unsupported EVTX source type")


def validate_evtxecmd_request(source_path: str) -> dict:
    tool = require_action(
        tool_id="eztools",
        action="offline_evtx_analysis",
        required_policy="AUTO",
    )

    source, input_type = _validate_evtx_source(source_path)

    return {
        "tool": tool,
        "source": str(source),
        "input_type": input_type,
    }


def run_evtxecmd(
    source_path: str,
    case_id: str,
) -> dict:

    try:
        validated = validate_evtxecmd_request(source_path)

        source = Path(validated["source"])
        input_type = validated["input_type"]
        tool = validated["tool"]

        output_root = get_case_output_directory(
            case_id=case_id,
            tool_name=r"parsed\evtxecmd",
        )

        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")

        output_file_name = f"evtxecmd_{timestamp}.csv"

        output_file = output_root / output_file_name

        if output_file.exists():
            raise PolicyError(
                f"Output file already exists: {output_file}"
            )

        executable = EVTXECMD_EXE.resolve()

        if not executable.exists():
            raise PolicyError(
                f"EvtxECmd executable not found: {executable}"
            )

        command = [str(executable)]

        if input_type == "file":
            command.extend(["-f", str(source)])
        else:
            command.extend(["-d", str(source)])

        command.extend([
            "--csv",
            str(output_root),
            "--csvf",
            output_file_name,
        ])

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
            "success": completed.returncode == 0 and output_file.exists(),
            "tool": "eztools",
            "component": "EvtxECmd",
            "tool_version": "2026.5.0",
            "action": "offline_evtx_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "input_type": input_type,
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
            "component": "EvtxECmd",
            "error_type": "TIMEOUT",
            "error": "EvtxECmd timed out after 1800 seconds",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "eztools",
            "component": "EvtxECmd",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "eztools",
            "component": "EvtxECmd",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }

