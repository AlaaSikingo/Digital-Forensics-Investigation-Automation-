from datetime import datetime, timezone
from pathlib import Path
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    require_action,
    resolve_executable,
    validate_evtx_input,
)


def validate_hayabusa_request(evidence_path: str) -> dict:
    """
    Validate an offline Hayabusa EVTX analysis request before job creation.
    """

    tool = require_action(
        tool_id="hayabusa",
        action="offline_evtx_analysis",
        required_policy="AUTO",
    )

    evidence, input_type = validate_evtx_input(evidence_path)

    return {
        "tool": tool,
        "evidence": evidence,
        "input_type": input_type,
    }


def run_hayabusa(evidence_path: str, case_id: str) -> dict:
    """
    Analyze offline Windows EVTX evidence with Hayabusa.

    Accepts either one .evtx file or a directory containing .evtx files.
    Results are written only to the DFIR-AI case workspace.
    """

    try:
        validation = validate_hayabusa_request(evidence_path)

        tool = validation["tool"]
        evidence = validation["evidence"]
        input_type = validation["input_type"]

        executable = resolve_executable(tool)

        output_directory = get_case_output_directory(
            case_id=case_id,
            tool_name=r"parsed\hayabusa",
        )

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_file = output_directory / f"timeline_{timestamp}.jsonl"

        if output_file.exists():
            raise PolicyError(
                f"Output already exists and overwrite is prohibited: {output_file}"
            )

        command = [
            str(executable),
            "json-timeline",
        ]

        if input_type == "file":
            command.extend(["-f", str(evidence)])
        else:
            command.extend(["-d", str(evidence)])

        command.extend([
            "-L",
            "-o",
            str(output_file),
            "-w",
            "-O",
            "-K",
        ])

        completed = subprocess.run(
            command,
            cwd=str(Path(tool["install_path"]).resolve()),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )

        success = (
            completed.returncode == 0
            and output_file.exists()
        )

        return {
            "success": success,
            "tool": "hayabusa",
            "tool_version": tool.get("version"),
            "action": "offline_evtx_analysis",
            "policy": "AUTO",
            "evidence_path": str(evidence),
            "input_type": input_type,
            "output_file": str(output_file) if output_file.exists() else None,
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
            "tool": "hayabusa",
            "error": "Hayabusa execution timed out after 1800 seconds",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "hayabusa",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "hayabusa",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }
