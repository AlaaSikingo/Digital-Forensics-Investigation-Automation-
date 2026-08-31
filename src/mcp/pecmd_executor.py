from datetime import datetime, timezone
from pathlib import Path
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    get_tool,
    require_action,
)


ALLOWED_SOURCE_ROOTS = (
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test"),
    (Path(__file__).resolve().parents[2] / "workspace"),
)


def _is_under_allowed_root(path: Path) -> bool:
    resolved = path.resolve()

    for root in ALLOWED_SOURCE_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue

    return False


def validate_pecmd_request(source_path: str) -> dict:
    """
    Validate an offline Prefetch parsing request.

    Only a single .pf file or a directory containing .pf files
    under approved DFIR-AI evidence locations is accepted.
    """

    tool = require_action(
        tool_id="eztools",
        action="offline_prefetch_analysis",
        required_policy="AUTO",
    )

    source = Path(source_path).resolve()

    if not _is_under_allowed_root(source):
        raise PolicyError(
            f"Prefetch source is outside approved evidence roots: {source}"
        )

    if source.is_file():
        if source.suffix.lower() != ".pf":
            raise PolicyError(
                f"PECmd AUTO analysis accepts only .pf files: {source}"
            )

        input_type = "file"
        prefetch_count = 1

    elif source.is_dir():
        prefetch_files = [
            path
            for path in source.rglob("*")
            if path.is_file() and path.suffix.lower() == ".pf"
        ]

        if not prefetch_files:
            raise PolicyError(
                f"No Prefetch .pf files found in directory: {source}"
            )

        input_type = "directory"
        prefetch_count = len(prefetch_files)

    else:
        raise PolicyError(
            f"Prefetch source does not exist: {source}"
        )

    executable = (
        Path(tool["install_path"]).resolve()
        / tool["tools"]["prefetch"]
    ).resolve()

    if not executable.is_file():
        raise PolicyError(
            f"PECmd executable not found: {executable}"
        )

    return {
        "tool": tool,
        "source": source,
        "input_type": input_type,
        "prefetch_count": prefetch_count,
        "executable": executable,
    }


def run_pecmd(source_path: str, case_id: str) -> dict:
    """
    Parse offline Windows Prefetch evidence with PECmd.

    Fixed AUTO command surface:
      PECmd.exe -f <file> --csv <workspace> --csvf <name>
      PECmd.exe -d <dir>  --csv <workspace> --csvf <name>

    No VSS, decompressed-byte export, arbitrary keywords,
    JSON/HTML output, debug/trace, or arbitrary switches.
    """

    try:
        validation = validate_pecmd_request(source_path)

        tool = validation["tool"]
        source = validation["source"]
        input_type = validation["input_type"]
        executable = validation["executable"]

        output_directory = get_case_output_directory(
            case_id=case_id,
            tool_name=r"parsed\pecmd",
        )

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )

        output_name = f"pecmd_{timestamp}.csv"
        output_file = output_directory / output_name

        if output_file.exists():
            raise PolicyError(
                f"Output already exists and overwrite is prohibited: "
                f"{output_file}"
            )

        command = [str(executable)]

        if input_type == "file":
            command.extend(["-f", str(source)])
        else:
            command.extend(["-d", str(source)])

        command.extend([
            "--csv",
            str(output_directory),
            "--csvf",
            output_name,
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

        timeline_file = (
            output_directory
            / f"{Path(output_name).stem}_Timeline.csv"
        )

        output_files = []

        for path, output_type in (
            (output_file, "prefetch"),
            (timeline_file, "timeline"),
        ):
            if path.exists():
                output_files.append({
                    "type": output_type,
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                })

        success = (
            completed.returncode == 0
            and output_file.exists()
        )

        return {
            "success": success,
            "tool": "pecmd",
            "tool_version": tool.get("version"),
            "action": "offline_prefetch_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "input_type": input_type,
            "prefetch_count": validation["prefetch_count"],
            "output_files": output_files,
            "output_count": len(output_files),
            "exit_code": completed.returncode,
            "stdout": (completed.stdout or "")[-8000:],
            "stderr": (completed.stderr or "")[-8000:],
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "pecmd",
            "error": "PECmd execution timed out after 1800 seconds",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "pecmd",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "pecmd",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }

