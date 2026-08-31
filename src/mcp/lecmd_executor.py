from pathlib import Path
from datetime import datetime, timezone
import subprocess

from policy import (
    WORKSPACE_ROOT,
    PolicyError,
    get_tool,
    require_action,
)


ALLOWED_SOURCE_ROOTS = [
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test"),
    Path(WORKSPACE_ROOT),
]


def _resolve_lecmd_executable() -> Path:
    tool = get_tool("eztools")

    tools = tool.get("tools", {})
    relative = tools.get("lnk")

    if not relative:
        raise PolicyError(
            "LECmd executable is not registered in EZTools manifest"
        )

    install_path = Path(tool["install_path"]).resolve()
    executable = (install_path / relative).resolve()

    try:
        executable.relative_to(install_path)
    except ValueError:
        raise PolicyError(
            "LECmd executable path escapes EZTools installation directory"
        )

    if not executable.is_file():
        raise PolicyError(
            f"LECmd executable does not exist: {executable}"
        )

    return executable


def _validate_source_root(source: Path) -> None:
    resolved = source.resolve()

    for root in ALLOWED_SOURCE_ROOTS:
        root_resolved = root.resolve()

        try:
            resolved.relative_to(root_resolved)
            return
        except ValueError:
            continue

    raise PolicyError(
        f"LECmd source is outside approved evidence roots: {resolved}"
    )


def validate_lecmd_request(source_path: str) -> dict:
    """
    Validate an offline Windows LNK parsing request.

    Supported:
      - one .lnk file
      - directory recursively containing .lnk files

    Not supported:
      - live system parsing
      - arbitrary LECmd switches
      - non-LNK processing
      - external upload
      - evidence modification
    """

    require_action(
        "eztools",
        "offline_lnk_analysis",
        "AUTO",
    )

    source = Path(source_path).resolve()

    if not source.exists():
        raise PolicyError(
            f"LECmd source does not exist: {source}"
        )

    _validate_source_root(source)

    if source.is_file():
        if source.suffix.lower() != ".lnk":
            raise PolicyError(
                f"LECmd AUTO mode accepts only .lnk files: {source}"
            )

        lnk_files = [source]
        input_type = "file"

    elif source.is_dir():
        lnk_files = [
            item
            for item in source.rglob("*")
            if item.is_file()
            and item.suffix.lower() == ".lnk"
        ]

        if not lnk_files:
            raise PolicyError(
                f"No .lnk files found under: {source}"
            )

        input_type = "directory"

    else:
        raise PolicyError(
            f"Unsupported LECmd source type: {source}"
        )

    executable = _resolve_lecmd_executable()

    return {
        "source_path": str(source),
        "input_type": input_type,
        "lnk_count": len(lnk_files),
        "executable": str(executable),
        "policy": "AUTO",
    }


def run_lecmd(source_path: str, case_id: str) -> dict:
    """
    Run LECmd against approved offline LNK evidence.

    Output is written only beneath:
      workspace/<case_id>/parsed/lecmd
    """

    validation = validate_lecmd_request(source_path)

    source = Path(validation["source_path"])
    executable = Path(validation["executable"])

    workspace_root = Path(WORKSPACE_ROOT).resolve()
    case_root = (workspace_root / case_id).resolve()

    try:
        case_root.relative_to(workspace_root)
    except ValueError:
        raise PolicyError(
            "Case path escapes the DFIR-AI workspace"
        )

    output_dir = case_root / "parsed" / "lecmd"
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    output_name = f"lecmd_{timestamp}.csv"
    output_file = output_dir / output_name

    if output_file.exists():
        raise PolicyError(
            f"LECmd output already exists: {output_file}"
        )

    command = [
        str(executable),
    ]

    if validation["input_type"] == "file":
        command += [
            "-f",
            str(source),
        ]
    else:
        command += [
            "-d",
            str(source),
        ]

    command += [
        "--csv",
        str(output_dir),
        "--csvf",
        output_name,
        "-q",
    ]

    started = datetime.now(timezone.utc)

    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "lecmd",
            "action": "offline_lnk_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "error_type": "TIMEOUT",
            "error": "LECmd exceeded 1800 second timeout",
            "original_evidence_modified": False,
        }

    except OSError as exc:
        return {
            "success": False,
            "tool": "lecmd",
            "action": "offline_lnk_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
            "original_evidence_modified": False,
        }

    finished = datetime.now(timezone.utc)

    output_exists = output_file.is_file()
    output_size = (
        output_file.stat().st_size
        if output_exists
        else 0
    )

    success = (
        completed.returncode == 0
        and output_exists
        and output_size > 0
    )

    return {
        "success": success,
        "tool": "lecmd",
        "action": "offline_lnk_analysis",
        "policy": "AUTO",
        "source_path": str(source),
        "input_type": validation["input_type"],
        "lnk_count": validation["lnk_count"],
        "output_file": (
            str(output_file)
            if output_exists
            else None
        ),
        "output_size_bytes": output_size,
        "exit_code": completed.returncode,
        "started_utc": started.isoformat(),
        "completed_utc": finished.isoformat(),
        "duration_seconds": round(
            (finished - started).total_seconds(),
            3,
        ),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "original_evidence_modified": False,
    }


