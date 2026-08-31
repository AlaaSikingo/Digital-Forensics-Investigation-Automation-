from __future__ import annotations

from pathlib import Path
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    require_action,
)


OFFLINE_EVIDENCE_ROOTS = [
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "kape_offline"),
]

ALLOWED_TARGETS = {
    "RegistryHives",
    "EvidenceOfExecution",
    "EventLogs",
    "WebBrowsers",
    "Windows",
}


def _validate_source(source_path: str) -> Path:
    source = Path(source_path).resolve()

    if not source.exists():
        raise PolicyError(f"Source path does not exist: {source}")

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
            f"KAPE AUTO collection only accepts approved offline evidence paths: {source}"
        )

    return source


def _validate_target(target: str) -> str:
    if target not in ALLOWED_TARGETS:
        raise PolicyError(
            f"KAPE target is not allowed for AUTO execution: {target}"
        )

    return target




def validate_kape_collection_request(
    source_path: str,
    target: str,
) -> dict:
    tool = require_action(
        tool_id="kape",
        action="offline_evidence_collection",
        required_policy="AUTO",
    )

    source = _validate_source(source_path)
    validated_target = _validate_target(target)

    return {
        "tool": tool,
        "source": str(source),
        "target": validated_target,
    }

def run_kape_collection(
    source_path: str,
    target: str,
    case_id: str,
) -> dict:
    try:
        tool = require_action(
            tool_id="kape",
            action="offline_evidence_collection",
            required_policy="AUTO",
        )

        source = _validate_source(source_path)
        target = _validate_target(target)

        output_directory = get_case_output_directory(
            case_id=case_id,
            tool_name="kape",
        )

        collection_directory = output_directory / "collection"

        if collection_directory.exists():
            if any(collection_directory.iterdir()):
                raise PolicyError(
                    f"KAPE output directory is not empty: "
                    f"{collection_directory}"
                )
        else:
            collection_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

        executable = (Path(__file__).resolve().parents[2] / "tools" / "collection" / "KAPE" / "kape.exe").resolve()

        if not executable.exists():
            raise PolicyError(
                f"KAPE executable not found: {executable}"
            )

        command = [
            str(executable),
            "--tsource",
            str(source),
            "--target",
            target,
            "--tdest",
            str(collection_directory),
        ]

        completed = subprocess.run(
            command,
            cwd=str(executable.parent),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=7200,
        )

        collected_files = []

        if collection_directory.exists():
            for item in collection_directory.rglob("*"):
                if item.is_file():
                    collected_files.append(str(item))

        return {
            "success": completed.returncode == 0,
            "tool": "kape",
            "tool_version": tool.get("version"),
            "action": "offline_evidence_collection",
            "policy": "AUTO",
            "source_path": str(source),
            "target": target,
            "output_directory": str(collection_directory),
            "collected_file_count": len(collected_files),
            "exit_code": completed.returncode,
            "stdout": (completed.stdout or "")[-8000:],
            "stderr": (completed.stderr or "")[-8000:],
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "kape",
            "error_type": "TIMEOUT",
            "error": "KAPE execution timed out after 7200 seconds",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "kape",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "kape",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }


