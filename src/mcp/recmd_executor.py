from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess

from policy import (
    PolicyError,
    get_case_output_directory,
    require_action,
)


ALLOWED_SOURCE_ROOTS = (
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test"),
    (Path(__file__).resolve().parents[2] / "workspace"),
)

RECMD_BATCH_RELATIVE_PATH = (
    Path("RECmd") / "BatchExamples" / "DFIRBatch.reb"
)

RECOGNIZED_HIVE_NAMES = {
    "system",
    "software",
    "sam",
    "security",
    "default",
    "ntuser.dat",
    "usrclass.dat",
}

TRANSACTION_LOG_ERROR_MARKERS = (
    "not a Registry transaction log",
    "Registry hive is dirty and no transaction logs were found",
    "Aborting!!",
)

PLUGIN_EXCEPTION_MARKERS = (
    "System.NullReferenceException",
    "System.ArgumentException",
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


def _find_registry_hives(source: Path) -> list[Path]:
    candidates = (
        [source]
        if source.is_file()
        else [p for p in source.rglob("*") if p.is_file()]
    )

    hives = [
        path
        for path in candidates
        if path.name.lower() in RECOGNIZED_HIVE_NAMES
    ]

    return sorted(
        hives,
        key=lambda p: str(p).lower(),
    )


def validate_recmd_request(source_path: str) -> dict:
    """
    Validate a fixed offline Registry triage request.

    AUTO mode accepts only recognized offline Windows Registry hives
    beneath approved DFIR-AI evidence locations. RECmd's DFIRBatch.reb
    is fixed internally and cannot be supplied by the caller.
    """

    tool = require_action(
        tool_id="eztools",
        action="offline_registry_analysis",
        required_policy="AUTO",
    )

    source = Path(source_path).resolve()

    if not _is_under_allowed_root(source):
        raise PolicyError(
            f"Registry source is outside approved evidence roots: {source}"
        )

    if not source.exists():
        raise PolicyError(
            f"Registry source does not exist: {source}"
        )

    if not source.is_file() and not source.is_dir():
        raise PolicyError(
            f"Registry source must be a file or directory: {source}"
        )

    hives = _find_registry_hives(source)

    if not hives:
        raise PolicyError(
            f"No recognized offline Registry hives found: {source}"
        )

    install_path = Path(tool["install_path"]).resolve()

    registry_relative = tool.get("tools", {}).get("registry")

    if not registry_relative:
        raise PolicyError(
            "RECmd executable is not registered in the EZTools manifest"
        )

    executable = (install_path / registry_relative).resolve()

    if not executable.is_file():
        raise PolicyError(
            f"RECmd executable not found: {executable}"
        )

    batch_file = (
        install_path / RECMD_BATCH_RELATIVE_PATH
    ).resolve()

    if not batch_file.is_file():
        raise PolicyError(
            f"Approved RECmd DFIR batch not found: {batch_file}"
        )

    return {
        "tool": tool,
        "source": source,
        "input_type": "file" if source.is_file() else "directory",
        "hives": hives,
        "hive_count": len(hives),
        "executable": executable,
        "batch_file": batch_file,
    }


def _safe_hive_label(hive: Path, source: Path) -> str:
    """
    Produce a deterministic output-safe label without exposing arbitrary
    caller-controlled command-line arguments.
    """

    try:
        if source.is_dir():
            relative = hive.relative_to(source)
        else:
            relative = Path(hive.name)
    except ValueError:
        relative = Path(hive.name)

    raw = "__".join(relative.parts)

    safe = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        raw,
    ).strip("._-")

    return safe or "registry_hive"


def _classify_recmd_output(
    stdout: str,
    stderr: str,
    returncode: int,
    output_file: Path,
) -> dict:
    combined = "\n".join(
        part
        for part in (stdout, stderr)
        if part
    )

    lower = combined.lower()

    transaction_log_error = any(
        marker.lower() in lower
        for marker in TRANSACTION_LOG_ERROR_MARKERS
    )

    abort_detected = "aborting!!" in lower

    null_reference_warning = (
        "system.nullreferenceexception" in lower
    )

    argument_exception = (
        "system.argumentexception" in lower
    )

    output_exists = output_file.is_file()
    output_size = (
        output_file.stat().st_size
        if output_exists
        else 0
    )

    match = re.search(
        r"Found\s+([\d,]+)\s+key/value pairs?\s+across\s+"
        r"([\d,]+)\s+files?",
        combined,
        flags=re.IGNORECASE,
    )

    key_value_pairs = None

    if match:
        key_value_pairs = int(
            match.group(1).replace(",", "")
        )

    parser_warnings = []

    if transaction_log_error:
        parser_warnings.append(
            "Registry transaction-log processing failed"
        )

    if null_reference_warning:
        parser_warnings.append(
            "RECmd plugin raised NullReferenceException"
        )

    if argument_exception and not transaction_log_error:
        parser_warnings.append(
            "RECmd raised ArgumentException"
        )

    fatal_parser_failure = (
        returncode != 0
        or transaction_log_error
        or abort_detected
    )

    parsed = (
        not fatal_parser_failure
        and output_exists
        and output_size > 0
    )

    return {
        "parsed": parsed,
        "transaction_log_error": transaction_log_error,
        "abort_detected": abort_detected,
        "key_value_pairs": key_value_pairs,
        "parser_warnings": parser_warnings,
        "output_exists": output_exists,
        "output_size_bytes": output_size,
    }


def _run_single_hive(
    executable: Path,
    batch_file: Path,
    hive: Path,
    source: Path,
    output_directory: Path,
    timestamp: str,
    index: int,
) -> dict:
    label = _safe_hive_label(
        hive=hive,
        source=source,
    )

    output_name = (
        f"recmd_{timestamp}_{index:02d}_{label}.csv"
    )

    output_file = output_directory / output_name

    if output_file.exists():
        raise PolicyError(
            f"Output already exists and overwrite is prohibited: "
            f"{output_file}"
        )

    command = [
        str(executable),
        "-f",
        str(hive),
        "--bn",
        str(batch_file),
        "--csv",
        str(output_directory),
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

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    classification = _classify_recmd_output(
        stdout=stdout,
        stderr=stderr,
        returncode=completed.returncode,
        output_file=output_file,
    )

    return {
        "hive": str(hive),
        "hive_name": hive.name,
        "parsed": classification["parsed"],
        "transaction_log_error": (
            classification["transaction_log_error"]
        ),
        "abort_detected": (
            classification["abort_detected"]
        ),
        "key_value_pairs": (
            classification["key_value_pairs"]
        ),
        "parser_warnings": (
            classification["parser_warnings"]
        ),
        "output_file": (
            str(output_file)
            if classification["output_exists"]
            else None
        ),
        "output_size_bytes": (
            classification["output_size_bytes"]
        ),
        "exit_code": completed.returncode,
        "stdout": stdout[-12000:],
        "stderr": stderr[-12000:],
    }


def run_recmd(source_path: str, case_id: str) -> dict:
    """
    Parse approved offline Windows Registry evidence with RECmd.

    Each recognized hive is executed independently. This prevents one
    malformed or unusable hive/transaction-log pair from obscuring the
    processing status of other hives.

    Fixed AUTO command surface:

      RECmd.exe -f <recognized hive>
                 --bn <fixed DFIRBatch.reb>
                 --csv <workspace>
                 --csvf <generated filename>

    No caller-controlled batch files, Registry keys, values, VSS,
    synchronization, binary export, debug/trace, transaction-log
    manipulation, or arbitrary switches.

    Original evidence is never modified.
    """

    try:
        validation = validate_recmd_request(source_path)

        source = validation["source"]
        executable = validation["executable"]
        batch_file = validation["batch_file"]
        hives = validation["hives"]

        output_directory = get_case_output_directory(
            case_id=case_id,
            tool_name=r"parsed\recmd",
        )

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )

        hive_results = []

        for index, hive in enumerate(hives, start=1):
            try:
                result = _run_single_hive(
                    executable=executable,
                    batch_file=batch_file,
                    hive=hive,
                    source=source,
                    output_directory=output_directory,
                    timestamp=timestamp,
                    index=index,
                )

            except subprocess.TimeoutExpired:
                result = {
                    "hive": str(hive),
                    "hive_name": hive.name,
                    "parsed": False,
                    "transaction_log_error": False,
                    "abort_detected": False,
                    "key_value_pairs": None,
                    "parser_warnings": [
                        "RECmd execution timed out after 1800 seconds"
                    ],
                    "output_file": None,
                    "output_size_bytes": 0,
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "error_type": "TIMEOUT",
                }

            except Exception as exc:
                result = {
                    "hive": str(hive),
                    "hive_name": hive.name,
                    "parsed": False,
                    "transaction_log_error": False,
                    "abort_detected": False,
                    "key_value_pairs": None,
                    "parser_warnings": [],
                    "output_file": None,
                    "output_size_bytes": 0,
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "error_type": "EXECUTION_ERROR",
                    "error": str(exc),
                }

            hive_results.append(result)

        parsed_hives = [
            item
            for item in hive_results
            if item["parsed"]
        ]

        failed_hives = [
            item
            for item in hive_results
            if not item["parsed"]
        ]

        warning_hives = [
            item
            for item in hive_results
            if item.get("parser_warnings")
        ]

        transaction_log_failures = [
            item
            for item in hive_results
            if item.get("transaction_log_error")
        ]

        success = (
            len(parsed_hives) == len(hive_results)
            and len(hive_results) > 0
        )

        partial_success = (
            len(parsed_hives) > 0
            and len(failed_hives) > 0
        )

        return {
            "success": success,
            "partial_success": partial_success,
            "tool": "recmd",
            "action": "offline_registry_analysis",
            "policy": "AUTO",
            "source_path": str(source),
            "input_type": validation["input_type"],
            "batch_file": str(batch_file),
            "hives_discovered": len(hive_results),
            "hives_parsed": len(parsed_hives),
            "hives_failed": len(failed_hives),
            "hives_with_warnings": len(warning_hives),
            "transaction_log_failures": len(
                transaction_log_failures
            ),
            "failed_hives": [
                item["hive"]
                for item in failed_hives
            ],
            "hive_results": hive_results,
            "original_evidence_modified": False,
        }

    except PolicyError as exc:
        return {
            "success": False,
            "partial_success": False,
            "tool": "recmd",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "partial_success": False,
            "tool": "recmd",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }
