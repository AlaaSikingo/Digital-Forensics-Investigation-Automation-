from pathlib import Path
from datetime import datetime, timezone

from policy import WORKSPACE_ROOT, PolicyError, validate_case_id
from mftecmd_executor import run_mftecmd, validate_mftecmd_request
from evtxecmd_executor import run_evtxecmd, validate_evtxecmd_request
from hayabusa_executor import run_hayabusa, validate_hayabusa_request
from pecmd_executor import run_pecmd, validate_pecmd_request
from recmd_executor import run_recmd, validate_recmd_request
from lecmd_executor import run_lecmd, validate_lecmd_request


def _case_triage_paths(case_id: str) -> dict:
    """Resolve the fixed DFIR-AI triage paths for a case."""

    validate_case_id(case_id)

    case_root = (Path(WORKSPACE_ROOT) / case_id).resolve()
    workspace_root = Path(WORKSPACE_ROOT).resolve()

    try:
        case_root.relative_to(workspace_root)
    except ValueError:
        raise PolicyError("Case path escapes the DFIR-AI workspace")

    return {
        "case_root": case_root,
        "triage_root": case_root / "triage",
        "mft": case_root / "triage" / "filesystem" / "$MFT",
        "eventlogs": case_root / "triage" / "eventlogs",
        "prefetch": case_root / "triage" / "prefetch",
        "registry": case_root / "triage" / "registry",
        "lnk": case_root / "triage" / "lnk",
    }


def validate_triage_parse_request(case_id: str) -> dict:
    """
    Validate all currently supported AUTO parsing inputs before execution.

    Version 3 supports:
      - $MFT -> MFTECmd
      - EVTX -> EvtxECmd
      - EVTX -> Hayabusa
      - Prefetch -> PECmd
      - Registry -> RECmd
      - LNK -> LECmd
    """

    paths = _case_triage_paths(case_id)

    triage_root = paths["triage_root"]

    if not triage_root.is_dir():
        raise PolicyError(
            f"Triage directory does not exist: {triage_root}"
        )

    if not paths["mft"].is_file():
        raise PolicyError(
            f"Required $MFT artifact does not exist: {paths['mft']}"
        )

    if not paths["eventlogs"].is_dir():
        raise PolicyError(
            f"Required eventlogs directory does not exist: "
            f"{paths['eventlogs']}"
        )

    evtx_files = list(paths["eventlogs"].rglob("*.evtx"))

    if not evtx_files:
        raise PolicyError(
            f"No EVTX files found: {paths['eventlogs']}"
        )

    #
    # Prefetch is optional.
    #
    # Some valid Windows evidence sets do not contain Prefetch.
    # Absence of .pf files is an evidence gap, not a policy failure.
    #
    if paths["prefetch"].is_dir():
        prefetch_files = list(
            paths["prefetch"].rglob("*.pf")
        )
    else:
        prefetch_files = []

    if not paths["registry"].is_dir():
        raise PolicyError(
            f"Required Registry directory does not exist: "
            f"{paths['registry']}"
        )

    if not paths["lnk"].is_dir():
        raise PolicyError(
            f"Required LNK directory does not exist: "
            f"{paths['lnk']}"
        )

    # Every parser performs its own policy, executable, source-scope,
    # and input validation before any parser execution begins.
    validate_mftecmd_request(str(paths["mft"]))

    validate_evtxecmd_request(
        str(paths["eventlogs"])
    )

    validate_hayabusa_request(
        str(paths["eventlogs"])
    )

    pecmd_validation = None

    if prefetch_files:
        pecmd_validation = validate_pecmd_request(
            str(paths["prefetch"])
        )

    recmd_validation = validate_recmd_request(
        str(paths["registry"])
    )

    lecmd_validation = validate_lecmd_request(
        str(paths["lnk"])
    )

    return {
        "case_id": case_id,
        "case_root": str(paths["case_root"]),
        "triage_root": str(triage_root),
        "mft": str(paths["mft"]),
        "eventlogs": str(paths["eventlogs"]),
        "prefetch": str(paths["prefetch"]),
        "registry": str(paths["registry"]),
        "lnk": str(paths["lnk"]),
        "evtx_count": len(evtx_files),
        "prefetch_count": len(prefetch_files),
        "registry_hive_count": recmd_validation["hive_count"],
        "lnk_count": lecmd_validation["lnk_count"],
        "parsers": (
            [
                "MFTECmd",
                "EvtxECmd",
                "Hayabusa",
            ]
            + (
                ["PECmd"]
                if prefetch_files
                else []
            )
            + [
                "RECmd",
                "LECmd",
            ]
        ),
    }


def _parser_status(result: dict) -> str:
    """
    Normalize executor results without hiding partial forensic results.
    """

    if result.get("success") is True:
        return "SUCCESS"

    if result.get("partial_success") is True:
        return "PARTIAL_SUCCESS"

    return "FAILED"


def parse_triage_artifacts(case_id: str) -> dict:
    """
    Run the approved parsing chain against an existing case triage set.

    Parser execution remains delegated to the individual validated
    executors. No arbitrary command-line arguments are accepted.

    A parser may return PARTIAL_SUCCESS when useful forensic output was
    produced but one or more artifacts could not be parsed.
    """

    started = datetime.now(timezone.utc)

    try:
        validation = validate_triage_parse_request(case_id)

        results = {}

        results["mftecmd"] = run_mftecmd(
            validation["mft"],
            case_id,
        )

        results["evtxecmd"] = run_evtxecmd(
            validation["eventlogs"],
            case_id,
        )

        results["hayabusa"] = run_hayabusa(
            validation["eventlogs"],
            case_id,
        )

        if validation.get("prefetch_count", 0) > 0:
            results["pecmd"] = run_pecmd(
                validation["prefetch"],
                case_id,
            )

        results["recmd"] = run_recmd(
            validation["registry"],
            case_id,
        )

        results["lecmd"] = run_lecmd(
            validation["lnk"],
            case_id,
        )

        completed = datetime.now(timezone.utc)

        parser_statuses = {
            name: _parser_status(result)
            for name, result in results.items()
        }

        successful = [
            name
            for name, status in parser_statuses.items()
            if status == "SUCCESS"
        ]

        partial = [
            name
            for name, status in parser_statuses.items()
            if status == "PARTIAL_SUCCESS"
        ]

        failed = [
            name
            for name, status in parser_statuses.items()
            if status == "FAILED"
        ]

        # Overall parsing is considered successful when every parser
        # produced usable forensic results. Partial parser results are
        # explicitly retained and surfaced rather than hidden.
        usable = len(failed) == 0

        overall_status = (
            "SUCCESS"
            if usable and not partial
            else "PARTIAL_SUCCESS"
            if usable and partial
            else "FAILED"
        )

        return {
            "success": usable,
            "partial_success": (
                usable and len(partial) > 0
            ),
            "status": overall_status,
            "component": "triage_parser",
            "case_id": case_id,
            "policy": "AUTO",
            "triage_root": validation["triage_root"],
            "evtx_count": validation["evtx_count"],
            "prefetch_count": validation["prefetch_count"],
            "registry_hive_count": (
                validation["registry_hive_count"]
            ),
            "lnk_count": validation["lnk_count"],
            "parser_count": len(results),
            "successful_parsers": successful,
            "partial_parsers": partial,
            "failed_parsers": failed,
            "parser_statuses": parser_statuses,
            "started_utc": started.isoformat(),
            "completed_utc": completed.isoformat(),
            "duration_seconds": round(
                (completed - started).total_seconds(),
                3,
            ),
            "results": results,
        }

    except PolicyError as exc:
        return {
            "success": False,
            "partial_success": False,
            "status": "FAILED",
            "component": "triage_parser",
            "case_id": case_id,
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "partial_success": False,
            "status": "FAILED",
            "component": "triage_parser",
            "case_id": case_id,
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }


