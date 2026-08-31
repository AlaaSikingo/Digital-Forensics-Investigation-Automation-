from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from policy import (
    PolicyError,
    WORKSPACE_ROOT,
    require_action,
    validate_case_id,
)

from tsk_image_executor import (
    inspect_forensic_image,
    validate_image_inspection_request,
)

TSK_BIN = (Path(__file__).resolve().parents[2] / "tools" / "disk" / "SleuthKit" / "bin")
FLS = TSK_BIN / "fls.exe"
ICAT = TSK_BIN / "icat.exe"

MAX_FLS_SECONDS = 1800
MAX_EXTRACT_SECONDS = 1800

# Prevent accidental unbounded collection.
CATEGORY_LIMITS = {
    "filesystem": 10,
    "eventlogs": 1000,
    "registry": 500,
    "prefetch": 2000,
    "amcache": 10,
    "srum": 10,
    "lnk": 3000,
    "jumplists": 3000,
}

STANDARD_DIRECTORIES = [
    "filesystem",
    "eventlogs",
    "registry",
    "registry/users",
    "prefetch",
    "amcache",
    "srum",
    "lnk",
    "jumplists",
]


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def _norm_lower(path: str) -> str:
    return _norm(path).lower()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)

    return h.hexdigest().upper()


def _run_text(command: list[str], timeout: int = MAX_FLS_SECONDS) -> dict:
    completed = subprocess.run(
        command,
        cwd=str(TSK_BIN),
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )

    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _parse_fls(text: str) -> list[dict[str, Any]]:
    """
    Typical TSK output:

      r/r 0-128-6:  $MFT
      d/d 39-144-5: Windows
      r/r 123-128-1: Windows/System32/file.ext

    Deleted entries may contain '*'.
    """

    records: list[dict[str, Any]] = []

    rx = re.compile(
        r"^\s*"
        r"(?P<entry_type>\S+)"
        r"\s+"
        r"(?:(?P<deleted>\*)\s+)?"
        r"(?P<meta>[^:]+)"
        r":\s*"
        r"(?P<path>.+?)"
        r"\s*$"
    )

    for line in text.splitlines():
        match = rx.match(line)

        if not match:
            continue

        path = match.group("path").strip()

        records.append(
            {
                "entry_type": match.group("entry_type"),
                "metadata_address": match.group("meta").strip(),
                "path": path,
                "normalized_path": _norm(path),
                "deleted": bool(match.group("deleted")),
            }
        )

    return records


def _fls_recursive(image: Path, offset_sectors: int) -> list[dict[str, Any]]:
    command = [
        str(FLS),
        "-r",
        "-p",
    ]

    if offset_sectors > 0:
        command.extend(
            [
                "-o",
                str(offset_sectors),
            ]
        )

    command.append(str(image))

    result = _run_text(command)

    if result["exit_code"] != 0:
        raise RuntimeError(
            "fls failed for filesystem offset "
            f"{offset_sectors}: {result['stderr'][-4000:]}"
        )

    return _parse_fls(result["stdout"])


def _candidate_offsets(inspection: dict) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    zero = inspection.get("offset_zero_filesystem") or {}

    if zero.get("detected"):
        candidates.append(
            {
                "offset_sectors": 0,
                "filesystem": zero.get("filesystem") or {},
            }
        )

    for fs in inspection.get("discovered_filesystems") or []:
        offset = fs.get("offset_sectors")

        if offset is None:
            offset = fs.get("start_sector")

        if offset is None:
            continue

        try:
            offset = int(offset)
        except (TypeError, ValueError):
            continue

        if not any(
            x["offset_sectors"] == offset
            for x in candidates
        ):
            candidates.append(
                {
                    "offset_sectors": offset,
                    "filesystem": fs.get("filesystem", fs),
                }
            )

    return candidates


def _looks_like_windows(
    records: list[dict[str, Any]],
) -> bool:
    """
    Detect a Windows filesystem using multiple independent
    filesystem artifacts.

    Strong Windows registry paths are sufficient alone.

    Otherwise require NTFS metadata plus at least two
    Windows-specific forensic artifact families.

    This prevents accepting arbitrary NTFS volumes simply
    because they contain a directory named Windows.
    """

    paths = {
        _norm_lower(record["path"])
        for record in records
        if record.get("path")
    }


    def exact_or_suffix(
        expected: str,
    ) -> bool:

        expected = expected.lower()

        return any(
            path == expected
            or path.endswith(
                "/" + expected
            )
            for path in paths
        )


    def contains_path(
        fragment: str,
    ) -> bool:

        fragment = fragment.lower()

        return any(
            fragment in path
            for path in paths
        )


    def contains_suffix(
        fragment: str,
        suffix: str,
    ) -> bool:

        fragment = fragment.lower()
        suffix = suffix.lower()

        return any(
            fragment in path
            and path.endswith(suffix)
            for path in paths
        )


    # --------------------------------------------------------
    # Strong Windows installation indicators.
    # Any one of these is enough.
    # --------------------------------------------------------

    strong_registry = any([
        exact_or_suffix(
            "windows/system32/config/system"
        ),
        exact_or_suffix(
            "windows/system32/config/software"
        ),
    ])

    if strong_registry:
        return True


    # --------------------------------------------------------
    # Supporting Windows artifact families.
    # --------------------------------------------------------

    registry_family = any([
        exact_or_suffix(
            "windows/system32/config/sam"
        ),
        exact_or_suffix(
            "windows/system32/config/security"
        ),
        exact_or_suffix(
            "windows/system32/config/default"
        ),
    ])


    evtx_family = contains_suffix(
        "windows/system32/winevt/logs/",
        ".evtx",
    )


    prefetch_family = contains_suffix(
        "windows/prefetch/",
        ".pf",
    )


    amcache_family = exact_or_suffix(
        "windows/appcompat/programs/amcache.hve"
    )


    srum_family = exact_or_suffix(
        "windows/system32/sru/srudb.dat"
    )


    ntfs_metadata = any([
        exact_or_suffix("$mft"),
        exact_or_suffix("$logfile"),
    ])


    family_count = sum([
        registry_family,
        evtx_family,
        prefetch_family,
        amcache_family,
        srum_family,
    ])


    # --------------------------------------------------------
    # Conservative forensic-volume fallback.
    #
    # Require:
    #   - NTFS metadata
    #   - at least two independent Windows artifact families
    #
    # Examples:
    #   EVTX + Prefetch
    #   Registry + EVTX
    #   Amcache + SRUM
    # --------------------------------------------------------

    if (
        ntfs_metadata
        and family_count >= 2
    ):
        return True


    return False

def _classify_artifact(record: dict[str, Any]) -> dict[str, Any] | None:
    path = _norm(record["path"])
    low = path.lower()
    basename = Path(path).name
    basename_low = basename.lower()

    #
    # NTFS filesystem metadata.
    #
    if low == "$mft":
        return {
            "category": "filesystem",
            "artifact_type": "mft",
            "output_relative": "$MFT",
        }

    if low == "$logfile":
        return {
            "category": "filesystem",
            "artifact_type": "logfile",
            "output_relative": "$LogFile",
        }

    if low in {
        "$extend/$usnjrnl:$j",
        "$usnjrnl:$j",
    }:
        return {
            "category": "filesystem",
            "artifact_type": "usn_journal",
            "output_relative": "$UsnJrnl_$J",
        }

    #
    # Windows Event Logs.
    #
    prefix = "windows/system32/winevt/logs/"

    if low.startswith(prefix) and low.endswith(".evtx"):
        return {
            "category": "eventlogs",
            "artifact_type": "evtx",
            "output_relative": basename,
        }

    #
    # Machine registry hives.
    #
    registry_machine = {
        "windows/system32/config/system": "SYSTEM",
        "windows/system32/config/software": "SOFTWARE",
        "windows/system32/config/sam": "SAM",
        "windows/system32/config/security": "SECURITY",
    }

    if low in registry_machine:
        return {
            "category": "registry",
            "artifact_type": "registry_hive",
            "output_relative": registry_machine[low],
        }

    #
    # Machine Registry transaction logs.
    # Keep LOG1/LOG2 beside their corresponding offline hive so
    # RECmd can replay dirty hives without modifying source evidence.
    #
    machine_log_match = re.match(
        r"^windows/system32/config/(system|software|sam|security)\.(log1|log2)$",
        low,
        re.IGNORECASE,
    )

    if machine_log_match:
        hive_name = machine_log_match.group(1).upper()
        log_name = machine_log_match.group(2).upper()

        return {
            "category": "registry",
            "artifact_type": "registry_transaction_log",
            "output_relative": f"{hive_name}.{log_name}",
        }

    #
    # User registry hives.
    #
    user_match = re.match(
        r"^users/([^/]+)/ntuser\.dat$",
        low,
        re.IGNORECASE,
    )

    if user_match:
        username = _norm(path).split("/")[1]

        return {
            "category": "registry",
            "artifact_type": "ntuser",
            "output_relative":
                f"users/{username}/NTUSER.DAT",
        }

    ntuser_log_match = re.match(
        r"^users/([^/]+)/ntuser\.dat\.(log1|log2)$",
        low,
        re.IGNORECASE,
    )

    if ntuser_log_match:
        username = _norm(path).split("/")[1]
        log_name = ntuser_log_match.group(2).upper()

        return {
            "category": "registry",
            "artifact_type": "registry_transaction_log",
            "output_relative":
                f"users/{username}/NTUSER.DAT.{log_name}",
        }

    usrclass_match = re.match(
        r"^users/([^/]+)/appdata/local/microsoft/windows/usrclass\.dat$",
        low,
        re.IGNORECASE,
    )

    if usrclass_match:
        username = _norm(path).split("/")[1]

        return {
            "category": "registry",
            "artifact_type": "usrclass",
            "output_relative":
                f"users/{username}/UsrClass.dat",
        }

    usrclass_log_match = re.match(
        r"^users/([^/]+)/appdata/local/microsoft/windows/usrclass\.dat\.(log1|log2)$",
        low,
        re.IGNORECASE,
    )

    if usrclass_log_match:
        username = _norm(path).split("/")[1]
        log_name = usrclass_log_match.group(2).upper()

        return {
            "category": "registry",
            "artifact_type": "registry_transaction_log",
            "output_relative":
                f"users/{username}/UsrClass.dat.{log_name}",
        }

    #
    # Prefetch.
    #
    if (
        low.startswith("windows/prefetch/")
        and low.endswith(".pf")
    ):
        return {
            "category": "prefetch",
            "artifact_type": "prefetch",
            "output_relative": basename,
        }

    #
    # Amcache.
    #
    if low == "windows/appcompat/programs/amcache.hve":
        return {
            "category": "amcache",
            "artifact_type": "amcache",
            "output_relative": "Amcache.hve",
        }

    #
    # SRUM.
    #
    if low == "windows/system32/sru/srudb.dat":
        return {
            "category": "srum",
            "artifact_type": "srum",
            "output_relative": "SRUDB.dat",
        }

    #
    # Recent LNK files.
    #
    if (
        low.startswith("users/")
        and "/appdata/roaming/microsoft/windows/recent/" in low
        and low.endswith(".lnk")
        and "/automaticdestinations/" not in low
        and "/customdestinations/" not in low
    ):
        parts = _norm(path).split("/")
        username = parts[1] if len(parts) > 1 else "unknown"

        return {
            "category": "lnk",
            "artifact_type": "lnk",
            "output_relative":
                f"{username}/{basename}",
        }

    #
    # Jump Lists.
    #
    if (
        low.startswith("users/")
        and "/appdata/roaming/microsoft/windows/recent/" in low
        and (
            low.endswith(".automaticdestinations-ms")
            or low.endswith(".customdestinations-ms")
        )
    ):
        parts = _norm(path).split("/")
        username = parts[1] if len(parts) > 1 else "unknown"

        return {
            "category": "jumplists",
            "artifact_type": "jumplist",
            "output_relative":
                f"{username}/{basename}",
        }

    return None


def _discover_on_filesystem(
    image: Path,
    offset_sectors: int,
    filesystem_info: dict[str, Any],
) -> dict[str, Any]:

    records = _fls_recursive(
        image=image,
        offset_sectors=offset_sectors,
    )

    artifacts: list[dict[str, Any]] = []

    counts = {
        key: 0
        for key in CATEGORY_LIMITS
    }

    for record in records:
        #
        # We only collect allocated files automatically.
        #
        if record.get("deleted"):
            continue

        classified = _classify_artifact(record)

        if classified is None:
            continue

        category = classified["category"]

        if counts[category] >= CATEGORY_LIMITS[category]:
            continue

        counts[category] += 1

        artifacts.append(
            {
                **classified,
                "source_path": record["normalized_path"],
                "metadata_address":
                    record["metadata_address"],
                "offset_sectors": offset_sectors,
            }
        )

    return {
        "offset_sectors": offset_sectors,
        "filesystem": filesystem_info,
        "windows_detected": _looks_like_windows(records),
        "filesystem_entry_count": len(records),
        "artifact_count": len(artifacts),
        "artifact_counts": counts,
        "artifacts": artifacts,
    }


def discover_triage_artifacts(
    image_path: str,
    profile: str = "windows_standard",
) -> dict[str, Any]:

    try:
        if profile != "windows_standard":
            raise PolicyError(
                "Only the windows_standard triage profile "
                "is currently approved."
            )

        require_action(
            tool_id="sleuthkit",
            action="filesystem_enumeration",
            required_policy="AUTO",
        )

        validated = validate_image_inspection_request(
            image_path=image_path
        )

        image = Path(validated["image"])

        inspection = inspect_forensic_image(str(image))

        if not inspection.get("success"):
            return inspection

        candidates = _candidate_offsets(inspection)

        if not candidates:
            raise PolicyError(
                "No supported filesystem was discovered "
                "inside the forensic image."
            )

        filesystem_results = []

        for candidate in candidates:
            fs_result = _discover_on_filesystem(
                image=image,
                offset_sectors=candidate["offset_sectors"],
                filesystem_info=candidate["filesystem"],
            )

            filesystem_results.append(fs_result)

        #
        # Pick the filesystem that contains a real Windows installation.
        #
        windows_candidates = [
            fs
            for fs in filesystem_results
            if fs["windows_detected"]
        ]

        selected = None

        if windows_candidates:
            selected = max(
                windows_candidates,
                key=lambda item: item["artifact_count"],
            )

        return {
            "success": True,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "action": "filesystem_enumeration",
            "policy": "AUTO",
            "profile": profile,
            "image_path": str(image),
            "image_layout": inspection.get("layout"),
            "candidate_filesystem_count":
                len(filesystem_results),
            "windows_filesystem_detected":
                selected is not None,
            "selected_offset_sectors":
                (
                    selected["offset_sectors"]
                    if selected
                    else None
                ),
            "artifact_count":
                (
                    selected["artifact_count"]
                    if selected
                    else 0
                ),
            "artifact_counts":
                (
                    selected["artifact_counts"]
                    if selected
                    else {}
                ),
            "artifacts":
                (
                    selected["artifacts"]
                    if selected
                    else []
                ),
            "filesystems": filesystem_results,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "TIMEOUT",
            "error":
                "Filesystem enumeration timed out.",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }


def _safe_output_path(
    root: Path,
    relative_path: str,
) -> Path:

    relative = Path(relative_path)

    if relative.is_absolute():
        raise PolicyError(
            "Absolute artifact output paths are forbidden."
        )

    output = (root / relative).resolve()
    root_resolved = root.resolve()

    try:
        output.relative_to(root_resolved)
    except ValueError:
        raise PolicyError(
            "Artifact output escaped the triage workspace."
        )

    return output


def _extract_one(
    image: Path,
    metadata_address: str,
    offset_sectors: int,
    output_file: Path,
) -> dict[str, Any]:

    if not re.fullmatch(
        r"\d+(?:-\d+){0,3}",
        metadata_address,
    ):
        raise PolicyError(
            f"Invalid metadata address: {metadata_address}"
        )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if output_file.exists():
        raise PolicyError(
            f"Refusing to overwrite existing artifact: "
            f"{output_file}"
        )

    temp_file = output_file.with_suffix(
        output_file.suffix + ".partial"
    )

    if temp_file.exists():
        temp_file.unlink()

    command = [
        str(ICAT),
    ]

    if offset_sectors > 0:
        command.extend(
            [
                "-o",
                str(offset_sectors),
            ]
        )

    command.extend(
        [
            str(image),
            metadata_address,
        ]
    )

    try:
        with temp_file.open("xb") as output_handle:
            completed = subprocess.run(
                command,
                cwd=str(TSK_BIN),
                shell=False,
                stdout=output_handle,
                stderr=subprocess.PIPE,
                timeout=MAX_EXTRACT_SECONDS,
            )

        if completed.returncode != 0:
            temp_file.unlink(missing_ok=True)

            raise RuntimeError(
                completed.stderr.decode(
                    "utf-8",
                    errors="replace",
                )[-4000:]
            )

        temp_file.replace(output_file)

        return {
            "size_bytes": output_file.stat().st_size,
            "sha256": _sha256_file(output_file),
        }

    except Exception:
        temp_file.unlink(missing_ok=True)
        raise


def _create_case_layout(case_id: str) -> dict[str, Path]:
    validate_case_id(case_id)

    case_root = WORKSPACE_ROOT / case_id
    triage_root = case_root / "triage"
    parsed_root = case_root / "parsed"
    provenance_root = case_root / "provenance"

    #
    # Protect existing evidence/results.
    #
    if triage_root.exists():
        existing = list(triage_root.rglob("*"))

        if existing:
            raise PolicyError(
                f"Triage directory is not empty: {triage_root}"
            )

    for relative in STANDARD_DIRECTORIES:
        (triage_root / relative).mkdir(
            parents=True,
            exist_ok=True,
        )

    for parser in [
        "mftecmd",
        "evtxecmd",
        "hayabusa",
        "pecmd",
        "recmd",
    ]:
        (parsed_root / parser).mkdir(
            parents=True,
            exist_ok=True,
        )

    provenance_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    return {
        "case_root": case_root,
        "triage_root": triage_root,
        "parsed_root": parsed_root,
        "provenance_root": provenance_root,
    }


def collect_triage_artifacts(
    image_path: str,
    case_id: str,
    profile: str = "windows_standard",
) -> dict[str, Any]:

    try:
        #
        # IMPORTANT:
        # Perform all discovery/policy validation BEFORE creating
        # the case workspace.
        #
        require_action(
            tool_id="sleuthkit",
            action="single_file_extraction_to_workspace",
            required_policy="AUTO",
        )

        discovery = discover_triage_artifacts(
            image_path=image_path,
            profile=profile,
        )

        if not discovery.get("success"):
            return discovery

        if not discovery.get(
            "windows_filesystem_detected"
        ):
            raise PolicyError(
                "No Windows filesystem was identified. "
                "Triage collection was not started."
            )

        artifacts = discovery.get("artifacts") or []

        if not artifacts:
            raise PolicyError(
                "No approved triage artifacts were discovered."
            )

        validate_case_id(case_id)

        image = Path(discovery["image_path"])

        layout = _create_case_layout(case_id)
        triage_root = layout["triage_root"]

        provenance_records = []

        failures = []

        for artifact in artifacts:
            category = artifact["category"]

            output_relative = artifact[
                "output_relative"
            ]

            output_file = _safe_output_path(
                triage_root / category,
                output_relative,
            )

            try:
                extracted = _extract_one(
                    image=image,
                    metadata_address=
                        artifact["metadata_address"],
                    offset_sectors=
                        artifact["offset_sectors"],
                    output_file=output_file,
                )

                provenance_records.append(
                    {
                        "artifact_type":
                            artifact["artifact_type"],
                        "category": category,
                        "source_image": str(image),
                        "filesystem_offset_sectors":
                            artifact["offset_sectors"],
                        "original_path":
                            artifact["source_path"],
                        "tsk_metadata_address":
                            artifact["metadata_address"],
                        "output_path":
                            str(output_file),
                        "size_bytes":
                            extracted["size_bytes"],
                        "sha256":
                            extracted["sha256"],
                        "collector": "sleuthkit",
                        "source_modified": False,
                    }
                )

            except Exception as exc:
                failures.append(
                    {
                        "artifact":
                            artifact["source_path"],
                        "metadata_address":
                            artifact["metadata_address"],
                        "error": str(exc),
                    }
                )

        manifest = {
            "schema_version": "1.0",
            "case_id": case_id,
            "profile": profile,
            "source_image": str(image),
            "source_modified": False,
            "filesystem_offset_sectors":
                discovery.get(
                    "selected_offset_sectors"
                ),
            "artifact_count":
                len(provenance_records),
            "failure_count": len(failures),
            "artifacts": provenance_records,
            "failures": failures,
        }

        manifest_file = (
            layout["provenance_root"]
            / "triage_manifest.json"
        )

        manifest_file.write_text(
            json.dumps(
                manifest,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return {
            "success": len(provenance_records) > 0,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "action":
                "single_file_extraction_to_workspace",
            "policy": "AUTO",
            "case_id": case_id,
            "profile": profile,
            "source_image": str(image),
            "filesystem_offset_sectors":
                discovery.get(
                    "selected_offset_sectors"
                ),
            "artifact_count":
                len(provenance_records),
            "failure_count": len(failures),
            "artifact_counts":
                discovery.get("artifact_counts"),
            "triage_directory":
                str(layout["triage_root"]),
            "parsed_directory":
                str(layout["parsed_root"]),
            "manifest":
                str(manifest_file),
            "failures": failures,
            "original_evidence_modified": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "TIMEOUT",
            "error":
                "Triage collection timed out.",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "triage_collector",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }

