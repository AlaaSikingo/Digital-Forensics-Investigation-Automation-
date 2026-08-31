from __future__ import annotations

from pathlib import Path
import re
import subprocess

from policy import PolicyError, require_action


TSK_BIN = (Path(__file__).resolve().parents[2] / "tools" / "disk" / "SleuthKit" / "bin")

IMG_STAT = TSK_BIN / "img_stat.exe"
MMLS = TSK_BIN / "mmls.exe"
FSSTAT = TSK_BIN / "fsstat.exe"

ALLOWED_IMAGE_ROOTS = [
    (Path(__file__).resolve().parents[2] / "evidence"),
    (Path(__file__).resolve().parents[2] / "test" / "images"),
    (Path(__file__).resolve().parents[2] / "workspace"),
]

ALLOWED_EXTENSIONS = {
    ".e01",
    ".ex01",
    ".raw",
    ".dd",
    ".img",
    ".vmdk",
    ".vhd",
}

MAX_PARTITIONS_TO_PROBE = 32


def _is_under_allowed_root(path: Path) -> bool:
    path = path.resolve()

    for root in ALLOWED_IMAGE_ROOTS:
        root = root.resolve()

        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue

    return False


def _validate_image_path(image_path: str) -> Path:
    image = Path(image_path).resolve()

    if not image.exists():
        raise PolicyError(
            f"Forensic image does not exist: {image}"
        )

    if not image.is_file():
        raise PolicyError(
            "Forensic image inspection requires an offline image file"
        )

    if not _is_under_allowed_root(image):
        raise PolicyError(
            f"Image is outside approved offline evidence roots: {image}"
        )

    if image.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise PolicyError(
            f"Unsupported AUTO image extension: {image.suffix}"
        )

    return image


def _run(command: list[str], timeout: int = 120) -> dict:
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
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
    }


def _extract_value(text: str, pattern: str):
    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )

    if not match:
        return None

    return match.group(1).strip()


def _parse_img_stat(text: str) -> dict:
    logical_size = _extract_value(
        text,
        r"Size of data in bytes:\s*(\d+)",
    )

    sector_size = _extract_value(
        text,
        r"Sector size:\s*(\d+)",
    )

    return {
        "image_type": _extract_value(
            text,
            r"Image Type:\s*([^\r\n]+)",
        ),
        "logical_size_bytes": (
            int(logical_size)
            if logical_size is not None
            else None
        ),
        "sector_size": (
            int(sector_size)
            if sector_size is not None
            else None
        ),
        "logical_data_md5": _extract_value(
            text,
            r"MD5 hash of data:\s*([0-9a-fA-F]+)",
        ),
    }


def _parse_fsstat(text: str) -> dict:
    sector_size = _extract_value(
        text,
        r"^Sector Size:\s*(\d+)",
    )

    cluster_size = _extract_value(
        text,
        r"^Cluster Size:\s*(\d+)",
    )

    return {
        "filesystem_type": _extract_value(
            text,
            r"^File System Type:\s*(.+)$",
        ),
        "volume_name": _extract_value(
            text,
            r"^Volume Name:\s*(.*)$",
        ),
        "volume_serial_number": _extract_value(
            text,
            r"^Volume Serial Number:\s*(.+)$",
        ),
        "sector_size": (
            int(sector_size)
            if sector_size is not None
            else None
        ),
        "cluster_size": (
            int(cluster_size)
            if cluster_size is not None
            else None
        ),
    }


def _parse_mmls(text: str) -> list[dict]:
    partitions = []

    line_regex = re.compile(
        r"^\s*"
        r"(?P<index>\d+):\s+"
        r"(?P<slot>\S+)\s+"
        r"(?P<start>\d+)\s+"
        r"(?P<end>\d+)\s+"
        r"(?P<length>\d+)\s+"
        r"(?P<description>.+?)\s*$"
    )

    for line in text.splitlines():
        match = line_regex.match(line)

        if not match:
            continue

        slot = match.group("slot")
        description = match.group("description").strip()

        # mmls also reports metadata and unallocated ranges.
        # They are useful for raw output, but they are not
        # filesystem partitions that AUTO should probe.
        if slot.lower() in {
            "meta",
            "-------",
        }:
            continue

        if "unallocated" in description.lower():
            continue

        partitions.append({
            "index": int(match.group("index")),
            "slot": slot,
            "start_sector": int(match.group("start")),
            "end_sector": int(match.group("end")),
            "length_sectors": int(match.group("length")),
            "description": description,
        })

    return partitions


def validate_image_inspection_request(
    image_path: str,
) -> dict:

    tool = require_action(
        tool_id="sleuthkit",
        action="offline_image_inspection",
        required_policy="AUTO",
    )

    image = _validate_image_path(image_path)

    return {
        "tool": tool,
        "image": str(image),
    }


def inspect_forensic_image(
    image_path: str,
) -> dict:

    try:
        validated = validate_image_inspection_request(
            image_path
        )

        image = Path(validated["image"])

        for executable in [
            IMG_STAT,
            MMLS,
            FSSTAT,
        ]:
            if not executable.exists():
                raise PolicyError(
                    f"Required Sleuth Kit executable not found: "
                    f"{executable}"
                )

        #
        # 1. Image/container information
        #
        img_stat_result = _run([
            str(IMG_STAT),
            str(image),
        ])

        if img_stat_result["exit_code"] != 0:
            return {
                "success": False,
                "tool": "sleuthkit",
                "component": "image_access",
                "action": "offline_image_inspection",
                "error_type": "IMAGE_INSPECTION_FAILED",
                "error": (
                    img_stat_result["stderr"]
                    or img_stat_result["stdout"]
                ),
            }

        image_info = _parse_img_stat(
            img_stat_result["stdout"]
        )

        #
        # 2. Check for filesystem directly at offset 0.
        #
        fsstat_zero_result = _run([
            str(FSSTAT),
            str(image),
        ])

        offset_zero_detected = (
            fsstat_zero_result["exit_code"] == 0
            and "File System Type:"
            in fsstat_zero_result["stdout"]
        )

        offset_zero_fs = None

        if offset_zero_detected:
            offset_zero_fs = _parse_fsstat(
                fsstat_zero_result["stdout"]
            )

        #
        # 3. Inspect partition table.
        #
        mmls_result = _run([
            str(MMLS),
            str(image),
        ])

        partition_entries = []

        if mmls_result["stdout"].strip():
            partition_entries = _parse_mmls(
                mmls_result["stdout"]
            )

        #
        # 4. Probe discovered allocated partitions.
        #
        discovered_filesystems = []

        for partition in partition_entries[
            :MAX_PARTITIONS_TO_PROBE
        ]:
            offset = partition["start_sector"]

            fs_result = _run([
                str(FSSTAT),
                "-o",
                str(offset),
                str(image),
            ])

            detected = (
                fs_result["exit_code"] == 0
                and "File System Type:"
                in fs_result["stdout"]
            )

            filesystem = None

            if detected:
                filesystem = _parse_fsstat(
                    fs_result["stdout"]
                )

                discovered_filesystems.append({
                    "partition_index":
                        partition["index"],
                    "slot":
                        partition["slot"],
                    "offset_sectors":
                        offset,
                    "description":
                        partition["description"],
                    **filesystem,
                })

            partition["filesystem_detected"] = detected
            partition["filesystem"] = filesystem
            partition["fsstat_exit_code"] = (
                fs_result["exit_code"]
            )

        if offset_zero_detected:
            image_layout = "volume_level"
        elif discovered_filesystems:
            image_layout = "partitioned_disk"
        elif partition_entries:
            image_layout = (
                "partitioned_disk_no_supported_filesystem"
            )
        else:
            image_layout = "unknown"

        return {
            "success": True,
            "tool": "sleuthkit",
            "component": "image_access",
            "action": "offline_image_inspection",
            "policy": "AUTO",

            "image_path": str(image),

            # Physical size of the container file itself.
            "container_size_bytes":
                image.stat().st_size,

            "image_extension":
                image.suffix.lower(),

            "image_info":
                image_info,

            "layout":
                image_layout,

            "offset_zero_filesystem": {
                "detected":
                    offset_zero_detected,
                "offset_sectors":
                    0,
                "filesystem":
                    offset_zero_fs,
                "exit_code":
                    fsstat_zero_result["exit_code"],
            },

            "partition_table": {
                "detected":
                    bool(partition_entries),
                "mmls_exit_code":
                    mmls_result["exit_code"],
                "partition_count":
                    len(partition_entries),
                "partitions":
                    partition_entries,
            },

            "discovered_filesystems":
                discovered_filesystems,

            "raw_tool_output": {
                "img_stat":
                    img_stat_result["stdout"][-12000:],
                "mmls":
                    mmls_result["stdout"][-12000:],
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "TIMEOUT",
            "error":
                "Sleuth Kit image inspection timed out",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest().upper()


def validate_image_artifact_extraction_request(
    image_path: str,
    metadata_address: str,
) -> dict:

    tool = require_action(
        tool_id="sleuthkit",
        action="single_file_extraction_to_workspace",
        required_policy="AUTO",
    )

    image = _validate_image_path(image_path)

    #
    # TSK metadata addresses can look like:
    #   0
    #   128
    #   0-128-6
    #
    # Do not allow arbitrary command-line material here.
    #
    if not re.fullmatch(
        r"\d+(?:-\d+){0,2}",
        metadata_address,
    ):
        raise PolicyError(
            "Invalid Sleuth Kit metadata address"
        )

    return {
        "tool": tool,
        "image": str(image),
        "metadata_address": metadata_address,
    }


def extract_image_artifact(
    image_path: str,
    metadata_address: str,
    artifact_name: str,
    case_id: str,
    offset_sectors: int = 0,
) -> dict:

    try:
        validated = (
            validate_image_artifact_extraction_request(
                image_path=image_path,
                metadata_address=metadata_address,
            )
        )

        image = Path(validated["image"])

        if not isinstance(offset_sectors, int):
            raise PolicyError(
                "offset_sectors must be an integer"
            )

        if offset_sectors < 0:
            raise PolicyError(
                "offset_sectors cannot be negative"
            )

        #
        # Keep the output name narrow and safe.
        #
        if not artifact_name:
            raise PolicyError(
                "artifact_name is required"
            )

        if artifact_name in {".", ".."}:
            raise PolicyError(
                "Invalid artifact name"
            )

        if "/" in artifact_name or "\\" in artifact_name:
            raise PolicyError(
                "artifact_name must be a file name, not a path"
            )

        if ":" in artifact_name:
            raise PolicyError(
                "artifact_name cannot contain ':'"
            )

        if not re.fullmatch(
            r"[A-Za-z0-9_$%().+\- ]{1,180}",
            artifact_name,
        ):
            raise PolicyError(
                "artifact_name contains unsupported characters"
            )

        ICAT = TSK_BIN / "icat.exe"

        if not ICAT.exists():
            raise PolicyError(
                f"icat executable not found: {ICAT}"
            )

        #
        # Use the same central case validation/output mechanism
        # already used by the other executors.
        #
        from policy import get_case_output_directory

        artifact_root = get_case_output_directory(
            case_id=case_id,
            tool_name="artifacts",
        )

        output_dir = artifact_root / "image_extracted"

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = output_dir / artifact_name

        #
        # Never overwrite an existing artifact.
        #
        if output_file.exists():
            raise PolicyError(
                f"Artifact output already exists: {output_file}"
            )

        command = [
            str(ICAT),
        ]

        if offset_sectors > 0:
            command.extend([
                "-o",
                str(offset_sectors),
            ])

        command.extend([
            str(image),
            validated["metadata_address"],
        ])

        #
        # Binary output: do NOT use text=True and do NOT route
        # through PowerShell/cmd redirection.
        #
        completed = subprocess.run(
            command,
            cwd=str(TSK_BIN),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,
        )

        if completed.returncode != 0:
            if output_file.exists():
                output_file.unlink()

            return {
                "success": False,
                "tool": "sleuthkit",
                "component": "image_access",
                "action":
                    "single_file_extraction_to_workspace",
                "policy": "AUTO",
                "error_type": "EXTRACTION_FAILED",
                "exit_code": completed.returncode,
                "stderr": completed.stderr.decode(
                    "utf-8",
                    errors="replace",
                )[-8000:],
            }

        if not completed.stdout:
            return {
                "success": False,
                "tool": "sleuthkit",
                "component": "image_access",
                "action":
                    "single_file_extraction_to_workspace",
                "policy": "AUTO",
                "error_type": "EMPTY_ARTIFACT",
                "error":
                    "icat returned an empty artifact",
            }

        #
        # Write only after successful icat execution.
        #
        with output_file.open("xb") as handle:
            handle.write(completed.stdout)

        size = output_file.stat().st_size
        sha256 = _sha256_file(output_file)

        return {
            "success": True,
            "tool": "sleuthkit",
            "component": "image_access",
            "tool_version": "4.15.0",
            "action":
                "single_file_extraction_to_workspace",
            "policy": "AUTO",

            "source_image": str(image),
            "offset_sectors": offset_sectors,
            "metadata_address":
                validated["metadata_address"],

            "artifact_name": artifact_name,
            "output_file": str(output_file),
            "output_size_bytes": size,
            "sha256": sha256,

            "exit_code": completed.returncode,
            "original_evidence_modified": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "TIMEOUT",
            "error":
                "Sleuth Kit artifact extraction timed out",
        }

    except PolicyError as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "POLICY_BLOCK",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "success": False,
            "tool": "sleuthkit",
            "component": "image_access",
            "error_type": "EXECUTION_ERROR",
            "error": str(exc),
        }
