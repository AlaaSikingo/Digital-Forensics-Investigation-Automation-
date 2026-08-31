from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import re

from policy import PolicyError, validate_case_id


WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace").resolve()
SCHEMA_VERSION = "1.0"


def _latest_file(directory: Path, pattern: str) -> Path:
    files = [
        p for p in directory.glob(pattern)
        if p.is_file()
    ]

    if not files:
        raise PolicyError(
            f"No parser output matching {pattern} in {directory}"
        )

    return max(
        files,
        key=lambda p: (p.stat().st_mtime_ns, p.name),
    ).resolve()


def _latest_recmd_run(directory: Path) -> list[Path]:
    files = [
        p for p in directory.glob("recmd_*.csv")
        if p.is_file()
    ]

    if not files:
        raise PolicyError(
            f"No RECmd CSV outputs found in {directory}"
        )

    groups: dict[str, list[Path]] = {}

    pattern = re.compile(
        r"^(recmd_\d{8}T\d{6}Z)_",
        re.IGNORECASE,
    )

    for path in files:
        match = pattern.match(path.name)

        if match:
            groups.setdefault(
                match.group(1),
                [],
            ).append(path)

    if not groups:
        raise PolicyError(
            "Could not identify a complete RECmd run"
        )

    latest_prefix = max(groups.keys())

    return sorted(
        [p.resolve() for p in groups[latest_prefix]],
        key=lambda p: p.name.lower(),
    )


def discover_normalization_inputs(case_id: str) -> dict[str, Any]:
    case_id = validate_case_id(case_id)

    case_root = (
        WORKSPACE_ROOT / case_id
    ).resolve()

    parsed_root = (
        case_root / "parsed"
    ).resolve()

    try:
        parsed_root.relative_to(case_root)
    except ValueError:
        raise PolicyError(
            "Parsed evidence path escapes case workspace"
        )

    if not parsed_root.is_dir():
        raise PolicyError(
            f"Parsed directory does not exist: {parsed_root}"
        )

    mftecmd = _latest_file(
        parsed_root / "mftecmd",
        "mftecmd_*.csv",
    )

    evtxecmd = _latest_file(
        parsed_root / "evtxecmd",
        "evtxecmd_*.csv",
    )

    # Exclude PECmd timeline CSV. The main PECmd CSV contains
    # the richer execution record and previous-run timestamps.
    pecmd_candidates = [
        p for p in (parsed_root / "pecmd").glob(
            "pecmd_*.csv"
        )
        if (
            p.is_file()
            and not p.name.lower().endswith(
                "_timeline.csv"
            )
        )
    ]

    pecmd = None

    if pecmd_candidates:
        pecmd = max(
            pecmd_candidates,
            key=lambda p: (
                p.stat().st_mtime_ns,
                p.name,
            ),
        ).resolve()

    recmd = _latest_recmd_run(
        parsed_root / "recmd"
    )

    lecmd = _latest_file(
        parsed_root / "lecmd",
        "lecmd_*.csv",
    )

    hayabusa = _latest_file(
        parsed_root / "hayabusa",
        "timeline_*.jsonl",
    )

    return {
        "case_id": case_id,
        "parsed_root": str(parsed_root),
        "inputs": {
            "mftecmd": str(mftecmd),
            "evtxecmd": str(evtxecmd),
            "pecmd": (
                str(pecmd)
                if pecmd is not None
                else None
            ),
            "recmd": [
                str(p) for p in recmd
            ],
            "lecmd": str(lecmd),
            "hayabusa": str(hayabusa),
        },
        "recmd_file_count": len(recmd),
    }


def make_event(
    *,
    case_id: str,
    timestamp: str,
    timestamp_type: str,
    timestamp_source: str,
    artifact_type: str,
    event_type: str,
    source_tool: str,
    parser_output: str,
    source_evidence: str,
    source_row: int,
    identity_discriminator: str = "",
    **fields: Any,
) -> dict[str, Any]:

    identity = "|".join([
        case_id,
        source_tool,
        parser_output,
        str(source_row),
        timestamp_type,
        timestamp,
        event_type,
    ])

    # Backward-compatible identity extension.
    #
    # Existing adapters that do not supply a discriminator
    # retain their original deterministic event_uid exactly.
    #
    # Adapters that emit multiple distinct observations with
    # otherwise identical identity fields may supply one.
    if identity_discriminator:
        identity = (
            identity
            + "|"
            + identity_discriminator
        )

    event_uid = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()

    event = {
        "schema_version": SCHEMA_VERSION,
        "event_uid": event_uid,
        "case_id": case_id,

        "timestamp": timestamp,
        "timestamp_type": timestamp_type,
        "timestamp_source": timestamp_source,

        "artifact_type": artifact_type,
        "event_type": event_type,
        "source_tool": source_tool,

        "hostname": "",
        "username": "",

        "executable": "",
        "process_id": "",
        "command_line": "",

        "path": "",
        "target_path": "",

        "windows_event_id": "",
        "provider": "",
        "channel": "",

        "registry_hive": "",
        "registry_key": "",
        "registry_value_name": "",
        "registry_value_data": "",

        "mft_entry": "",
        "mft_sequence": "",

        "detection_rule": "",
        "severity": "",

        "description": "",
        "attributes": {},

        "provenance": {
            "parser": source_tool,
            "parser_output": parser_output,
            "source_evidence": source_evidence,
            "source_row": source_row,
        },
    }

    for key, value in fields.items():
        if key not in event:
            raise ValueError(
                f"Unknown normalized field: {key}"
            )

        event[key] = value

    return event


def validate_normalization_request(
    case_id: str,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    return {
        "success": True,
        "component": "normalizer",
        "schema_version": SCHEMA_VERSION,
        **discovered,
    }



# ============================================================
# MFTECmd NORMALIZATION
# ============================================================

import csv


MFT_TIMESTAMP_FIELDS = {
    "Created0x10": (
        "FILE_CREATED",
        "STANDARD_INFORMATION",
    ),
    "Created0x30": (
        "FILE_CREATED",
        "FILE_NAME",
    ),
    "LastModified0x10": (
        "FILE_MODIFIED",
        "STANDARD_INFORMATION",
    ),
    "LastModified0x30": (
        "FILE_MODIFIED",
        "FILE_NAME",
    ),
    "LastRecordChange0x10": (
        "FILE_RECORD_CHANGED",
        "STANDARD_INFORMATION",
    ),
    "LastRecordChange0x30": (
        "FILE_RECORD_CHANGED",
        "FILE_NAME",
    ),
    "LastAccess0x10": (
        "FILE_ACCESSED",
        "STANDARD_INFORMATION",
    ),
    "LastAccess0x30": (
        "FILE_ACCESSED",
        "FILE_NAME",
    ),
}


def _mft_path(row: dict[str, str]) -> str:
    parent = (row.get("ParentPath") or "").strip()
    name = (row.get("FileName") or "").strip()

    if not parent or parent == ".":
        return name

    if parent.endswith("\\"):
        return f"{parent}{name}"

    return f"{parent}\\{name}"


def iter_mftecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
    start_row: int = 2,
):

    source = Path(csv_path).resolve()

    if not source.is_file():
        raise PolicyError(
            f"MFTECmd CSV does not exist: {source}"
        )

    with source.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "EntryNumber",
            "SequenceNumber",
            "ParentPath",
            "FileName",
            "SourceFile",
            *MFT_TIMESTAMP_FIELDS.keys(),
        }

        actual = set(reader.fieldnames or [])

        missing = required - actual

        if missing:
            raise PolicyError(
                "MFTECmd CSV missing required fields: "
                + ", ".join(sorted(missing))
            )

        if start_row < 2:
            raise PolicyError(
                "MFTECmd start_row cannot be less than 2"
            )

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            if (
                max_rows is not None
                and row_number > max_rows + 1
            ):
                break

            if row_number < start_row:
                continue

            path = _mft_path(row)

            source_evidence = (
                row.get("SourceFile") or ""
            ).strip()

            attributes = {
                "sequence_number":
                    (row.get("SequenceNumber") or "").strip(),

                "parent_entry_number":
                    (row.get("ParentEntryNumber") or "").strip(),

                "parent_sequence_number":
                    (row.get("ParentSequenceNumber") or "").strip(),

                "file_name":
                    (row.get("FileName") or "").strip(),

                "extension":
                    (row.get("Extension") or "").strip(),

                "file_size":
                    (row.get("FileSize") or "").strip(),

                "in_use":
                    (row.get("InUse") or "").strip(),

                "is_directory":
                    (row.get("IsDirectory") or "").strip(),

                "has_ads":
                    (row.get("HasAds") or "").strip(),

                "is_ads":
                    (row.get("IsAds") or "").strip(),

                "si_less_than_fn":
                    (row.get("SI<FN") or "").strip(),

                "copied":
                    (row.get("Copied") or "").strip(),

                "si_flags":
                    (row.get("SiFlags") or "").strip(),

                "name_type":
                    (row.get("NameType") or "").strip(),

                "update_sequence_number":
                    (row.get("UpdateSequenceNumber") or "").strip(),

                "logfile_sequence_number":
                    (row.get("LogfileSequenceNumber") or "").strip(),

                "zone_id_contents":
                    (row.get("ZoneIdContents") or "").strip(),
            }

            for timestamp_field, (
                event_type,
                timestamp_origin,
            ) in MFT_TIMESTAMP_FIELDS.items():

                timestamp = (
                    row.get(timestamp_field) or ""
                ).strip()

                if not timestamp:
                    continue

                event = make_event(
                    case_id=case_id,
                    timestamp=timestamp,
                    timestamp_type=event_type,
                    timestamp_source=(
                        f"MFT.{timestamp_field}"
                    ),
                    artifact_type="mft",
                    event_type=event_type,
                    source_tool="mftecmd",
                    parser_output=str(source),
                    source_evidence=source_evidence,
                    source_row=row_number,
                    path=path,
                    mft_entry=(
                        row.get("EntryNumber") or ""
                    ).strip(),
                    mft_sequence=(
                        row.get("SequenceNumber") or ""
                    ).strip(),
                    description=(
                        f"{event_type} timestamp from "
                        f"{timestamp_origin}"
                    ),
                    attributes={
                        **attributes,
                        "timestamp_origin":
                            timestamp_origin,
                        "timestamp_field":
                            timestamp_field,
                    },
                )

                yield event


def normalize_mftecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:

    return list(
        iter_mftecmd(
            case_id,
            csv_path,
            max_rows=max_rows,
        )
    )

def write_mftecmd_jsonl(
    case_id: str,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    source = Path(
        discovered["inputs"]["mftecmd"]
    ).resolve()

    case_root = (
        WORKSPACE_ROOT / case_id
    ).resolve()

    output_dir = (
        case_root / "normalized"
    ).resolve()

    try:
        output_dir.relative_to(case_root)
    except ValueError:
        raise PolicyError(
            "Normalized output path escapes case workspace"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        output_dir / "mftecmd.jsonl"
    ).resolve()

    partial_file = (
        output_dir / "mftecmd.jsonl.partial"
    ).resolve()

    if output_file.exists():
        raise PolicyError(
            f"Normalized output already exists: {output_file}"
        )

    if partial_file.exists():
        partial_file.unlink()

    source_rows = 0
    event_count = 0

    try:
        with source.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline="",
        ) as input_handle, partial_file.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output_handle:

            reader = csv.DictReader(
                input_handle
            )

            required = {
                "EntryNumber",
                "SequenceNumber",
                "ParentPath",
                "FileName",
                "SourceFile",
                *MFT_TIMESTAMP_FIELDS.keys(),
            }

            actual = set(
                reader.fieldnames or []
            )

            missing = required - actual

            if missing:
                raise PolicyError(
                    "MFTECmd CSV missing required fields: "
                    + ", ".join(
                        sorted(missing)
                    )
                )

            for row_number, row in enumerate(
                reader,
                start=2,
            ):
                source_rows += 1

                path = _mft_path(row)

                source_evidence = (
                    row.get("SourceFile") or ""
                ).strip()

                base_attributes = {
                    "sequence_number":
                        (row.get("SequenceNumber") or "").strip(),

                    "parent_entry_number":
                        (row.get("ParentEntryNumber") or "").strip(),

                    "parent_sequence_number":
                        (row.get("ParentSequenceNumber") or "").strip(),

                    "file_name":
                        (row.get("FileName") or "").strip(),

                    "extension":
                        (row.get("Extension") or "").strip(),

                    "file_size":
                        (row.get("FileSize") or "").strip(),

                    "in_use":
                        (row.get("InUse") or "").strip(),

                    "is_directory":
                        (row.get("IsDirectory") or "").strip(),

                    "has_ads":
                        (row.get("HasAds") or "").strip(),

                    "is_ads":
                        (row.get("IsAds") or "").strip(),

                    "si_less_than_fn":
                        (row.get("SI<FN") or "").strip(),

                    "copied":
                        (row.get("Copied") or "").strip(),

                    "si_flags":
                        (row.get("SiFlags") or "").strip(),

                    "name_type":
                        (row.get("NameType") or "").strip(),

                    "update_sequence_number":
                        (row.get("UpdateSequenceNumber") or "").strip(),

                    "logfile_sequence_number":
                        (row.get("LogfileSequenceNumber") or "").strip(),

                    "zone_id_contents":
                        (row.get("ZoneIdContents") or "").strip(),
                }

                for timestamp_field, (
                    event_type,
                    timestamp_origin,
                ) in MFT_TIMESTAMP_FIELDS.items():

                    timestamp = (
                        row.get(timestamp_field)
                        or ""
                    ).strip()

                    if not timestamp:
                        continue

                    event = make_event(
                        case_id=case_id,
                        timestamp=timestamp,
                        timestamp_type=event_type,
                        timestamp_source=(
                            f"MFT.{timestamp_field}"
                        ),
                        artifact_type="mft",
                        event_type=event_type,
                        source_tool="mftecmd",
                        parser_output=str(source),
                        source_evidence=source_evidence,
                        source_row=row_number,
                        path=path,
                        mft_entry=(
                            row.get("EntryNumber")
                            or ""
                        ).strip(),
                        mft_sequence=(
                            row.get("SequenceNumber")
                            or ""
                        ).strip(),
                        description=(
                            f"{event_type} timestamp from "
                            f"{timestamp_origin}"
                        ),
                        attributes={
                            **base_attributes,
                            "timestamp_origin":
                                timestamp_origin,
                            "timestamp_field":
                                timestamp_field,
                        },
                    )

                    output_handle.write(
                        json.dumps(
                            event,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    event_count += 1

        partial_file.replace(
            output_file
        )

    except Exception:
        if partial_file.exists():
            partial_file.unlink()
        raise

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "mftecmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": str(source),
        "output_file": str(output_file),
        "source_rows": source_rows,
        "normalized_event_count":
            event_count,
        "output_size_bytes":
            output_file.stat().st_size,
    }

def test_mftecmd_normalization(
    case_id: str,
    max_rows: int = 3,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    csv_path = discovered["inputs"]["mftecmd"]

    events = normalize_mftecmd(
        case_id,
        csv_path,
        max_rows=max_rows,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "mftecmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": csv_path,
        "rows_requested": max_rows,
        "normalized_event_count": len(events),
        "events": events,
    }


# ============================================================
# EvtxECmd NORMALIZATION
# ============================================================

def iter_evtxecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
    start_row: int = 2,
):

    source = Path(csv_path).resolve()

    if not source.is_file():
        raise PolicyError(
            f"EvtxECmd CSV does not exist: {source}"
        )

    if start_row < 2:
        raise PolicyError(
            "EvtxECmd start_row must be >= 2"
        )

    with source.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "RecordNumber",
            "EventRecordId",
            "TimeCreated",
            "EventId",
            "Provider",
            "Channel",
            "ProcessId",
            "Computer",
            "UserName",
            "RemoteHost",
            "SourceFile",
            "Payload",
        }

        actual = set(reader.fieldnames or [])
        missing = required - actual

        if missing:
            raise PolicyError(
                "EvtxECmd CSV missing required fields: "
                + ", ".join(sorted(missing))
            )

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            if (
                max_rows is not None
                and row_number > max_rows + 1
            ):
                break

            if row_number < start_row:
                continue

            timestamp = (
                row.get("TimeCreated") or ""
            ).strip()

            # An EVTX record without TimeCreated is retained
            # later as parser-quality information, but it cannot
            # participate in the normalized timeline.
            if not timestamp:
                continue

            event_id = (
                row.get("EventId") or ""
            ).strip()

            provider = (
                row.get("Provider") or ""
            ).strip()

            channel = (
                row.get("Channel") or ""
            ).strip()

            payload_data = {}

            for n in range(1, 7):
                key = f"PayloadData{n}"
                value = (
                    row.get(key) or ""
                ).strip()

                if value:
                    payload_data[key] = value

            attributes = {
                "record_number":
                    (row.get("RecordNumber") or "").strip(),

                "event_record_id":
                    (row.get("EventRecordId") or "").strip(),

                "level":
                    (row.get("Level") or "").strip(),

                "thread_id":
                    (row.get("ThreadId") or "").strip(),

                "chunk_number":
                    (row.get("ChunkNumber") or "").strip(),

                "user_id":
                    (row.get("UserId") or "").strip(),

                "map_description":
                    (row.get("MapDescription") or "").strip(),

                "remote_host":
                    (row.get("RemoteHost") or "").strip(),

                "executable_info":
                    (row.get("ExecutableInfo") or "").strip(),

                "hidden_record":
                    (row.get("HiddenRecord") or "").strip(),

                "keywords":
                    (row.get("Keywords") or "").strip(),

                "extra_data_offset":
                    (row.get("ExtraDataOffset") or "").strip(),

                "payload_data": payload_data,

                # Preserve raw EvtxECmd payload. Do not interpret
                # its event-specific structure in normalization v1.
                "payload":
                    (row.get("Payload") or "").strip(),
            }

            event = make_event(
                case_id=case_id,
                timestamp=timestamp,
                timestamp_type="EVENT_CREATED",
                timestamp_source="EVTX.TimeCreated",
                artifact_type="evtx",
                event_type="WINDOWS_EVENT",
                source_tool="evtxecmd",
                parser_output=str(source),
                source_evidence=(
                    row.get("SourceFile") or ""
                ).strip(),
                source_row=row_number,

                hostname=(
                    row.get("Computer") or ""
                ).strip(),

                username=(
                    row.get("UserName") or ""
                ).strip(),

                process_id=(
                    row.get("ProcessId") or ""
                ).strip(),

                windows_event_id=event_id,
                provider=provider,
                channel=channel,

                description=(
                    f"Windows Event ID {event_id}"
                    if event_id
                    else "Windows event"
                ),

                attributes=attributes,
            )

            yield event


def normalize_evtxecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:

    return list(
        iter_evtxecmd(
            case_id,
            csv_path,
            max_rows=max_rows,
        )
    )


def test_evtxecmd_normalization(
    case_id: str,
    max_rows: int = 3,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    csv_path = discovered["inputs"]["evtxecmd"]

    events = normalize_evtxecmd(
        case_id,
        csv_path,
        max_rows=max_rows,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "evtxecmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": csv_path,
        "rows_requested": max_rows,
        "normalized_event_count": len(events),
        "events": events,
    }


# ============================================================
# PECmd NORMALIZATION
# ============================================================

PREFETCH_RUN_FIELDS = [
    "LastRun",
    "PreviousRun0",
    "PreviousRun1",
    "PreviousRun2",
    "PreviousRun3",
    "PreviousRun4",
    "PreviousRun5",
    "PreviousRun6",
]


def iter_pecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
    start_row: int = 2,
):

    source = Path(csv_path).resolve()

    if not source.is_file():
        raise PolicyError(
            f"PECmd CSV does not exist: {source}"
        )


    if start_row < 2:
        raise PolicyError(
            "start_row must be >= 2"
        )

    with source.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "SourceFilename",
            "ExecutableName",
            "Hash",
            "RunCount",
            "LastRun",
            *PREFETCH_RUN_FIELDS,
        }

        actual = set(reader.fieldnames or [])
        missing = required - actual

        if missing:
            raise PolicyError(
                "PECmd CSV missing required fields: "
                + ", ".join(sorted(missing))
            )

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            if row_number < start_row:
                continue
            if (
                max_rows is not None
                and row_number > max_rows + 1
            ):
                break

            executable = (
                row.get("ExecutableName") or ""
            ).strip()

            source_evidence = (
                row.get("SourceFilename") or ""
            ).strip()

            attributes = {
                "prefetch_hash":
                    (row.get("Hash") or "").strip(),

                "run_count":
                    (row.get("RunCount") or "").strip(),

                "prefetch_version":
                    (row.get("Version") or "").strip(),

                "prefetch_size":
                    (row.get("Size") or "").strip(),

                "source_created":
                    (row.get("SourceCreated") or "").strip(),

                "source_modified":
                    (row.get("SourceModified") or "").strip(),

                "source_accessed":
                    (row.get("SourceAccessed") or "").strip(),

                "volume0_name":
                    (row.get("Volume0Name") or "").strip(),

                "volume0_serial":
                    (row.get("Volume0Serial") or "").strip(),

                "volume0_created":
                    (row.get("Volume0Created") or "").strip(),

                "volume1_name":
                    (row.get("Volume1Name") or "").strip(),

                "volume1_serial":
                    (row.get("Volume1Serial") or "").strip(),

                "volume1_created":
                    (row.get("Volume1Created") or "").strip(),

                "directories":
                    (row.get("Directories") or "").strip(),

                "files_loaded":
                    (row.get("FilesLoaded") or "").strip(),

                "parsing_error":
                    (row.get("ParsingError") or "").strip(),

                "note":
                    (row.get("Note") or "").strip(),
            }

            for run_field in PREFETCH_RUN_FIELDS:

                timestamp = (
                    row.get(run_field) or ""
                ).strip()

                if not timestamp:
                    continue

                event = make_event(
                    case_id=case_id,
                    timestamp=timestamp,
                    timestamp_type="EXECUTION_TIME",
                    timestamp_source=(
                        f"Prefetch.{run_field}"
                    ),
                    artifact_type="prefetch",
                    event_type="PROGRAM_EXECUTION",
                    source_tool="pecmd",
                    parser_output=str(source),
                    source_evidence=source_evidence,
                    source_row=row_number,
                    identity_discriminator=run_field,

                    executable=executable,

                    description=(
                        "Program execution timestamp "
                        f"from Prefetch {run_field}"
                    ),

                    attributes={
                        **attributes,
                        "run_timestamp_field":
                            run_field,
                    },
                )

                yield event


def normalize_pecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:
    """
    Compatibility wrapper preserving the frozen
    PECmd normalization API.
    """

    return list(
        iter_pecmd(
            case_id,
            csv_path,
            max_rows=max_rows,
        )
    )


def test_pecmd_normalization(
    case_id: str,
    max_rows: int = 3,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    csv_path = discovered["inputs"]["pecmd"]

    events = normalize_pecmd(
        case_id,
        csv_path,
        max_rows=max_rows,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "pecmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": csv_path,
        "rows_requested": max_rows,
        "normalized_event_count": len(events),
        "events": events,
    }


# ============================================================
# RECmd NORMALIZATION
# ============================================================

def normalize_recmd(
    case_id: str,
    csv_paths: list[str],
    *,
    max_rows_per_file: int | None = None,
) -> list[dict[str, Any]]:

    events: list[dict[str, Any]] = []

    for csv_path in csv_paths:

        source = Path(csv_path).resolve()

        if not source.is_file():
            raise PolicyError(
                f"RECmd CSV does not exist: {source}"
            )

        with source.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline="",
        ) as handle:

            reader = csv.DictReader(handle)

            required = {
                "HivePath",
                "HiveType",
                "Category",
                "KeyPath",
                "ValueName",
                "ValueType",
                "ValueData",
                "LastWriteTimestamp",
                "Deleted",
            }

            actual = set(reader.fieldnames or [])
            missing = required - actual

            if missing:
                raise PolicyError(
                    "RECmd CSV missing required fields: "
                    + ", ".join(sorted(missing))
                )

            for row_number, row in enumerate(
                reader,
                start=2,
            ):
                if (
                    max_rows_per_file is not None
                    and row_number >
                    max_rows_per_file + 1
                ):
                    break

                timestamp = (
                    row.get("LastWriteTimestamp")
                    or ""
                ).strip()

                # Timeline v1 requires a timestamp.
                if not timestamp:
                    continue

                hive_path = (
                    row.get("HivePath") or ""
                ).strip()

                hive_type = (
                    row.get("HiveType") or ""
                ).strip()

                key_path = (
                    row.get("KeyPath") or ""
                ).strip()

                value_name = (
                    row.get("ValueName") or ""
                ).strip()

                value_data = (
                    row.get("ValueData") or ""
                ).strip()

                deleted = (
                    row.get("Deleted") or ""
                ).strip()

                attributes = {
                    "hive_type": hive_type,

                    "category":
                        (row.get("Category") or "").strip(),

                    "value_type":
                        (row.get("ValueType") or "").strip(),

                    "deleted": deleted,

                    "description":
                        (row.get("Description") or "").strip(),

                    "comment":
                        (row.get("Comment") or "").strip(),

                    "plugin_name":
                        (row.get("PluginName") or "").strip(),
                }

                event = make_event(
                    case_id=case_id,
                    timestamp=timestamp,
                    timestamp_type=(
                        "REGISTRY_KEY_LAST_WRITE"
                    ),
                    timestamp_source=(
                        "Registry.LastWriteTimestamp"
                    ),
                    artifact_type="registry",
                    event_type=(
                        "REGISTRY_KEY_LAST_WRITE"
                    ),
                    source_tool="recmd",
                    parser_output=str(source),
                    source_evidence=hive_path,
                    source_row=row_number,

                    registry_hive=hive_type,
                    registry_key=key_path,
                    registry_value_name=value_name,
                    registry_value_data=value_data,

                    description=(
                        "Registry key LastWrite observation"
                    ),

                    attributes=attributes,
                )

                events.append(event)

    return events


def test_recmd_normalization(
    case_id: str,
    max_rows_per_file: int = 1,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    csv_paths = discovered["inputs"]["recmd"]

    events = normalize_recmd(
        case_id,
        csv_paths,
        max_rows_per_file=max_rows_per_file,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "recmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_files": csv_paths,
        "input_file_count": len(csv_paths),
        "rows_requested_per_file":
            max_rows_per_file,
        "normalized_event_count": len(events),
        "events": events,
    }


# ============================================================
# LECmd NORMALIZATION
# ============================================================

LNK_TIMESTAMP_FIELDS = {
    "SourceCreated": (
        "LNK_CREATED",
        "LNK_SOURCE"
    ),
    "SourceModified": (
        "LNK_MODIFIED",
        "LNK_SOURCE"
    ),
    "SourceAccessed": (
        "LNK_ACCESSED",
        "LNK_SOURCE"
    ),
    "TargetCreated": (
        "TARGET_CREATED",
        "LNK_TARGET_METADATA"
    ),
    "TargetModified": (
        "TARGET_MODIFIED",
        "LNK_TARGET_METADATA"
    ),
    "TargetAccessed": (
        "TARGET_ACCESSED",
        "LNK_TARGET_METADATA"
    ),
}


def normalize_lecmd(
    case_id: str,
    csv_path: str,
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:

    source = Path(csv_path).resolve()

    if not source.is_file():
        raise PolicyError(
            f"LECmd CSV does not exist: {source}"
        )

    events: list[dict[str, Any]] = []

    with source.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "TargetCreated",
            "TargetModified",
            "TargetAccessed",
            "LocalPath",
            "RelativePath",
        }

        actual = set(reader.fieldnames or [])
        missing = required - actual

        if missing:
            raise PolicyError(
                "LECmd CSV missing required fields: "
                + ", ".join(sorted(missing))
            )

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            if (
                max_rows is not None
                and row_number > max_rows + 1
            ):
                break

            source_evidence = (
                row.get("SourceFile") or ""
            ).strip()

            local_path = (
                row.get("LocalPath") or ""
            ).strip()

            relative_path = (
                row.get("RelativePath") or ""
            ).strip()

            target_path = (
                local_path or relative_path
            )

            attributes = {
                "relative_path": relative_path,

                "local_path": local_path,

                "working_directory":
                    (row.get("WorkingDirectory") or "").strip(),

                "arguments":
                    (row.get("Arguments") or "").strip(),

                "file_size":
                    (row.get("FileSize") or "").strip(),

                "header_flags":
                    (row.get("HeaderFlags") or "").strip(),

                "file_attributes":
                    (row.get("FileAttributes") or "").strip(),

                "drive_type":
                    (row.get("DriveType") or "").strip(),

                "volume_serial_number":
                    (row.get("VolumeSerialNumber") or "").strip(),

                "volume_label":
                    (row.get("VolumeLabel") or "").strip(),

                "machine_id":
                    (row.get("MachineID") or "").strip(),

                "mac_address":
                    (row.get("MacAddress") or "").strip(),

                "tracker_created_on":
                    (row.get("TrackerCreatedOn") or "").strip(),

                "target_mft_entry":
                    (row.get("TargetMFTEntryNumber") or "").strip(),

                "target_mft_sequence":
                    (row.get("TargetMFTSequenceNumber") or "").strip(),
            }

            for timestamp_field, (
                event_type,
                timestamp_origin,
            ) in LNK_TIMESTAMP_FIELDS.items():

                timestamp = (
                    row.get(timestamp_field) or ""
                ).strip()

                if not timestamp:
                    continue

                event = make_event(
                    case_id=case_id,
                    timestamp=timestamp,
                    timestamp_type=event_type,
                    timestamp_source=(
                        f"LNK.{timestamp_field}"
                    ),
                    artifact_type="lnk",
                    event_type=event_type,
                    source_tool="lecmd",
                    parser_output=str(source),
                    source_evidence=source_evidence,
                    source_row=row_number,

                    path=source_evidence,
                    target_path=target_path,

                    mft_entry=(
                        row.get(
                            "TargetMFTEntryNumber"
                        ) or ""
                    ).strip(),

                    mft_sequence=(
                        row.get(
                            "TargetMFTSequenceNumber"
                        ) or ""
                    ).strip(),

                    description=(
                        f"{event_type} timestamp from "
                        f"{timestamp_origin}"
                    ),

                    attributes={
                        **attributes,
                        "timestamp_origin":
                            timestamp_origin,
                        "timestamp_field":
                            timestamp_field,
                    },
                )

                events.append(event)

    return events


def test_lecmd_normalization(
    case_id: str,
    max_rows: int = 1,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    csv_path = discovered["inputs"]["lecmd"]

    events = normalize_lecmd(
        case_id,
        csv_path,
        max_rows=max_rows,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "lecmd",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": csv_path,
        "rows_requested": max_rows,
        "normalized_event_count": len(events),
        "events": events,
    }


# ============================================================
# HAYABUSA NORMALIZATION
# ============================================================

def normalize_hayabusa(
    case_id: str,
    jsonl_path: str,
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:

    source = Path(jsonl_path).resolve()

    if not source.is_file():
        raise PolicyError(
            f"Hayabusa JSONL does not exist: {source}"
        )

    events: list[dict[str, Any]] = []

    with source.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as handle:

        for row_number, line in enumerate(
            handle,
            start=1,
        ):
            if (
                max_rows is not None
                and row_number > max_rows
            ):
                break

            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PolicyError(
                    f"Invalid Hayabusa JSON at line "
                    f"{row_number}: {exc}"
                )

            timestamp = str(
                row.get("Timestamp") or ""
            ).strip()

            if not timestamp:
                continue

            event_id = str(
                row.get("EventID") or ""
            ).strip()

            channel = str(
                row.get("Channel") or ""
            ).strip()

            computer = str(
                row.get("Computer") or ""
            ).strip()

            level = str(
                row.get("Level") or ""
            ).strip()

            rule_title = str(
                row.get("RuleTitle") or ""
            ).strip()

            details = str(
                row.get("Details") or ""
            ).strip()

            attributes = {
                "rule_title": rule_title,

                "details": details,

                "record_id":
                    str(
                        row.get("RecordID") or ""
                    ).strip(),

                "rule_file":
                    str(
                        row.get("RuleFile") or ""
                    ).strip(),

                "evtx_file":
                    str(
                        row.get("EvtxFile") or ""
                    ).strip(),

                "tags":
                    row.get("Tags"),

                "mitre_tactics":
                    row.get("MitreTactics"),

                "mitre_tags":
                    row.get("MitreTags"),

                "other_tags":
                    row.get("OtherTags"),

                "rule_author":
                    row.get("RuleAuthor"),

                "rule_creation_date":
                    row.get("RuleCreationDate"),

                "rule_modified_date":
                    row.get("RuleModifiedDate"),

                "status":
                    row.get("Status"),
            }

            event = make_event(
                case_id=case_id,
                timestamp=timestamp,
                timestamp_type="EVENT_TIME",
                timestamp_source="Hayabusa.Timestamp",
                artifact_type="hayabusa_detection",
                event_type="DETECTION",
                source_tool="hayabusa",
                parser_output=str(source),

                source_evidence=str(
                    row.get("EvtxFile") or ""
                ).strip(),

                source_row=row_number,

                hostname=computer,

                windows_event_id=event_id,

                channel=channel,

                detection_rule=rule_title,

                severity=level,

                description=(
                    rule_title
                    or "Hayabusa detection"
                ),

                attributes=attributes,
            )

            events.append(event)

    return events


def test_hayabusa_normalization(
    case_id: str,
    max_rows: int = 3,
) -> dict[str, Any]:

    discovered = discover_normalization_inputs(
        case_id
    )

    jsonl_path = discovered["inputs"]["hayabusa"]

    events = normalize_hayabusa(
        case_id,
        jsonl_path,
        max_rows=max_rows,
    )

    return {
        "success": True,
        "component": "normalizer",
        "adapter": "hayabusa",
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "input_file": jsonl_path,
        "rows_requested": max_rows,
        "normalized_event_count": len(events),
        "events": events,
    }

if __name__ == "__main__":
    import sys

    case = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "CASE-DEMO"
    )

    print(
        json.dumps(
            validate_normalization_request(case),
            indent=2,
        )
    )










