
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


AD1_SIGNATURE = b"ADSEGMENTEDFILE\x00"


ARTIFACT_FAMILIES = {
    "mft": {
        "directory": "filesystem",
        "parser": "mftecmd",
    },

    "evtx": {
        "directory": "eventlogs",
        "parser": "evtxecmd",
    },

    "prefetch": {
        "directory": "prefetch",
        "parser": "pecmd",
    },

    "registry": {
        "directory": "registry",
        "parser": "recmd",
    },

    "lnk": {
        "directory": "lnk",
        "parser": "lecmd",
    },

    "amcache": {
        "directory": "amcache",
        "parser": None,
    },

    "srum": {
        "directory": "srum",
        "parser": None,
    },

    "powershell_history": {
        "directory": "powershell_history",
        "parser": None,
    },
}


PARSER_OUTPUTS = {
    "mftecmd": (
        "parsed/mftecmd",
        "*.csv",
    ),

    "evtxecmd": (
        "parsed/evtxecmd",
        "*.csv",
    ),

    "pecmd": (
        "parsed/pecmd",
        "*.csv",
    ),

    "recmd": (
        "parsed/recmd",
        "*.csv",
    ),

    "lecmd": (
        "parsed/lecmd",
        "*.csv",
    ),

    "hayabusa": (
        "parsed/hayabusa",
        "*.jsonl",
    ),
}


def sha256_file(
    path: Path,
    chunk_size: int = 8 * 1024 * 1024,
) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:

        while True:

            block = f.read(
                chunk_size
            )

            if not block:
                break

            h.update(block)

    return h.hexdigest().upper()


def detect_input_type(
    image_path: str | Path,
) -> dict[str, Any]:

    image = Path(
        image_path
    ).resolve()

    if not image.is_file():

        raise FileNotFoundError(
            str(image)
        )

    with image.open("rb") as f:

        header = f.read(
            max(
                len(AD1_SIGNATURE),
                64,
            )
        )

    suffix = (
        image.suffix
        .lower()
    )

    if header.startswith(
        AD1_SIGNATURE
    ):

        return {
            "type": "AD1",
            "container_class":
                "LOGICAL_CONTAINER",
            "collector":
                "ad1_collector_v1",
            "signature_verified":
                True,
            "source_filesystem_metadata_preserved":
                False,
            "source_timestamp_trust":
                "CONDITIONAL",
            "target_metadata_timestamp_trust":
                "MEDIUM",
        }

    if suffix in {
        ".e01",
        ".e02",
        ".e03",
        ".ex01",
    }:

        return {
            "type": "EWF",
            "container_class":
                "PHYSICAL_IMAGE",
            "collector":
                "triage_collector",
            "signature_verified":
                False,
            "source_filesystem_metadata_preserved":
                True,
            "source_timestamp_trust":
                "HIGH",
            "target_metadata_timestamp_trust":
                "MEDIUM",
        }

    if suffix in {
        ".raw",
        ".dd",
        ".img",
        ".001",
    }:

        return {
            "type": "RAW",
            "container_class":
                "PHYSICAL_IMAGE",
            "collector":
                "triage_collector",
            "signature_verified":
                False,
            "source_filesystem_metadata_preserved":
                True,
            "source_timestamp_trust":
                "HIGH",
            "target_metadata_timestamp_trust":
                "MEDIUM",
        }

    return {
        "type": "UNKNOWN",
        "container_class":
            "UNKNOWN",
        "collector": None,
        "signature_verified":
            False,
        "source_filesystem_metadata_preserved":
            None,
        "source_timestamp_trust":
            "UNKNOWN",
        "target_metadata_timestamp_trust":
            "UNKNOWN",
    }


def dispatch_collection(
    *,
    image_path: str,
    case_id: str,
    profile: str = "windows_standard",
) -> dict[str, Any]:

    detected = detect_input_type(
        image_path
    )

    if detected["type"] == "AD1":

        from ad1_collector_v1 import (
            collect_ad1_artifacts,
        )

        result = (
            collect_ad1_artifacts(
                image_path=image_path,
                case_id=case_id,
                profile=profile,
            )
        )

    elif detected[
        "container_class"
    ] == "PHYSICAL_IMAGE":

        from triage_collector import (
            collect_triage_artifacts,
        )

        result = (
            collect_triage_artifacts(
                image_path=image_path,
                case_id=case_id,
                profile=profile,
            )
        )

    else:

        raise RuntimeError(
            "Unsupported forensic input. "
            f"Detected type: "
            f"{detected['type']}"
        )

    if not isinstance(
        result,
        dict,
    ):

        raise RuntimeError(
            "Collector returned "
            "non-dictionary result"
        )

    result = dict(result)

    result[
        "input_detection"
    ] = detected

    return result


def count_files(
    path: Path,
) -> int:

    if not path.exists():
        return 0

    if path.is_file():
        return 1

    return sum(
        1
        for p in path.rglob("*")
        if p.is_file()
    )


def discover_artifact_capabilities(
    case_dir: str | Path,
) -> dict[str, Any]:

    case = Path(
        case_dir
    ).resolve()

    triage = (
        case
        / "triage"
    )

    capabilities = {}

    for family, policy in (
        ARTIFACT_FAMILIES.items()
    ):

        path = (
            triage
            / policy[
                "directory"
            ]
        )

        count = count_files(
            path
        )

        if count > 0:

            state = "AVAILABLE"

        else:

            state = "ABSENT"

        capabilities[
            family
        ] = {
            "state": state,
            "count": count,
            "path": str(path),
            "parser":
                policy["parser"],
        }

    return capabilities


def discover_parser_outputs(
    case_dir: str | Path,
) -> dict[str, list[str]]:

    case = Path(
        case_dir
    ).resolve()

    result = {}

    for parser, (
        relative_dir,
        pattern,
    ) in PARSER_OUTPUTS.items():

        directory = (
            case
            / relative_dir
        )

        files = []

        if directory.is_dir():

            files = sorted(
                str(path.resolve())
                for path
                in directory.glob(
                    pattern
                )
                if path.is_file()
            )

        if parser == "pecmd":

            files = [
                path
                for path in files
                if not Path(
                    path
                ).name.lower().endswith(
                    "_timeline.csv"
                )
            ]

        result[parser] = files

    return result


def available_import_sources(
    case_dir: str | Path,
) -> list[str]:

    discovered = (
        discover_parser_outputs(
            case_dir
        )
    )

    order = (
        "mftecmd",
        "evtxecmd",
        "pecmd",
        "recmd",
        "lecmd",
        "hayabusa",
    )

    return [
        source
        for source in order
        if discovered.get(
            source
        )
    ]


def build_case_capabilities(
    *,
    case_id: str,
    image_path: str,
    case_dir: str | Path,
    collection_result:
        dict[str, Any] | None = None,
) -> dict[str, Any]:

    image = Path(
        image_path
    ).resolve()

    detected = detect_input_type(
        image
    )

    artifact_capabilities = (
        discover_artifact_capabilities(
            case_dir
        )
    )

    parser_outputs = (
        discover_parser_outputs(
            case_dir
        )
    )

    import_sources = (
        available_import_sources(
            case_dir
        )
    )

    collection_result = (
        collection_result
        or {}
    )

    failure_count = int(
        collection_result.get(
            "failure_count",
            0,
        )
        or 0
    )

    return {
        "schema_version": "1.0",
        "case_id": case_id,

        "evidence": {
            "path": str(image),
            "container_type":
                detected["type"],
            "container_class":
                detected[
                    "container_class"
                ],
            "sha256":
                sha256_file(image),
            "signature_verified":
                detected[
                    "signature_verified"
                ],
            "original_modified":
                False,
        },

        "timestamp_policy": {
            "source_filesystem_metadata_preserved":
                detected[
                    "source_filesystem_metadata_preserved"
                ],

            "source_timestamp_trust":
                detected[
                    "source_timestamp_trust"
                ],

            "target_metadata_timestamp_trust":
                detected[
                    "target_metadata_timestamp_trust"
                ],

            "rule":
                (
                    "Logical-container extraction "
                    "source timestamps are not "
                    "automatically timeline-eligible "
                    "unless metadata preservation "
                    "is explicitly established."
                ),
        },

        "collection": {
            "collector":
                detected[
                    "collector"
                ],

            "artifact_count":
                collection_result.get(
                    "artifact_count",
                    0,
                ),

            "failure_count":
                failure_count,

            "coverage_state":
                (
                    "PARTIAL"
                    if failure_count > 0
                    else "COMPLETED"
                ),
        },

        "artifacts":
            artifact_capabilities,

        "parser_outputs":
            parser_outputs,

        "available_import_sources":
            import_sources,
    }


def write_case_capabilities(
    *,
    case_id: str,
    image_path: str,
    case_dir: str | Path,
    collection_result:
        dict[str, Any] | None = None,
) -> Path:

    case = Path(
        case_dir
    ).resolve()

    output = (
        case
        / "provenance"
        / "case_capabilities.json"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = (
        build_case_capabilities(
            case_id=case_id,
            image_path=image_path,
            case_dir=case,
            collection_result=
                collection_result,
        )
    )

    temp = output.with_suffix(
        ".json.tmp"
    )

    temp.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    temp.replace(output)

    return output
