from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator
import hashlib
import re
import subprocess
import sys


@dataclass
class EvidenceEntry:
    logical_path: str
    name: str
    is_dir: bool
    deleted: bool = False
    size: int | None = None
    locator: Any = None
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class EvidenceReader(ABC):
    """
    Small, container-independent read-only evidence interface.

    Artifact-selection logic must live outside the reader.
    Readers know how to enumerate and extract; they do not decide what
    is suspicious or which forensic artifacts are important.
    """

    container_type: str = "UNKNOWN"
    container_class: str = "UNKNOWN"

    def __init__(self, image_path: str | Path):
        self.image_path = Path(image_path).resolve()

    @abstractmethod
    def validate(self) -> None:
        pass

    @abstractmethod
    def iter_entries(self) -> Iterator[EvidenceEntry]:
        pass

    @abstractmethod
    def extract_to(
        self,
        entry: EvidenceEntry,
        destination: str | Path,
    ) -> dict[str, Any]:
        pass

    def exists(self, logical_path: str) -> bool:
        expected = (
            str(logical_path)
            .replace("\\", "/")
            .strip("/")
            .lower()
        )

        return any(
            (
                entry.logical_path
                .replace("\\", "/")
                .strip("/")
                .lower()
                == expected
            )
            for entry in self.iter_entries()
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest().upper()


class AD1EvidenceReader(EvidenceReader):
    container_type = "AD1"
    container_class = "LOGICAL_CONTAINER"

    AD1_SIGNATURE = b"ADSEGMENTEDFILE"

    def __init__(
        self,
        image_path: str | Path,
        *,
        tool_root: str | Path = (
            str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tools" / "ad1" / "ad1-viewer")
        ),
    ):
        super().__init__(image_path)

        self.tool_root = Path(
            tool_root
        ).resolve()

        if str(self.tool_root) not in sys.path:
            sys.path.insert(
                0,
                str(self.tool_root),
            )

        from ad1.parser import AD1

        self._ad1_type = AD1
        self._ad1 = None

    def validate(self) -> None:
        if not self.image_path.is_file():
            raise FileNotFoundError(
                f"AD1 does not exist: {self.image_path}"
            )

        if self.image_path.suffix.lower() != ".ad1":
            raise ValueError(
                f"Not an AD1 file: {self.image_path}"
            )

        with self.image_path.open("rb") as handle:
            signature = handle.read(
                len(self.AD1_SIGNATURE)
            )

        if signature != self.AD1_SIGNATURE:
            raise ValueError(
                "Unsupported AD1 signature: "
                f"{signature!r}"
            )

    def _container(self):
        if self._ad1 is None:
            self.validate()
            self._ad1 = self._ad1_type(
                str(self.image_path)
            )

        return self._ad1

    @staticmethod
    def _walk_nodes(root: Any):
        stack = [root]

        while stack:
            node = stack.pop()
            yield node

            children = list(
                getattr(
                    node,
                    "children",
                    [],
                )
            )

            for child in reversed(children):
                stack.append(child)

    def iter_entries(self) -> Iterator[EvidenceEntry]:
        ad1 = self._container()

        for node in self._walk_nodes(
            ad1.root
        ):
            logical_path = str(
                getattr(
                    node,
                    "path",
                    "",
                )
            )

            name = str(
                getattr(
                    node,
                    "name",
                    "",
                )
            )

            yield EvidenceEntry(
                logical_path=logical_path,
                name=name,
                is_dir=bool(
                    getattr(
                        node,
                        "is_dir",
                        False,
                    )
                ),
                locator=node,
                metadata={
                    "reader": "AD1EvidenceReader",
                },
            )

    def extract_to(
        self,
        entry: EvidenceEntry,
        destination: str | Path,
    ) -> dict[str, Any]:
        if entry.is_dir:
            raise ValueError(
                "Cannot extract a directory as a file"
            )

        ad1 = self._container()
        destination = Path(destination).resolve()

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.exists():
            raise FileExistsError(
                "Refusing to overwrite extracted evidence: "
                f"{destination}"
            )

        data = ad1.read_file(
            entry.locator
        )

        temp = destination.with_suffix(
            destination.suffix + ".partial"
        )

        if temp.exists():
            temp.unlink()

        try:
            temp.write_bytes(data)

            if temp.stat().st_size != len(data):
                raise RuntimeError(
                    "AD1 extraction size mismatch"
                )

            temp.replace(destination)

        except Exception:
            temp.unlink(
                missing_ok=True
            )
            raise

        return {
            "size_bytes":
                destination.stat().st_size,
            "sha256":
                _sha256_file(destination),
        }


class TSKEvidenceReader(EvidenceReader):
    """
    Reader for physical filesystem images handled by the existing
    Sleuth Kit path (E01/EWF, DD/RAW/IMG/001).

    This adapter deliberately reuses the project's already-tested image
    inspection and filesystem selection logic instead of creating a
    second forensic parser.
    """

    container_type = "PHYSICAL"
    container_class = "PHYSICAL_IMAGE"

    def __init__(
        self,
        image_path: str | Path,
        *,
        tsk_root: str | Path = (
            str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tools" / "disk" / "SleuthKit" / "bin")
        ),
        filesystem_ranker: (
            Callable[[list[dict[str, Any]]], int | None]
            | None
        ) = None,
    ):
        super().__init__(image_path)

        self.tsk_root = Path(
            tsk_root
        ).resolve()

        self.fls = self.tsk_root / "fls.exe"
        self.icat = self.tsk_root / "icat.exe"

        self.filesystem_ranker = filesystem_ranker

        self._selected_offset = None
        self._selected_filesystem = None
        self._records = None

    def validate(self) -> None:
        if not self.image_path.is_file():
            raise FileNotFoundError(
                f"Image does not exist: {self.image_path}"
            )

        if not self.fls.is_file():
            raise FileNotFoundError(
                f"fls.exe not found: {self.fls}"
            )

        if not self.icat.is_file():
            raise FileNotFoundError(
                f"icat.exe not found: {self.icat}"
            )

    @staticmethod
    def _parse_fls(text: str) -> list[dict[str, Any]]:
        records = []

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

            path = (
                match.group("path")
                .strip()
                .replace("\\", "/")
                .strip("/")
            )

            records.append(
                {
                    "entry_type":
                        match.group("entry_type"),
                    "metadata_address":
                        match.group("meta").strip(),
                    "logical_path": path,
                    "deleted":
                        bool(
                            match.group("deleted")
                        ),
                }
            )

        return records

    def _fls_recursive(
        self,
        offset_sectors: int,
    ) -> list[dict[str, Any]]:
        command = [
            str(self.fls),
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

        command.append(
            str(self.image_path)
        )

        completed = subprocess.run(
            command,
            cwd=str(self.tsk_root),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                "fls failed: "
                + completed.stderr[-4000:]
            )

        return self._parse_fls(
            completed.stdout
        )

    @staticmethod
    def _looks_like_windows(
        records: list[dict[str, Any]],
    ) -> bool:
        """
        Detect a Windows filesystem using the same conservative
        rules as the production physical-image collector.

        Strong SYSTEM/SOFTWARE registry paths are sufficient alone.
        Otherwise require NTFS metadata plus at least two
        Windows-specific forensic artifact families.
        """

        paths = {
            str(record["logical_path"])
            .replace("\\", "/")
            .strip("/")
            .lower()
            for record in records
            if record.get("logical_path")
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

        strong_registry = any(
            [
                exact_or_suffix(
                    "windows/system32/config/system"
                ),
                exact_or_suffix(
                    "windows/system32/config/software"
                ),
            ]
        )

        if strong_registry:
            return True

        registry_family = any(
            [
                exact_or_suffix(
                    "windows/system32/config/sam"
                ),
                exact_or_suffix(
                    "windows/system32/config/security"
                ),
                exact_or_suffix(
                    "windows/system32/config/default"
                ),
            ]
        )

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

        ntfs_metadata = any(
            [
                exact_or_suffix("$mft"),
                exact_or_suffix("$logfile"),
            ]
        )

        family_count = sum(
            [
                registry_family,
                evtx_family,
                prefetch_family,
                amcache_family,
                srum_family,
            ]
        )

        return bool(
            ntfs_metadata
            and family_count >= 2
        )


    def _prepare(self) -> None:
        if self._records is not None:
            return

        self.validate()

        # Reuse the project's existing forensic image inspection.
        from tsk_image_executor import (
            inspect_forensic_image,
            validate_image_inspection_request,
        )

        validated = validate_image_inspection_request(
            image_path=str(self.image_path)
        )

        inspection = inspect_forensic_image(
            str(validated["image"])
        )

        if not inspection.get("success"):
            raise RuntimeError(
                "Image inspection failed"
            )

        candidates: list[dict[str, Any]] = []

        zero = (
            inspection.get(
                "offset_zero_filesystem"
            )
            or {}
        )

        if zero.get("detected"):
            candidates.append(
                {
                    "offset_sectors": 0,
                    "filesystem":
                        zero.get("filesystem")
                        or {},
                }
            )

        for item in (
            inspection.get(
                "discovered_filesystems"
            )
            or []
        ):
            offset = item.get(
                "offset_sectors"
            )

            if offset is None:
                offset = item.get(
                    "start_sector"
                )

            if offset is None:
                continue

            try:
                offset = int(offset)
            except (TypeError, ValueError):
                continue

            if not any(
                candidate["offset_sectors"] == offset
                for candidate in candidates
            ):
                candidates.append(
                    {
                        "offset_sectors": offset,
                        "filesystem":
                            item.get(
                                "filesystem",
                                item,
                            ),
                    }
                )

        if not candidates:
            raise RuntimeError(
                "No supported filesystem discovered"
            )

        viable = []

        for candidate in candidates:
            offset = int(
                candidate["offset_sectors"]
            )

            records = self._fls_recursive(
                offset
            )

            if not self._looks_like_windows(
                records
            ):
                continue

            if self.filesystem_ranker is None:
                score = len(records)
            else:
                score = self.filesystem_ranker(
                    records
                )

                if score is None:
                    continue

                score = int(score)

            viable.append(
                (
                    score,
                    offset,
                    records,
                    candidate["filesystem"],
                )
            )

        if not viable:
            raise RuntimeError(
                "No Windows filesystem identified"
            )

        (
            _,
            offset,
            records,
            filesystem_info,
        ) = max(
            viable,
            key=lambda item: item[0],
        )

        self._selected_offset = offset
        self._selected_filesystem = filesystem_info
        self._records = records

    @property
    def selected_offset_sectors(
        self,
    ) -> int | None:
        self._prepare()
        return self._selected_offset

    @property
    def selected_filesystem(
        self,
    ) -> dict[str, Any] | None:
        self._prepare()
        return self._selected_filesystem


    def iter_entries(self) -> Iterator[EvidenceEntry]:
        self._prepare()

        for record in self._records:
            logical_path = record[
                "logical_path"
            ]

            entry_type = str(
                record["entry_type"]
            ).lower()

            yield EvidenceEntry(
                logical_path=logical_path,
                name=Path(
                    logical_path
                ).name,
                is_dir=entry_type.startswith("d"),
                deleted=bool(
                    record["deleted"]
                ),
                locator=record[
                    "metadata_address"
                ],
                metadata={
                    "reader":
                        "TSKEvidenceReader",
                    "offset_sectors":
                        self._selected_offset,
                },
            )

    def extract_to(
        self,
        entry: EvidenceEntry,
        destination: str | Path,
    ) -> dict[str, Any]:
        if entry.is_dir:
            raise ValueError(
                "Cannot extract a directory as a file"
            )

        if entry.deleted:
            raise ValueError(
                "Automatic extraction of deleted entries "
                "is disabled"
            )

        self._prepare()

        metadata_address = str(
            entry.locator
        )

        if not re.fullmatch(
            r"\d+(?:-\d+){0,3}",
            metadata_address,
        ):
            raise ValueError(
                "Invalid Sleuth Kit metadata address: "
                f"{metadata_address}"
            )

        destination = Path(
            destination
        ).resolve()

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.exists():
            raise FileExistsError(
                "Refusing to overwrite extracted evidence: "
                f"{destination}"
            )

        temp = destination.with_suffix(
            destination.suffix + ".partial"
        )

        if temp.exists():
            temp.unlink()

        command = [
            str(self.icat),
        ]

        if self._selected_offset > 0:
            command.extend(
                [
                    "-o",
                    str(self._selected_offset),
                ]
            )

        command.extend(
            [
                str(self.image_path),
                metadata_address,
            ]
        )

        try:
            with temp.open("xb") as handle:
                completed = subprocess.run(
                    command,
                    cwd=str(self.tsk_root),
                    shell=False,
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    timeout=1800,
                )

            if completed.returncode != 0:
                raise RuntimeError(
                    completed.stderr.decode(
                        "utf-8",
                        errors="replace",
                    )[-4000:]
                )

            temp.replace(destination)

        except Exception:
            temp.unlink(
                missing_ok=True
            )
            raise

        return {
            "size_bytes":
                destination.stat().st_size,
            "sha256":
                _sha256_file(destination),
        }


def open_evidence_reader(
    image_path: str | Path,
    *,
    detected_type: str,
    filesystem_ranker: (
        Callable[[list[dict[str, Any]]], int | None]
        | None
    ) = None,
) -> EvidenceReader:
    detected = str(
        detected_type
    ).upper()

    if detected == "AD1":
        return AD1EvidenceReader(
            image_path
        )

    if detected in {
        "EWF",
        "RAW",
    }:
        return TSKEvidenceReader(
            image_path,
            filesystem_ranker=filesystem_ranker,
        )

    raise ValueError(
        f"Unsupported evidence reader type: {detected}"
    )
