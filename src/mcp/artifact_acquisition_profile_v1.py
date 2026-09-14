from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Iterable


def normalize_logical_path(value: str) -> str:
    """
    Convert container-specific logical paths into a filesystem-relative
    Windows path without encoding AD1/EWF/RAW knowledge into artifact rules.

    Examples:
      Custom Content Image(...)/volume/[root]/Windows/Prefetch/X.pf
        -> Windows/Prefetch/X.pf

      Windows/System32/config/SYSTEM
        -> Windows/System32/config/SYSTEM

    The explicit [root] marker is preferred when present.  The fallback
    anchors support readers that expose a prefix without that marker while
    preserving already-canonical physical-image paths.
    """
    path = (
        str(value)
        .replace("\\", "/")
        .strip("/")
    )

    if not path:
        return ""

    parts = [
        part
        for part in path.split("/")
        if part
    ]

    # Preferred container-neutral filesystem-root marker.
    for index, part in enumerate(parts):
        if part.lower() == "[root]":
            return "/".join(
                parts[index + 1:]
            )

    low_parts = [
        part.lower()
        for part in parts
    ]

    # Already canonical paths remain unchanged.
    canonical_roots = {
        "windows",
        "users",
        "$recycle.bin",
        "$extend",
        "$mft",
        "$logfile",
    }

    if low_parts and low_parts[0] in canonical_roots:
        return "/".join(parts)

    # Conservative fallback for readers/containers that prepend a volume
    # label but do not expose an explicit [root] marker.
    for index, part in enumerate(low_parts):
        if part in canonical_roots:
            return "/".join(
                parts[index:]
            )

    return path


def normalize_logical_path_lower(value: str) -> str:
    return normalize_logical_path(value).lower()


@dataclass(frozen=True)
class ArtifactSelection:
    family: str
    artifact_type: str
    output_relative: str
    rule_id: str
    investigation_only: bool = False


SYSTEM_LIMITS = {
    "filesystem": 10,
    "eventlogs": 1000,
    "registry": 500,
    "prefetch": 2000,
    "amcache": 10,
    "srum": 10,
    "lnk": 3000,
    "jumplists": 3000,
    "powershell_history": 100,
}

INVESTIGATION_LIMITS = {
    "user_files": 10000,
    "recycle_bin": 5000,
}


def category_limits(profile: str) -> dict[str, int]:
    if profile == "windows_standard":
        return dict(SYSTEM_LIMITS)

    if profile == "windows_investigation":
        return {
            **SYSTEM_LIMITS,
            **INVESTIGATION_LIMITS,
        }

    raise ValueError(
        f"Unsupported acquisition profile: {profile}"
    )


def standard_directories(profile: str) -> list[str]:
    limits = category_limits(profile)

    directories = list(limits.keys())

    # Registry user hives retain their user subtree.
    if "registry" in limits:
        directories.append("registry/users")

    return directories


def _user_parts(path: str) -> tuple[str, str] | None:
    """
    Return (username, relative path under the user profile).

    This intentionally excludes Default/Public profile handling from
    interpretation. They remain ordinary filesystem paths unless a rule
    explicitly selects them.
    """
    normalized = normalize_logical_path(path)
    parts = normalized.split("/")

    if len(parts) < 3:
        return None

    if parts[0].lower() != "users":
        return None

    return parts[1], "/".join(parts[2:])


def _safe_relative_component(value: str) -> str:
    return re.sub(r'[<>:"\\|?*]', "_", value)


def classify_windows_artifact(
    logical_path: str,
    *,
    profile: str = "windows_standard",
) -> ArtifactSelection | None:
    """
    Container-independent Windows artifact classification.

    The caller supplies only a logical filesystem path.  No AD1, EWF,
    RAW/DD, Sleuth Kit, FTK, or parser knowledge is required here.
    """
    category_limits(profile)

    path = normalize_logical_path(logical_path)
    low = path.lower()
    basename = PurePosixPath(path).name
    basename_low = basename.lower()

    # ------------------------------------------------------------------
    # NTFS metadata
    # ------------------------------------------------------------------
    if low == "$mft":
        return ArtifactSelection(
            "filesystem",
            "mft",
            "$MFT",
            "ntfs_mft",
        )

    if low == "$logfile":
        return ArtifactSelection(
            "filesystem",
            "logfile",
            "$LogFile",
            "ntfs_logfile",
        )

    if low in {
        "$extend/$usnjrnl:$j",
        "$usnjrnl:$j",
    }:
        return ArtifactSelection(
            "filesystem",
            "usn_journal",
            "$UsnJrnl_$J",
            "ntfs_usn_journal",
        )

    # ------------------------------------------------------------------
    # Event logs
    # ------------------------------------------------------------------
    evtx_prefix = "windows/system32/winevt/logs/"
    if low.startswith(evtx_prefix) and low.endswith(".evtx"):
        return ArtifactSelection(
            "eventlogs",
            "evtx",
            basename,
            "windows_evtx",
        )

    # ------------------------------------------------------------------
    # Machine Registry hives + transaction logs
    # ------------------------------------------------------------------
    machine_hives = {
        "system": "SYSTEM",
        "software": "SOFTWARE",
        "sam": "SAM",
        "security": "SECURITY",
        "default": "DEFAULT",
    }

    config_prefix = "windows/system32/config/"

    if low.startswith(config_prefix):
        tail = low[len(config_prefix):]

        if tail in machine_hives:
            canonical = machine_hives[tail]
            return ArtifactSelection(
                "registry",
                "registry_hive",
                canonical,
                f"registry_machine_{tail}",
            )

        tx_match = re.fullmatch(
            r"(system|software|sam|security|default)\.(log|log1|log2)",
            tail,
            re.IGNORECASE,
        )

        if tx_match:
            hive = machine_hives[tx_match.group(1).lower()]
            suffix = tx_match.group(2).upper()
            return ArtifactSelection(
                "registry",
                "registry_transaction_log",
                f"{hive}.{suffix}",
                "registry_machine_transaction_log",
            )

        regback_match = re.fullmatch(
            r"regback/(system|software|sam|security|default)",
            tail,
            re.IGNORECASE,
        )

        if regback_match:
            hive = machine_hives[
                regback_match.group(1).lower()
            ]

            return ArtifactSelection(
                "registry",
                "registry_hive_backup",
                f"RegBack/{hive}",
                "registry_machine_regback",
            )

        systemprofile_match = re.fullmatch(
            r"systemprofile/ntuser\.dat",
            tail,
            re.IGNORECASE,
        )

        if systemprofile_match:
            return ArtifactSelection(
                "registry",
                "ntuser",
                "systemprofile/NTUSER.DAT",
                "registry_systemprofile_ntuser",
            )

        systemprofile_tx = re.fullmatch(
            r"systemprofile/ntuser\.dat\.(log|log1|log2)",
            tail,
            re.IGNORECASE,
        )

        if systemprofile_tx:
            suffix = systemprofile_tx.group(1).upper()

            return ArtifactSelection(
                "registry",
                "registry_transaction_log",
                f"systemprofile/NTUSER.DAT.{suffix}",
                "registry_systemprofile_ntuser_transaction_log",
            )

    # ------------------------------------------------------------------
    # User Registry hives + transaction logs
    # ------------------------------------------------------------------
    user = _user_parts(path)

    if user:
        username, relative = user
        rel_low = relative.lower()
        safe_user = _safe_relative_component(username)

        if rel_low == "ntuser.dat":
            return ArtifactSelection(
                "registry",
                "ntuser",
                f"users/{safe_user}/NTUSER.DAT",
                "registry_user_ntuser",
            )

        ntuser_tx = re.fullmatch(
            r"ntuser\.dat\.(log|log1|log2)",
            rel_low,
            re.IGNORECASE,
        )

        if ntuser_tx:
            suffix = ntuser_tx.group(1).upper()
            return ArtifactSelection(
                "registry",
                "registry_transaction_log",
                f"users/{safe_user}/NTUSER.DAT.{suffix}",
                "registry_user_ntuser_transaction_log",
            )

        usrclass_base = (
            "appdata/local/microsoft/windows/usrclass.dat"
        )

        if rel_low == usrclass_base:
            return ArtifactSelection(
                "registry",
                "usrclass",
                f"users/{safe_user}/UsrClass.dat",
                "registry_user_usrclass",
            )

        usrclass_tx = re.fullmatch(
            re.escape(usrclass_base)
            + r"\.(log|log1|log2)",
            rel_low,
            re.IGNORECASE,
        )

        if usrclass_tx:
            suffix = usrclass_tx.group(1).upper()
            return ArtifactSelection(
                "registry",
                "registry_transaction_log",
                f"users/{safe_user}/UsrClass.dat.{suffix}",
                "registry_user_usrclass_transaction_log",
            )

    # ------------------------------------------------------------------
    # Prefetch / Amcache / SRUM
    # ------------------------------------------------------------------
    if (
        low.startswith("windows/prefetch/")
        and low.endswith(".pf")
    ):
        return ArtifactSelection(
            "prefetch",
            "prefetch",
            basename,
            "windows_prefetch",
        )

    if low == "windows/appcompat/programs/amcache.hve":
        return ArtifactSelection(
            "amcache",
            "amcache",
            "Amcache.hve",
            "windows_amcache",
        )

    if low == "windows/system32/sru/srudb.dat":
        return ArtifactSelection(
            "srum",
            "srum",
            "SRUDB.dat",
            "windows_srum",
        )

    # ------------------------------------------------------------------
    # PowerShell history
    # ------------------------------------------------------------------
    if user:
        username, relative = user
        rel_low = relative.lower()
        safe_user = _safe_relative_component(username)

        ps_history = (
            "appdata/roaming/microsoft/windows/powershell/"
            "psreadline/consolehost_history.txt"
        )

        if rel_low == ps_history:
            return ArtifactSelection(
                "powershell_history",
                "powershell_history",
                f"{safe_user}/ConsoleHost_history.txt",
                "powershell_psreadline_history",
            )

    # ------------------------------------------------------------------
    # Recent LNK + Jump Lists
    # ------------------------------------------------------------------
    if user:
        username, relative = user
        rel_low = relative.lower()
        safe_user = _safe_relative_component(username)
        recent_prefix = (
            "appdata/roaming/microsoft/windows/recent/"
        )

        if rel_low.startswith(recent_prefix):
            if (
                rel_low.endswith(".lnk")
                and "/automaticdestinations/" not in rel_low
                and "/customdestinations/" not in rel_low
            ):
                return ArtifactSelection(
                    "lnk",
                    "lnk",
                    f"{safe_user}/{basename}",
                    "windows_recent_lnk",
                )

            if (
                rel_low.endswith(".automaticdestinations-ms")
                or rel_low.endswith(".customdestinations-ms")
            ):
                return ArtifactSelection(
                    "jumplists",
                    "jumplist",
                    f"{safe_user}/{basename}",
                    "windows_jumplist",
                )

        #
        # Generic user-profile LNK coverage.
        #
        # The legacy AD1 collector selected all .lnk files, while the
        # physical-image collector selected Recent LNKs only.  Centralize
        # on user-profile LNK evidence so Desktop, WinX, Application
        # Shortcuts, ConnectedSearch history, and other user shell
        # shortcuts are collected consistently across container types.
        #
        if rel_low.endswith(".lnk"):
            clean_relative = "/".join(
                _safe_relative_component(part)
                for part in relative.split("/")
                if part
            )

            return ArtifactSelection(
                "lnk",
                "lnk",
                f"{safe_user}/{clean_relative}",
                "windows_user_lnk",
            )

    # ------------------------------------------------------------------
    # Investigation profile: user-visible content
    #
    # These files are collected as evidence only.  They are NOT
    # automatically interpreted as suspicious and are not routed to
    # existing parsers merely because they were collected.
    # ------------------------------------------------------------------
    if profile == "windows_investigation" and user:
        username, relative = user
        rel_low = relative.lower()
        safe_user = _safe_relative_component(username)

        roots = (
            ("downloads/", "Downloads"),
            ("desktop/", "Desktop"),
            ("documents/", "Documents"),
            ("appdata/local/temp/", "Temp"),
        )

        for prefix, label in roots:
            if rel_low.startswith(prefix):
                tail = relative[len(prefix):].strip("/")

                if not tail:
                    return None

                clean_tail = "/".join(
                    _safe_relative_component(part)
                    for part in tail.split("/")
                    if part
                )

                return ArtifactSelection(
                    "user_files",
                    "user_file",
                    f"{safe_user}/{label}/{clean_tail}",
                    f"user_{label.lower()}",
                    investigation_only=True,
                )

        recycle_match = re.match(
            r"^\$recycle\.bin/([^/]+)/(.+)$",
            path,
            re.IGNORECASE,
        )

        if recycle_match:
            sid = _safe_relative_component(
                recycle_match.group(1)
            )
            tail = "/".join(
                _safe_relative_component(part)
                for part in recycle_match.group(2).split("/")
                if part
            )

            return ArtifactSelection(
                "recycle_bin",
                "recycle_bin_file",
                f"{sid}/{tail}",
                "windows_recycle_bin",
                investigation_only=True,
            )

    return None


def classify_many(
    logical_paths: Iterable[str],
    *,
    profile: str = "windows_standard",
) -> list[tuple[str, ArtifactSelection]]:
    output: list[tuple[str, ArtifactSelection]] = []

    for path in logical_paths:
        selected = classify_windows_artifact(
            path,
            profile=profile,
        )

        if selected is not None:
            output.append(
                (path, selected)
            )

    return output
