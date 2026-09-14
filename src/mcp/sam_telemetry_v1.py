from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import struct
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path


WORKSPACE = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace"))

RECMD = Path(
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tools" / "windows" / "EZTools" / "RECmd" / "RECmd.exe")
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest().upper()


def filetime_to_iso(value: int):

    if value == 0:
        return None

    if value == 0x7FFFFFFFFFFFFFFF:
        return None

    epoch = datetime(
        1601,
        1,
        1,
        tzinfo=timezone.utc,
    )

    try:
        dt = epoch + timedelta(
            microseconds=value / 10
        )

        return dt.isoformat()

    except Exception:
        return None


def find_primary_sam(
    case_root: Path,
):

    root = (
        case_root
        / "triage"
        / "registry"
    )

    candidates = []

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if path.name.lower() != "sam":
            continue

        size = path.stat().st_size

        if size <= 0:
            continue

        candidates.append(
            (
                size,
                path,
            )
        )

    if not candidates:
        raise RuntimeError(
            "No non-zero SAM hive found"
        )

    candidates.sort(
        key=lambda x: x[0],
        reverse=True,
    )

    return candidates[0][1]


def load_users(
    con,
):

    rows = con.execute(
        """
        SELECT
            event_uid,
            registry_value_data
        FROM events
        WHERE
            lower(source_tool) = 'recmd'
            AND lower(
                coalesce(
                    registry_hive,
                    ''
                )
            ) = 'sam'
            AND lower(
                coalesce(
                    registry_key,
                    ''
                )
            ) LIKE '%sam\\domains\\account\\users%'
            AND registry_value_name = 'V'
        """
    ).fetchall()

    pattern = re.compile(
        r"Username:\s*(.*?)\s+"
        r"Id:\s*(\d+)\s+"
        r"ValidUserId:\s*(True|False)",
        re.I,
    )

    users = []

    seen = set()

    for row in rows:

        data = (
            row["registry_value_data"]
            or ""
        )

        match = pattern.search(data)

        if not match:
            continue

        username = (
            match.group(1).strip()
        )

        rid = int(
            match.group(2)
        )

        if rid in seen:
            continue

        seen.add(rid)

        users.append(
            {
                "username":
                    username,
                "rid":
                    rid,
                "valid_user_id":
                    (
                        match.group(3)
                        .lower()
                        == "true"
                    ),
                "identity_event_uid":
                    row["event_uid"],
            }
        )

    return sorted(
        users,
        key=lambda x: x["rid"],
    )


def run_recmd_f(
    sam_path: Path,
    rid: int,
):

    rid_key = f"{rid:08X}"

    key = (
        "SAM\\Domains\\Account\\Users\\"
        + rid_key
    )

    result = subprocess.run(
        [
            str(RECMD),
            "-f",
            str(sam_path),
            "--kn",
            key,
            "--vn",
            "F",
        ],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "RECmd failed for RID "
            f"{rid}: {result.stderr}"
        )

    text = (
        result.stdout
        + "\n"
        + result.stderr
    )

    last_write = None

    match = re.search(
        r"Last write time:\s*"
        r"([^\r\n]+)",
        text,
        re.I,
    )

    if match:
        last_write = (
            match.group(1).strip()
        )

    marker = "Value data:"

    pos = text.find(marker)

    if pos < 0:
        return {
            "rid_key":
                rid_key,
            "registry_key":
                key,
            "last_write":
                last_write,
            "f_bytes":
                None,
        }

    payload = text[
        pos + len(marker):
    ]

    slack_pos = payload.find(
        "(Slack:"
    )

    if slack_pos >= 0:
        payload = payload[
            :slack_pos
        ]

    hex_pairs = re.findall(
        r"\b[0-9A-Fa-f]{2}\b",
        payload,
    )

    if not hex_pairs:
        return {
            "rid_key":
                rid_key,
            "registry_key":
                key,
            "last_write":
                last_write,
            "f_bytes":
                None,
        }

    raw = bytes(
        int(pair, 16)
        for pair in hex_pairs
    )

    return {
        "rid_key":
            rid_key,
        "registry_key":
            key,
        "last_write":
            last_write,
        "f_bytes":
            raw,
    }


def parse_f(
    raw: bytes,
):

    if raw is None:
        return None

    if len(raw) < 0x44:
        raise RuntimeError(
            "SAM F value shorter than "
            "expected minimum"
        )

    last_logon_ft = struct.unpack_from(
        "<Q",
        raw,
        0x08,
    )[0]

    password_last_set_ft = (
        struct.unpack_from(
            "<Q",
            raw,
            0x18,
        )[0]
    )

    account_expires_ft = (
        struct.unpack_from(
            "<Q",
            raw,
            0x20,
        )[0]
    )

    last_failed_logon_ft = (
        struct.unpack_from(
            "<Q",
            raw,
            0x28,
        )[0]
    )

    rid = struct.unpack_from(
        "<I",
        raw,
        0x30,
    )[0]

    account_control = (
        struct.unpack_from(
            "<I",
            raw,
            0x38,
        )[0]
    )

    failed_logon_count = (
        struct.unpack_from(
            "<H",
            raw,
            0x40,
        )[0]
    )

    logon_count = (
        struct.unpack_from(
            "<H",
            raw,
            0x42,
        )[0]
    )

    return {
        "last_logon":
            filetime_to_iso(
                last_logon_ft
            ),

        "password_last_set":
            filetime_to_iso(
                password_last_set_ft
            ),

        "account_expires":
            filetime_to_iso(
                account_expires_ft
            ),

        "last_failed_logon":
            filetime_to_iso(
                last_failed_logon_ft
            ),

        "rid_from_f":
            rid,

        "account_control_raw":
            account_control,

        "failed_logon_count":
            failed_logon_count,

        "logon_count":
            logon_count,
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--case",
        required=True,
    )

    args = parser.parse_args()

    if not RECMD.is_file():
        raise FileNotFoundError(
            RECMD
        )

    case_root = (
        WORKSPACE
        / args.case
    )

    db = (
        case_root
        / "evidence.db"
    )

    if not db.is_file():
        raise FileNotFoundError(
            db
        )

    sam_path = find_primary_sam(
        case_root
    )

    sam_hash_before = sha256_file(
        sam_path
    )

    con = sqlite3.connect(
        "file:"
        + str(db)
        + "?mode=ro",
        uri=True,
    )

    con.row_factory = sqlite3.Row

    integrity = con.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    if integrity != "ok":
        raise RuntimeError(
            "evidence.db integrity: "
            + str(integrity)
        )

    users = load_users(
        con
    )

    con.close()

    parsed_users = []

    machine_sid = None

    for user in users:

        result = run_recmd_f(
            sam_path,
            user["rid"],
        )

        parsed = parse_f(
            result["f_bytes"]
        )

        item = dict(
            user
        )

        item[
            "rid_registry_key"
        ] = result[
            "rid_key"
        ]

        item[
            "sam_key"
        ] = result[
            "registry_key"
        ]

        item[
            "sam_key_last_write"
        ] = result[
            "last_write"
        ]

        if parsed:
            item.update(
                parsed
            )

        parsed_users.append(
            item
        )

    profile_db = sqlite3.connect(
        "file:"
        + str(db)
        + "?mode=ro",
        uri=True,
    )

    profile_db.row_factory = (
        sqlite3.Row
    )

    profile_rows = (
        profile_db.execute(
            """
            SELECT
                event_uid,
                registry_value_data
            FROM events
            WHERE
                lower(source_tool)
                    = 'recmd'
                AND lower(
                    coalesce(
                        registry_hive,
                        ''
                    )
                ) = 'software'
                AND lower(
                    coalesce(
                        registry_key,
                        ''
                    )
                ) LIKE '%profilelist%'
            """
        ).fetchall()
    )

    profile_db.close()

    sid_pattern = re.compile(
        r"S-1-5-21-(?:\d+-){2}\d+-(\d+)",
        re.I,
    )

    sid_by_rid = {}

    for row in profile_rows:

        data = (
            row[
                "registry_value_data"
            ]
            or ""
        )

        match = sid_pattern.search(
            data
        )

        if not match:
            continue

        full_sid = match.group(0)

        rid = int(
            match.group(1)
        )

        sid_by_rid[
            rid
        ] = full_sid

        if machine_sid is None:
            machine_sid = "-".join(
                full_sid.split("-")[
                    :-1
                ]
            )

    for user in parsed_users:

        rid = user["rid"]

        if rid in sid_by_rid:
            user[
                "sid"
            ] = sid_by_rid[
                rid
            ]

        elif machine_sid:
            user[
                "sid"
            ] = (
                machine_sid
                + "-"
                + str(rid)
            )

            user[
                "sid_derivation"
            ] = (
                "Machine SID + local RID"
            )

        else:
            user[
                "sid"
            ] = None

    sam_hash_after = sha256_file(
        sam_path
    )

    if (
        sam_hash_before
        != sam_hash_after
    ):
        raise RuntimeError(
            "SAM hive changed during "
            "telemetry extraction"
        )

    output_data = {
        "schema_version":
            "1.0",

        "case_id":
            args.case,

        "sam_source": {
            "path":
                str(sam_path),
            "sha256":
                sam_hash_before,
            "size_bytes":
                sam_path.stat().st_size,
        },

        "machine_sid":
            machine_sid,

        "users":
            parsed_users,

        "forensic_safety": {
            "sam_read_only":
                True,
            "evidence_db_read_only":
                True,
            "database_modified":
                False,
            "qwen_calls":
                0,
        },
    }

    output_dir = (
        case_root
        / "investigation"
        / "sam_telemetry_v1"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = (
        output_dir
        / "sam_telemetry.json"
    )

    output.write_text(
        json.dumps(
            output_data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "=" * 90
    )
    print(
        "SAM TELEMETRY V1"
    )
    print(
        "=" * 90
    )

    print(
        "SAM:",
        sam_path,
    )

    print(
        "SHA256:",
        sam_hash_before,
    )

    print(
        "Machine SID:",
        machine_sid
        or "NOT AVAILABLE",
    )

    for user in parsed_users:

        print()
        print(
            "User:",
            user["username"],
        )

        print(
            "  RID:",
            user["rid"],
        )

        print(
            "  SID:",
            user.get(
                "sid"
            )
            or "NOT AVAILABLE",
        )

        print(
            "  Last Logon:",
            user.get(
                "last_logon"
            )
            or "NOT AVAILABLE",
        )

        print(
            "  Login Count:",
            user.get(
                "logon_count",
                "NOT AVAILABLE",
            ),
        )

        print(
            "  Password Last Set:",
            user.get(
                "password_last_set"
            )
            or "NOT AVAILABLE",
        )

        print(
            "  Last Failed Logon:",
            user.get(
                "last_failed_logon"
            )
            or "NOT AVAILABLE",
        )

        print(
            "  Failed Logon Count:",
            user.get(
                "failed_logon_count",
                "NOT AVAILABLE",
            ),
        )

    print()
    print(
        "Output:",
        output,
    )

    print(
        "SAM HIVE UNCHANGED: PASS"
    )

    print(
        "DATABASE MODIFIED: NO"
    )

    print(
        "QWEN CALLS: 0"
    )


if __name__ == "__main__":
    main()
