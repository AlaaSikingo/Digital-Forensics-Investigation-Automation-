from __future__ import annotations

import argparse
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path


WORKSPACE = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace"))


def clean(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return value


def evidence_value(row):
    return {
        "value": clean(
            row["registry_value_data"]
        ),
        "source": (
            f"Registry/{row['registry_hive']}"
        ),
        "event_uid": row["event_uid"],
        "registry_key": row["registry_key"],
        "registry_value_name":
            row["registry_value_name"],
    }


def first_registry(
    rows,
    key_contains,
    value_name,
    hive=None,
):
    key_contains = key_contains.lower()
    value_name = value_name.lower()

    for row in rows:

        row_hive = (
            row["registry_hive"]
            or ""
        ).lower()

        key = (
            row["registry_key"]
            or ""
        ).lower()

        name = (
            row["registry_value_name"]
            or ""
        ).lower()

        if hive and row_hive != hive.lower():
            continue

        if key_contains not in key:
            continue

        if name != value_name:
            continue

        value = clean(
            row["registry_value_data"]
        )

        if value is None:
            continue

        return evidence_value(row)

    return None


def derive_machine_sid(rows):

    candidates = []

    for row in rows:

        key = (
            row["registry_key"]
            or ""
        ).lower()

        data = (
            row["registry_value_data"]
            or ""
        )

        if "profilelist" not in key:
            continue

        match = re.search(
            r"S-1-5-21-(?:\d+-){2}\d+-\d+",
            data,
            re.I,
        )

        if not match:
            continue

        sid = match.group(0)

        parts = sid.split("-")

        if len(parts) < 8:
            continue

        try:
            rid = int(parts[-1])
        except ValueError:
            continue

        if rid < 1000:
            continue

        machine_sid = "-".join(
            parts[:-1]
        )

        candidates.append(
            {
                "value": machine_sid,
                "derived_from":
                    sid,
                "derivation":
                    "Removed local account RID "
                    "from local user SID",
                "source":
                    f"Registry/{row['registry_hive']}",
                "event_uid":
                    row["event_uid"],
            }
        )

    if not candidates:
        return None

    return candidates[0]


def parse_sam_users(rows):

    users = []

    pattern = re.compile(
        r"Username:\s*(.*?)\s+"
        r"Id:\s*(\d+)\s+"
        r"ValidUserId:\s*(True|False)",
        re.I,
    )

    for row in rows:

        if (
            row["registry_hive"]
            or ""
        ).lower() != "sam":
            continue

        key = (
            row["registry_key"]
            or ""
        ).lower()

        if (
            "sam\\domains\\account\\users"
            not in key
        ):
            continue

        data = (
            row["registry_value_data"]
            or ""
        )

        match = pattern.search(data)

        if not match:
            continue

        username = match.group(1).strip()
        rid = int(match.group(2))
        valid = (
            match.group(3).lower()
            == "true"
        )

        users.append(
            {
                "username": username,
                "rid": rid,
                "valid_user_id": valid,
                "sam_login_count":
                    "NOT AVAILABLE",
                "sam_last_login":
                    "NOT AVAILABLE",
                "source":
                    "Registry/SAM",
                "event_uid":
                    row["event_uid"],
            }
        )

    return users


def add_profile_sids(
    users,
    rows,
):

    sid_by_rid = {}

    for row in rows:

        key = (
            row["registry_key"]
            or ""
        ).lower()

        if "profilelist" not in key:
            continue

        data = (
            row["registry_value_data"]
            or ""
        )

        match = re.search(
            r"S-1-5-21-(?:\d+-){2}\d+-(\d+)",
            data,
            re.I,
        )

        if not match:
            continue

        sid = re.search(
            r"S-1-5-21-(?:\d+-){2}\d+-\d+",
            data,
            re.I,
        ).group(0)

        rid = int(
            match.group(1)
        )

        sid_by_rid[rid] = {
            "sid": sid,
            "event_uid":
                row["event_uid"],
        }

    for user in users:

        sid_info = sid_by_rid.get(
            user["rid"]
        )

        if sid_info:
            user["sid"] = (
                sid_info["sid"]
            )
            user[
                "sid_event_uid"
            ] = sid_info[
                "event_uid"
            ]
        else:
            user["sid"] = (
                "NOT AVAILABLE"
            )


def add_evtx_logon_context(
    users,
    con,
):

    for user in users:

        username = user["username"]

        rows = con.execute(
            """
            SELECT
                event_uid,
                timestamp_sort,
                timestamp,
                username,
                windows_event_id,
                channel
            FROM events
            WHERE
                windows_event_id = '4624'
                AND lower(
                    coalesce(username, '')
                ) = lower(?)
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                )
            """,
            (
                username,
            ),
        ).fetchall()

        user[
            "observed_successful_logons"
        ] = len(rows)

        if rows:

            last = rows[-1]

            user[
                "last_observed_successful_logon"
            ] = (
                last["timestamp_sort"]
                or last["timestamp"]
            )

            user[
                "last_logon_event_uid"
            ] = last[
                "event_uid"
            ]

            user[
                "observed_logon_source"
            ] = "EVTX/EventID 4624"

        else:
            user[
                "last_observed_successful_logon"
            ] = "NOT AVAILABLE"


def parse_network(rows):

    interfaces = defaultdict(
        dict
    )

    provenance = defaultdict(
        dict
    )

    wanted = {
        "enabledhcp":
            "dhcp_enabled",
        "dhcpipaddress":
            "ipv4_address",
        "dhcpdefaultgateway":
            "default_gateway",
        "dhcpnameserver":
            "dns_servers",
        "dhcpserver":
            "dhcp_server",
        "dhcpsubnetmask":
            "subnet_mask",
        "lease":
            "lease_seconds",
        "leaseobtainedtime":
            "lease_obtained",
        "leaseterminatestime":
            "lease_expires",
        "domain":
            "domain",
    }

    guid_pattern = re.compile(
        r"Interfaces\\(\{[^}]+\})",
        re.I,
    )

    for row in rows:

        if (
            row["registry_hive"]
            or ""
        ).lower() != "system":
            continue

        key = (
            row["registry_key"]
            or ""
        )

        if (
            "\\services\\tcpip\\parameters\\interfaces\\"
            not in key.lower()
        ):
            continue

        guid_match = (
            guid_pattern.search(key)
        )

        if not guid_match:
            continue

        guid = guid_match.group(1)

        name = (
            row["registry_value_name"]
            or ""
        ).lower()

        field = wanted.get(name)

        if not field:
            continue

        value = clean(
            row["registry_value_data"]
        )

        if value is None:
            continue

        if (
            field == "dhcp_enabled"
        ):
            value = (
                value == "1"
            )

        interfaces[guid][
            field
        ] = value

        provenance[guid][
            field
        ] = row["event_uid"]

    output = []

    for guid, values in interfaces.items():

        meaningful = any(
            values.get(field)
            for field in (
                "ipv4_address",
                "dhcp_server",
                "default_gateway",
                "dns_servers",
            )
        )

        if not meaningful:
            continue

        output.append(
            {
                "interface_guid":
                    guid,
                **values,
                "source":
                    "Registry/SYSTEM",
                "provenance":
                    provenance[guid],
            }
        )

    return output


def parse_usb(rows):

    devices = {}

    pattern = re.compile(
        r"Manufacturer:\s*(.*?)\s+"
        r"Title:\s*(.*?)\s+"
        r"Version:\s*(.*?)\s+"
        r"SerialNumber:\s*(.*?)\s+"
        r"DeviceName:\s*(.*?)\s+"
        r"DiskId:\s*(\{[^}]+\})",
        re.I,
    )

    for row in rows:

        hive = (
            row["registry_hive"]
            or ""
        ).lower()

        key = (
            row["registry_key"]
            or ""
        ).lower()

        if hive != "system":
            continue

        if "\\enum\\usbstor" not in key:
            continue

        data = (
            row["registry_value_data"]
            or ""
        )

        match = pattern.search(data)

        if not match:
            continue

        serial = (
            match.group(4)
            .strip()
            .removesuffix("&0")
        )

        devices[serial] = {
            "manufacturer":
                match.group(1)
                .replace("Ven_", "")
                .strip(),
            "product":
                match.group(2)
                .replace("Prod_", "")
                .strip(),
            "version":
                match.group(3)
                .replace("Rev_", "")
                .strip(),
            "serial_number":
                serial,
            "device_name":
                match.group(5).strip(),
            "disk_id":
                match.group(6),
            "source":
                "Registry/SYSTEM/USBSTOR",
            "event_uid":
                row["event_uid"],
            "registry_last_write":
                row["timestamp"],
        }

    return list(
        devices.values()
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--case",
        required=True,
    )

    args = parser.parse_args()

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
            f"evidence.db integrity: "
            f"{integrity}"
        )

    registry_rows = con.execute(
        """
        SELECT
            event_uid,
            timestamp,
            timestamp_sort,
            registry_hive,
            registry_key,
            registry_value_name,
            registry_value_data
        FROM events
        WHERE lower(source_tool) = 'recmd'
        """
    ).fetchall()

    computer_name = first_registry(
        registry_rows,
        "control\\computername\\computername",
        "computername",
        "system",
    )

    timezone = first_registry(
        registry_rows,
        "control\\timezoneinformation",
        "timezonekeyname",
        "system",
    )

    timezone_bias = first_registry(
        registry_rows,
        "control\\timezoneinformation",
        "activetimebias",
        "system",
    )

    product_name = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "productname",
        "software",
    )

    edition = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "editionid",
        "software",
    )

    build = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "currentbuildnumber",
        "software",
    )

    build_lab = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "buildlabex",
        "software",
    )

    install_date = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "installdate",
        "software",
    )

    registered_owner = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "registeredowner",
        "software",
    )

    system_root = first_registry(
        registry_rows,
        "microsoft\\windows nt\\currentversion",
        "systemroot",
        "software",
    )

    machine_sid = derive_machine_sid(
        registry_rows
    )

    users = parse_sam_users(
        registry_rows
    )

    add_profile_sids(
        users,
        registry_rows,
    )

    add_evtx_logon_context(
        users,
        con,
    )

    network = parse_network(
        registry_rows
    )

    usb = parse_usb(
        registry_rows
    )

    telemetry = {
        "schema_version":
            "1.0",
        "case_id":
            args.case,

        "system_identity": {
            "computer_name":
                computer_name,
            "operating_system":
                product_name,
            "edition":
                edition,
            "build_number":
                build,
            "build_lab":
                build_lab,
            "install_date":
                install_date,
            "registered_owner":
                registered_owner,
            "system_root":
                system_root,
            "machine_sid":
                machine_sid,
            "time_zone":
                timezone,
            "active_time_bias_minutes":
                timezone_bias,
        },

        "network": network,

        "users": users,

        "usb_devices": usb,

        "limitations": [
            (
                "SAM native login count "
                "was not exposed by the "
                "current normalized RECmd "
                "dataset."
            ),
            (
                "SAM native last-login "
                "value was not exposed by "
                "the current normalized "
                "RECmd dataset."
            ),
            (
                "Observed successful logon "
                "counts are derived from "
                "available Windows Event ID "
                "4624 records and must not "
                "be interpreted as the SAM "
                "native login counter."
            ),
            (
                "USB registry LastWrite "
                "timestamps describe registry "
                "artifact timestamps and are "
                "not automatically labeled "
                "as first/last connection "
                "times."
            ),
        ],

        "forensic_safety": {
            "evidence_db_mode":
                "READ_ONLY",
            "database_modified":
                False,
            "qwen_calls":
                0,
        },
    }

    output_dir = (
        case_root
        / "investigation"
        / "system_telemetry_v1"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = (
        output_dir
        / "system_telemetry.json"
    )

    output.write_text(
        json.dumps(
            telemetry,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    con.close()

    print(
        "=" * 90
    )
    print(
        "SYSTEM & FORENSIC TELEMETRY V1"
    )
    print(
        "=" * 90
    )

    def show(
        label,
        obj,
    ):
        if (
            isinstance(obj, dict)
            and "value" in obj
        ):
            value = (
                obj["value"]
                or "NOT AVAILABLE"
            )
        elif obj is None:
            value = "NOT AVAILABLE"
        else:
            value = obj

        print(
            f"{label:28s}: {value}"
        )

    show(
        "Computer Name",
        computer_name,
    )

    show(
        "Operating System",
        product_name,
    )

    show(
        "Build Number",
        build,
    )

    show(
        "Time Zone",
        timezone,
    )

    show(
        "Machine SID",
        machine_sid,
    )

    show(
        "Install Date",
        install_date,
    )

    show(
        "Registered Owner",
        registered_owner,
    )

    print()
    print("NETWORK")

    for item in network:
        print(
            "  Interface:",
            item[
                "interface_guid"
            ],
        )
        print(
            "    IPv4:",
            item.get(
                "ipv4_address",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    DHCP:",
            item.get(
                "dhcp_enabled",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    DHCP Server:",
            item.get(
                "dhcp_server",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    Gateway:",
            item.get(
                "default_gateway",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    DNS:",
            item.get(
                "dns_servers",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    Lease Obtained:",
            item.get(
                "lease_obtained",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    Lease Expires:",
            item.get(
                "lease_expires",
                "NOT AVAILABLE",
            ),
        )

    print()
    print("LOCAL USERS")

    for user in users:
        print(
            " ",
            user["username"],
        )
        print(
            "    RID:",
            user["rid"],
        )
        print(
            "    SID:",
            user.get(
                "sid",
                "NOT AVAILABLE",
            ),
        )
        print(
            "    SAM Login Count:",
            user[
                "sam_login_count"
            ],
        )
        print(
            "    SAM Last Login:",
            user[
                "sam_last_login"
            ],
        )
        print(
            "    Observed 4624 Logons:",
            user[
                "observed_successful_logons"
            ],
        )
        print(
            "    Last Observed 4624:",
            user[
                "last_observed_successful_logon"
            ],
        )

    print()
    print("USB STORAGE")

    for device in usb:
        print(
            " ",
            device["device_name"],
        )
        print(
            "    Serial:",
            device[
                "serial_number"
            ],
        )
        print(
            "    Manufacturer:",
            device[
                "manufacturer"
            ],
        )

    print()
    print(
        "Output:",
        output,
    )
    print(
        "evidence.db: READ ONLY"
    )
    print(
        "Database modified: NO"
    )
    print(
        "Qwen calls: 0"
    )


if __name__ == "__main__":
    main()
