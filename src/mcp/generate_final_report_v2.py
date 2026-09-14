
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from report_findings_view_v22 import report_finding_view, safe_display_value, filter_recommendations


WORKSPACE = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace"))


def load_json(path: Path, default=None):

    if default is None:
        default = {}

    if not path.is_file():
        return default

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return default


def table_exists(con, table):

    row = con.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type='table'
          AND name=?
        """,
        (table,)
    ).fetchone()

    return row is not None


def columns_for(con, table):

    if not table_exists(con, table):
        return set()

    return {
        row[1]
        for row in con.execute(
            f"PRAGMA table_info({table})"
        )
    }


def clean(value):

    if value is None:
        return ""

    return str(value).strip()


def first_nonempty(row, fields):

    for field in fields:

        value = clean(
            row.get(field)
        )

        if value:
            return value

    return ""


def report_timestamp_policy(case_dir):

    policy = {
        "source_filesystem_metadata_preserved": None,
        "source_timestamp_trust": "UNKNOWN",
        "target_metadata_timestamp_trust": "UNKNOWN",
    }

    if case_dir is None:
        return policy

    capabilities = load_json(
        Path(case_dir)
        / "provenance"
        / "case_capabilities.json",
        {},
    )

    timestamp_policy = (
        capabilities.get("timestamp_policy")
        if isinstance(capabilities, dict)
        else None
    )

    if isinstance(timestamp_policy, dict):

        for key in policy:

            if key in timestamp_policy:
                policy[key] = timestamp_policy[key]

    return policy


def query_events(db, case_id, case_dir=None):

    result = {
        "total": 0,
        "unique_event_uids": 0,
        "sources": {},
        "artifact_types": {},
        "event_types": {},
        "first_timestamp": "",
        "last_timestamp": "",
        "examples": [],
    }

    if not db.is_file():
        return result

    con = sqlite3.connect(
        str(db)
    )

    con.row_factory = sqlite3.Row

    try:

        if not table_exists(
            con,
            "events"
        ):
            return result

        cols = columns_for(
            con,
            "events"
        )

        timestamp_policy = (
            report_timestamp_policy(
                case_dir
            )
        )

        where = ""
        params = []

        if "case_id" in cols:

            where = " WHERE case_id = ? "
            params = [case_id]

        result["total"] = con.execute(
            f"""
            SELECT COUNT(*)
            FROM events
            {where}
            """,
            params
        ).fetchone()[0]

        if "event_uid" in cols:

            result["unique_event_uids"] = con.execute(
                f"""
                SELECT COUNT(DISTINCT event_uid)
                FROM events
                {where}
                """,
                params
            ).fetchone()[0]

        for field, key in [
            ("source_tool", "sources"),
            ("artifact_type", "artifact_types"),
            ("event_type", "event_types"),
        ]:

            if field not in cols:
                continue

            rows = con.execute(
                f"""
                SELECT
                    {field},
                    COUNT(*) AS n
                FROM events
                {where}
                GROUP BY {field}
                ORDER BY n DESC
                """,
                params
            ).fetchall()

            result[key] = {
                clean(row[0]) or "UNKNOWN":
                    row[1]
                for row in rows
            }

        timestamp_field = None

        for candidate in [
            "timestamp",
            "timestamp_sort",
            "event_time",
            "datetime",
        ]:

            if candidate in cols:
                timestamp_field = candidate
                break

        timeline_where = where
        timeline_params = list(params)
        timeline_filters = []

        #
        # Central analytical timestamp trust policy.
        #
        # Counts and provenance retain all normalized evidence.
        # Only report activity-window/example selection is filtered.
        #
        # For logical containers such as AD1, extracted LNK source
        # filesystem timestamps may reflect collection/extraction
        # metadata rather than the original endpoint filesystem.
        #
        if (
            timestamp_policy.get(
                "source_filesystem_metadata_preserved"
            ) is False
            and "timestamp_source" in cols
            and "source_tool" in cols
        ):
            timeline_filters.append(
                "NOT ("
                "source_tool = 'lecmd' "
                "AND timestamp_source LIKE 'LNK.Source%'"
                ")"
            )

        #
        # Exact LNK sentinel/default timestamp handling.
        #
        # Do not use a broad historical-date cutoff. Older target
        # timestamps remain eligible unless they match this exact
        # known default value and originate from a LNK target field.
        #
        if (
            timestamp_field
            and "timestamp_source" in cols
            and "source_tool" in cols
        ):
            timeline_filters.append(
                "NOT ("
                "source_tool = 'lecmd' "
                f"AND {timestamp_field} = ? "
                "AND timestamp_source IN ("
                "'LNK.TargetCreated', "
                "'LNK.TargetModified', "
                "'LNK.TargetAccessed'"
                ")"
                ")"
            )

            timeline_params.append(
                "2000-01-01 00:00:00"
            )

        if timeline_filters:

            if timeline_where.strip():

                timeline_where = (
                    timeline_where.rstrip()
                    + " AND "
                    + " AND ".join(
                        timeline_filters
                    )
                    + " "
                )

            else:

                timeline_where = (
                    " WHERE "
                    + " AND ".join(
                        timeline_filters
                    )
                    + " "
                )

        if timestamp_field:

            row = con.execute(
                f"""
                SELECT
                    MIN({timestamp_field}),
                    MAX({timestamp_field})
                FROM events
                {timeline_where}
                """,
                timeline_params
            ).fetchone()

            if row:

                result["first_timestamp"] = clean(
                    row[0]
                )

                result["last_timestamp"] = clean(
                    row[1]
                )

        wanted = [
            name
            for name in [
                "event_uid",
                "timestamp",
                "timestamp_type",
                "timestamp_source",
                "source_tool",
                "artifact_type",
                "event_type",
                "path",
                "target_path",
                "executable",
                "command_line",
                "description",
                "hostname",
                "username",
            ]
            if name in cols
        ]

        if wanted:

            order_field = (
                "timestamp"
                if "timestamp" in cols
                else wanted[0]
            )

            rows = con.execute(
                f"""
                SELECT
                    {", ".join(wanted)}
                FROM events
                {timeline_where}
                ORDER BY {order_field}
                LIMIT 500
                """,
                timeline_params
            ).fetchall()

            for raw in rows:

                row = dict(raw)

                result["examples"].append({
                    "event_uid":
                        clean(
                            row.get(
                                "event_uid"
                            )
                        ),

                    "timestamp":
                        clean(
                            row.get(
                                "timestamp"
                            )
                        ),

                    "timestamp_source":
                        clean(
                            row.get(
                                "timestamp_source"
                            )
                        ),

                    "source_tool":
                        clean(
                            row.get(
                                "source_tool"
                            )
                        ),

                    "artifact_type":
                        clean(
                            row.get(
                                "artifact_type"
                            )
                        ),

                    "event_type":
                        clean(
                            row.get(
                                "event_type"
                            )
                        ),

                    "display":
                        first_nonempty(
                            row,
                            [
                                "target_path",
                                "path",
                                "executable",
                                "command_line",
                                "description",
                            ]
                        ),
                })

    finally:
        con.close()

    return result


def artifact_coverage(case_dir):

    triage = (
        case_dir
        / "triage"
    )

    definitions = {
        "MFT":
            triage / "filesystem",

        "EVTX":
            triage / "eventlogs",

        "Registry":
            triage / "registry",

        "Prefetch":
            triage / "prefetch",

        "Amcache":
            triage / "amcache",

        "SRUM":
            triage / "srum",

        "LNK":
            triage / "lnk",

        "PowerShell History":
            triage / "powershell_history",
    }

    result = {}

    for name, path in definitions.items():

        count = 0

        if path.exists():

            if path.is_file():

                count = 1

            elif path.is_dir():

                count = sum(
                    1
                    for item in path.rglob("*")
                    if item.is_file()
                )

        result[name] = count

    return result


def findings_count(db, case_id):

    if not db.is_file():
        return 0

    con = sqlite3.connect(
        str(db)
    )

    try:

        if not table_exists(
            con,
            "findings"
        ):
            return 0

        cols = columns_for(
            con,
            "findings"
        )

        # Prefer the latest successfully completed findings
        # engine run. Historical findings from earlier engine
        # versions/runs must not be mixed into the current report.
        if table_exists(
            con,
            "runs"
        ):

            run_cols = columns_for(
                con,
                "runs"
            )

            required_run_cols = {
                "run_id",
                "status",
            }

            if required_run_cols.issubset(
                run_cols
            ):

                if (
                    "case_id" in run_cols
                    and "completed_utc" in run_cols
                ):

                    latest_run = con.execute(
                        """
                        SELECT run_id
                        FROM runs
                        WHERE case_id = ?
                          AND status = 'COMPLETED'
                        ORDER BY
                            completed_utc DESC,
                            rowid DESC
                        LIMIT 1
                        """,
                        (case_id,)
                    ).fetchone()

                elif "case_id" in run_cols:

                    latest_run = con.execute(
                        """
                        SELECT run_id
                        FROM runs
                        WHERE case_id = ?
                          AND status = 'COMPLETED'
                        ORDER BY rowid DESC
                        LIMIT 1
                        """,
                        (case_id,)
                    ).fetchone()

                elif "completed_utc" in run_cols:

                    latest_run = con.execute(
                        """
                        SELECT run_id
                        FROM runs
                        WHERE status = 'COMPLETED'
                        ORDER BY
                            completed_utc DESC,
                            rowid DESC
                        LIMIT 1
                        """
                    ).fetchone()

                else:

                    latest_run = con.execute(
                        """
                        SELECT run_id
                        FROM runs
                        WHERE status = 'COMPLETED'
                        ORDER BY rowid DESC
                        LIMIT 1
                        """
                    ).fetchone()

                if latest_run:

                    return con.execute(
                        """
                        SELECT COUNT(*)
                        FROM findings
                        WHERE run_id = ?
                        """,
                        (
                            latest_run[0],
                        )
                    ).fetchone()[0]

        # Legacy fallback for older findings databases
        # that do not contain the runs table/run metadata.
        if "case_id" in cols:

            return con.execute(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE case_id = ?
                """,
                (case_id,)
            ).fetchone()[0]

        return con.execute(
            """
            SELECT COUNT(*)
            FROM findings
            """
        ).fetchone()[0]

    finally:
        con.close()


def markdown_table(rows, headers):

    if not rows:
        return ""

    output = []

    output.append(
        "| "
        + " | ".join(headers)
        + " |"
    )

    output.append(
        "|"
        + "|".join(
            "---"
            for _ in headers
        )
        + "|"
    )

    for row in rows:

        values = []

        for value in row:

            text = clean(value)

            text = text.replace(
                "|",
                r"\|"
            )

            text = text.replace(
                "\n",
                " "
            )

            values.append(text)

        output.append(
            "| "
            + " | ".join(values)
            + " |"
        )

    return "\n".join(
        output
    )



def telemetry_value(value, default="NOT AVAILABLE"):

    if value is None:
        return default

    if isinstance(value, dict):

        nested = value.get("value")

        if nested is None:
            return default

        nested = str(nested).strip()

        return nested or default

    text = str(value).strip()

    return text or default


def render_system_telemetry(
    lines,
    system_telemetry,
    sam_telemetry,
):

    lines.append(
        "# 1. System & Forensic Telemetry"
    )

    lines.append("")

    system_identity = (
        system_telemetry.get(
            "system_identity"
        )
        if isinstance(
            system_telemetry,
            dict
        )
        else {}
    ) or {}

    sam_machine_sid = (
        sam_telemetry.get(
            "machine_sid"
        )
        if isinstance(
            sam_telemetry,
            dict
        )
        else None
    )

    machine_sid = (
        sam_machine_sid
        or telemetry_value(
            system_identity.get(
                "machine_sid"
            ),
            "",
        )
        or "NOT AVAILABLE"
    )

    lines.append(
        "## 1.1 System Identity"
    )

    lines.append("")

    identity_rows = [
        [
            "Computer Name",
            telemetry_value(
                system_identity.get(
                    "computer_name"
                )
            ),
        ],
        [
            "Operating System",
            telemetry_value(
                system_identity.get(
                    "operating_system"
                )
            ),
        ],
        [
            "Edition",
            telemetry_value(
                system_identity.get(
                    "edition"
                )
            ),
        ],
        [
            "Build Number",
            telemetry_value(
                system_identity.get(
                    "build_number"
                )
            ),
        ],
        [
            "Build Lab",
            telemetry_value(
                system_identity.get(
                    "build_lab"
                )
            ),
        ],
        [
            "Machine SID",
            machine_sid,
        ],
        [
            "Install Date",
            telemetry_value(
                system_identity.get(
                    "install_date"
                )
            ),
        ],
        [
            "Registered Owner",
            telemetry_value(
                system_identity.get(
                    "registered_owner"
                )
            ),
        ],
        [
            "System Root",
            telemetry_value(
                system_identity.get(
                    "system_root"
                )
            ),
        ],
        [
            "Time Zone",
            telemetry_value(
                system_identity.get(
                    "time_zone"
                )
            ),
        ],
        [
            "Active Time Bias (minutes)",
            telemetry_value(
                system_identity.get(
                    "active_time_bias_minutes"
                )
            ),
        ],
    ]

    lines.append(
        markdown_table(
            identity_rows,
            [
                "Property",
                "Observed Value",
            ],
        )
    )

    lines.append("")
    lines.append(
        "## 1.2 Network Configuration"
    )
    lines.append("")

    network = (
        system_telemetry.get(
            "network"
        )
        if isinstance(
            system_telemetry,
            dict
        )
        else []
    ) or []

    network_rows = []

    for item in network:

        if not isinstance(
            item,
            dict
        ):
            continue

        network_rows.append([
            item.get(
                "interface_guid",
                "NOT AVAILABLE",
            ),
            item.get(
                "ipv4_address",
                "NOT AVAILABLE",
            ),
            item.get(
                "subnet_mask",
                "NOT AVAILABLE",
            ),
            item.get(
                "dhcp_enabled",
                "NOT AVAILABLE",
            ),
            item.get(
                "dhcp_server",
                "NOT AVAILABLE",
            ),
            item.get(
                "default_gateway",
                "NOT AVAILABLE",
            ),
            item.get(
                "dns_servers",
                "NOT AVAILABLE",
            ),
            item.get(
                "lease_obtained",
                "NOT AVAILABLE",
            ),
            item.get(
                "lease_expires",
                "NOT AVAILABLE",
            ),
        ])

    if network_rows:

        lines.append(
            markdown_table(
                network_rows,
                [
                    "Interface",
                    "IPv4 Address",
                    "Subnet Mask",
                    "DHCP",
                    "DHCP Server",
                    "Default Gateway",
                    "DNS",
                    "Lease Obtained",
                    "Lease Expires",
                ],
            )
        )

    else:

        lines.append(
            "No deterministic network telemetry "
            "was available from the collected evidence."
        )

    lines.append("")
    lines.append(
        "## 1.3 Local User Accounts"
    )
    lines.append("")

    users = (
        sam_telemetry.get(
            "users"
        )
        if isinstance(
            sam_telemetry,
            dict
        )
        else []
    ) or []

    user_rows = []

    for user in users:

        if not isinstance(
            user,
            dict
        ):
            continue

        user_rows.append([
            user.get(
                "username",
                "NOT AVAILABLE",
            ),
            user.get(
                "sid",
                "NOT AVAILABLE",
            ),
            user.get(
                "rid",
                "NOT AVAILABLE",
            ),
            user.get(
                "logon_count",
                "NOT AVAILABLE",
            ),
            user.get(
                "last_logon",
                "NOT AVAILABLE",
            )
            or "NOT AVAILABLE",
            user.get(
                "password_last_set",
                "NOT AVAILABLE",
            )
            or "NOT AVAILABLE",
            user.get(
                "failed_logon_count",
                "NOT AVAILABLE",
            ),
            user.get(
                "last_failed_logon",
                "NOT AVAILABLE",
            )
            or "NOT AVAILABLE",
        ])

    if user_rows:

        lines.append(
            markdown_table(
                user_rows,
                [
                    "Username",
                    "SID",
                    "RID",
                    "SAM Login Count",
                    "SAM Last Logon",
                    "Password Last Set",
                    "Failed Logons",
                    "Last Failed Logon",
                ],
            )
        )

        lines.append("")

        lines.append(
            "**Interpretation note:** "
            "SAM Login Count and SAM Last Logon are "
            "derived from the local SAM account record. "
            "They are not counts of Windows Event ID 4624."
        )

    else:

        lines.append(
            "No deterministic local-account telemetry "
            "was available from the SAM evidence."
        )

    lines.append("")
    lines.append(
        "## 1.4 USB / Removable Storage"
    )
    lines.append("")

    usb_devices = (
        system_telemetry.get(
            "usb_devices"
        )
        if isinstance(
            system_telemetry,
            dict
        )
        else []
    ) or []

    usb_rows = []

    for device in usb_devices:

        if not isinstance(
            device,
            dict
        ):
            continue

        usb_rows.append([
            device.get(
                "manufacturer",
                "NOT AVAILABLE",
            ),
            device.get(
                "product",
                "NOT AVAILABLE",
            ),
            device.get(
                "device_name",
                "NOT AVAILABLE",
            ),
            device.get(
                "serial_number",
                "NOT AVAILABLE",
            ),
            device.get(
                "version",
                "NOT AVAILABLE",
            ),
            device.get(
                "disk_id",
                "NOT AVAILABLE",
            ),
        ])

    if usb_rows:

        lines.append(
            markdown_table(
                usb_rows,
                [
                    "Manufacturer",
                    "Product",
                    "Device Name",
                    "Serial Number",
                    "Version",
                    "Disk ID",
                ],
            )
        )

    else:

        lines.append(
            "No deterministic USB storage telemetry "
            "was available from the collected evidence."
        )

    lines.append("")

    system_available = bool(
        system_telemetry
    )

    sam_available = bool(
        sam_telemetry
    )

    lines.append(
        "**Telemetry provenance:** "
        f"System/Registry telemetry: "
        f"{'AVAILABLE' if system_available else 'NOT AVAILABLE'}; "
        f"SAM account telemetry: "
        f"{'AVAILABLE' if sam_available else 'NOT AVAILABLE'}."
    )

    lines.append("")



def event_attributes(
    con,
    event_uid,
):

    if not event_uid:
        return {}

    if not table_exists(
        con,
        "attributes"
    ):
        return {}

    rows = con.execute(
        """
        SELECT
            attribute_key,
            attribute_value
        FROM attributes
        WHERE event_uid = ?
        """,
        (event_uid,),
    ).fetchall()

    result = {}

    for row in rows:

        key = clean(
            row["attribute_key"]
        )

        value = clean(
            row["attribute_value"]
        )

        if key:
            result[key] = value

    return result


def parse_event_payload(
    attributes,
):

    raw = clean(
        attributes.get(
            "payload"
        )
    )

    if not raw:
        return {}

    try:
        obj = json.loads(raw)
    except Exception:
        return {}

    try:
        data = (
            obj.get(
                "EventData",
                {}
            ).get(
                "Data",
                []
            )
        )
    except Exception:
        return {}

    if isinstance(
        data,
        dict
    ):
        data = [data]

    result = {}

    for item in data:

        if not isinstance(
            item,
            dict
        ):
            continue

        name = clean(
            item.get(
                "@Name"
            )
        )

        value = clean(
            item.get(
                "#text"
            )
        )

        if name:
            result[
                name
            ] = value

    return result


def classify_auth_identity(
    username,
):

    value = clean(
        username
    )

    lower = value.lower()

    if not value or value == r"-\-":
        return "UNKNOWN"

    if (
        lower.endswith("$")
        or "\\system" in lower
        or "network service" in lower
        or "local service" in lower
        or "window manager\\" in lower
        or "font driver host\\" in lower
    ):
        return "SYSTEM / SERVICE"

    return "USER / OTHER"


def persistence_observation(
    event_id,
    payload,
    attributes,
):

    if event_id == "7045":

        service = clean(
            payload.get(
                "ServiceName"
            )
        )

        image = (
            clean(
                payload.get(
                    "ImagePath"
                )
            )
            or clean(
                attributes.get(
                    "executable_info"
                )
            )
        )

        start = clean(
            payload.get(
                "StartType"
            )
        )

        account = clean(
            payload.get(
                "AccountName"
            )
        )

        parts = []

        if service:
            parts.append(
                f"Service: {service}"
            )

        if image:
            parts.append(
                f"Image: {image}"
            )

        if start:
            parts.append(
                f"Start: {start}"
            )

        if account:
            parts.append(
                f"Account: {account}"
            )

        return (
            " | ".join(parts)
            or "Service installation event"
        )

    if event_id == "4720":

        target = clean(
            payload.get(
                "TargetUserName"
            )
        )

        domain = clean(
            payload.get(
                "TargetDomainName"
            )
        )

        sid = clean(
            payload.get(
                "TargetSid"
            )
        )

        if target and domain:
            account = (
                domain
                + "\\"
                + target
            )
        else:
            account = (
                target
                or "UNKNOWN"
            )

        parts = [
            f"Account created: {account}"
        ]

        if sid:
            parts.append(
                f"SID: {sid}"
            )

        return " | ".join(parts)

    if event_id in {
        "4728",
        "4732",
    }:

        group = clean(
            payload.get(
                "TargetUserName"
            )
        )

        domain = clean(
            payload.get(
                "TargetDomainName"
            )
        )

        member_name = clean(
            payload.get(
                "MemberName"
            )
        )

        member_sid = clean(
            payload.get(
                "MemberSid"
            )
        )

        if group and domain:
            group_name = (
                domain
                + "\\"
                + group
            )
        else:
            group_name = (
                group
                or "UNKNOWN"
            )

        member = (
            member_name
            if member_name
            and member_name != "-"
            else member_sid
        )

        return (
            f"Group: {group_name}"
            + (
                f" | Member: {member}"
                if member
                else ""
            )
        )

    if event_id == "4698":

        task = (
            clean(
                payload.get(
                    "TaskName"
                )
            )
            or clean(
                payload.get(
                    "TaskContent"
                )
            )
        )

        return (
            f"Scheduled task: {task}"
            if task
            else "Scheduled task created"
        )

    if event_id == "4740":

        target = clean(
            payload.get(
                "TargetUserName"
            )
        )

        return (
            f"Account locked: {target}"
            if target
            else "Account lockout event"
        )

    return (
        clean(
            attributes.get(
                "map_description"
            )
        )
        or "Windows security event"
    )


def query_windows_activity_sections(
    db,
    case_id,
    case_dir=None,
):

    result = {
        "authentication": {
            "counts": {},
            "identity_classes": {},
            "events": [],
        },

        "execution": {
            "prefetch": [],
            "process_creation": [],
        },

        "user_shell": [],

        "persistence_account": {
            "counts": {},
            "events": [],
        },
    }

    if not db.is_file():
        return result

    con = sqlite3.connect(
        "file:"
        + str(db)
        + "?mode=ro",
        uri=True,
    )

    con.row_factory = sqlite3.Row

    try:

        if not table_exists(
            con,
            "events"
        ):
            return result

        cols = columns_for(
            con,
            "events"
        )

        case_filter = ""
        case_params = []

        if "case_id" in cols:

            case_filter = (
                "case_id = ? AND "
            )

            case_params = [
                case_id
            ]

        # ====================================================
        # Authentication
        # ====================================================

        auth_labels = {
            "4624":
                "Successful Logon",

            "4625":
                "Failed Logon",

            "4648":
                "Explicit Credential Use",

            "4672":
                "Special Privileges Assigned",
        }

        placeholders = ",".join(
            "?"
            for _ in auth_labels
        )

        rows = con.execute(
            f"""
            SELECT
                CAST(
                    windows_event_id
                    AS TEXT
                ) AS event_id,
                COUNT(*) AS n
            FROM events
            WHERE
                {case_filter}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) IN ({placeholders})
            GROUP BY
                CAST(
                    windows_event_id
                    AS TEXT
                )
            """,
            case_params
            + list(
                auth_labels.keys()
            ),
        ).fetchall()

        count_map = {
            str(
                row["event_id"]
            ):
                row["n"]
            for row in rows
        }

        result[
            "authentication"
        ][
            "counts"
        ] = {
            event_id: {
                "label":
                    label,
                "count":
                    count_map.get(
                        event_id,
                        0,
                    ),
            }
            for event_id, label
            in auth_labels.items()
        }

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                CAST(
                    windows_event_id
                    AS TEXT
                ) AS event_id,
                username,
                hostname,
                description
            FROM events
            WHERE
                {case_filter}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) IN ({placeholders})
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 250
            """,
            case_params
            + list(
                auth_labels.keys()
            ),
        ).fetchall()

        identity_counts = {}

        auth_events = []

        for row in rows:

            item = dict(row)

            identity_class = (
                classify_auth_identity(
                    item.get(
                        "username"
                    )
                )
            )

            item[
                "identity_class"
            ] = identity_class

            identity_counts[
                identity_class
            ] = (
                identity_counts.get(
                    identity_class,
                    0,
                )
                + 1
            )

            auth_events.append(
                item
            )

        result[
            "authentication"
        ][
            "identity_classes"
        ] = identity_counts

        # USER / OTHER first, then SYSTEM/SERVICE,
        # preserving newest-first order within class.
        # Stable two-stage ordering:
        # newest first inside each identity class,
        # then user-oriented evidence before unknown/service.
        auth_events.sort(
            key=lambda item:
                clean(
                    item.get(
                        "timestamp"
                    )
                ),
            reverse=True,
        )

        auth_events.sort(
            key=lambda item:
                0
                if item[
                    "identity_class"
                ] == "USER / OTHER"
                else 1
                if item[
                    "identity_class"
                ] == "UNKNOWN"
                else 2
        )

        result[
            "authentication"
        ][
            "events"
        ] = auth_events[:30]

        # ====================================================
        # Prefetch - native RunCount
        # ====================================================

        if table_exists(
            con,
            "attributes"
        ):

            rows = con.execute(
                f"""
                SELECT
                    e.event_uid,
                    e.timestamp,
                    e.executable,
                    e.path,

                    MAX(
                        CASE
                            WHEN a.attribute_key
                                 = 'prefetch_hash'
                            THEN a.attribute_value
                        END
                    ) AS prefetch_hash,

                    MAX(
                        CASE
                            WHEN a.attribute_key
                                 = 'run_count'
                            THEN a.attribute_value
                        END
                    ) AS run_count,

                    MAX(
                        CASE
                            WHEN a.attribute_key
                                 = 'run_timestamp_field'
                            THEN a.attribute_value
                        END
                    ) AS run_timestamp_field

                FROM events e

                LEFT JOIN attributes a
                  ON a.event_uid
                   = e.event_uid

                WHERE
                    {case_filter.replace("case_id", "e.case_id")}
                    lower(
                        coalesce(
                            e.source_tool,
                            ''
                        )
                    ) = 'pecmd'

                GROUP BY
                    e.event_uid,
                    e.timestamp,
                    e.executable,
                    e.path

                HAVING
                    run_timestamp_field
                    = 'LastRun'

                ORDER BY
                    e.timestamp DESC
                """,
                case_params,
            ).fetchall()

            prefetch_by_hash = {}

            for row in rows:

                item = dict(row)

                pf_hash = (
                    clean(
                        item.get(
                            "prefetch_hash"
                        )
                    )
                    or clean(
                        item.get(
                            "executable"
                        )
                    )
                    or item[
                        "event_uid"
                    ]
                )

                existing = (
                    prefetch_by_hash.get(
                        pf_hash
                    )
                )

                if (
                    existing is None
                    or clean(
                        item.get(
                            "timestamp"
                        )
                    )
                    > clean(
                        existing.get(
                            "timestamp"
                        )
                    )
                ):
                    prefetch_by_hash[
                        pf_hash
                    ] = item

            result[
                "execution"
            ][
                "prefetch"
            ] = sorted(
                prefetch_by_hash.values(),
                key=lambda item: (
                    int(
                        item.get(
                            "run_count"
                        )
                        or 0
                    ),
                    clean(
                        item.get(
                            "timestamp"
                        )
                    ),
                ),
                reverse=True,
            )[:40]

        # 4688 if available.
        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                username,
                executable,
                command_line,
                path,
                description
            FROM events
            WHERE
                {case_filter}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) = '4688'
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 30
            """,
            case_params,
        ).fetchall()

        result[
            "execution"
        ][
            "process_creation"
        ] = [
            dict(row)
            for row in rows
        ]

        # ====================================================
        # User File / Shell Activity
        # ====================================================

        timestamp_policy = (
            report_timestamp_policy(
                case_dir
            )
        )

        lecmd_conditions = [
            "lower("
            "coalesce(source_tool,'')"
            ") = 'lecmd'"
        ]

        lecmd_params = list(
            case_params
        )

        if (
            timestamp_policy.get(
                "source_filesystem_metadata_preserved"
            )
            is False
        ):
            lecmd_conditions.append(
                "("
                "timestamp_source IS NULL "
                "OR timestamp_source NOT LIKE "
                "'LNK.Source%'"
                ")"
            )

        lecmd_conditions.append(
            "NOT ("
            "timestamp = ? "
            "AND timestamp_source IN ("
            "'LNK.TargetCreated',"
            "'LNK.TargetModified',"
            "'LNK.TargetAccessed'"
            ")"
            ")"
        )

        lecmd_params.append(
            "2000-01-01 00:00:00"
        )

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                timestamp_source,
                username,
                target_path,
                path,
                executable,
                description
            FROM events
            WHERE
                {case_filter}
                {" AND ".join(lecmd_conditions)}
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 100
            """,
            lecmd_params,
        ).fetchall()

        shell_items = []

        seen_shell = set()

        for row in rows:

            item = dict(row)

            display = (
                clean(
                    item.get(
                        "target_path"
                    )
                )
                or clean(
                    item.get(
                        "path"
                    )
                )
                or clean(
                    item.get(
                        "executable"
                    )
                )
                or clean(
                    item.get(
                        "description"
                    )
                )
            )

            safe = safe_display_value(
                display,
                case_dir,
            )

            if (
                not safe
                or safe
                == "[workspace-derived provenance path]"
            ):
                continue

            normalized_safe = (
                safe
                .strip()
                .rstrip("\\/")
                .lower()
            )

            generic_shell_values = {
                "c:\\users",
                "c:\\",
                "c:",
                "\\",
            }

            if (
                normalized_safe
                in generic_shell_values
            ):
                continue

            key = (
                clean(
                    item.get(
                        "timestamp"
                    )
                ),
                safe,
                clean(
                    item.get(
                        "timestamp_source"
                    )
                ),
            )

            if key in seen_shell:
                continue

            seen_shell.add(
                key
            )

            item[
                "activity_source"
            ] = "LNK / Shell"

            item[
                "display_value"
            ] = safe

            shell_items.append(
                item
            )

            if len(
                shell_items
            ) >= 30:
                break

        result[
            "user_shell"
        ] = shell_items

        # ====================================================
        # Persistence / Account Changes
        # ====================================================

        persistence_labels = {
            "4697":
                "Service Installed - Security Log",

            "4698":
                "Scheduled Task Created",

            "4720":
                "Local User Account Created",

            "4728":
                "Member Added to Global Group",

            "4732":
                "Member Added to Local Group",

            "4740":
                "Account Locked Out",

            "7045":
                "Service Installed - System Log",
        }

        placeholders = ",".join(
            "?"
            for _ in persistence_labels
        )

        rows = con.execute(
            f"""
            SELECT
                CAST(
                    windows_event_id
                    AS TEXT
                ) AS event_id,
                COUNT(*) AS n
            FROM events
            WHERE
                {case_filter}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) IN ({placeholders})
            GROUP BY
                CAST(
                    windows_event_id
                    AS TEXT
                )
            """,
            case_params
            + list(
                persistence_labels.keys()
            ),
        ).fetchall()

        count_map = {
            str(
                row["event_id"]
            ):
                row["n"]
            for row in rows
        }

        result[
            "persistence_account"
        ][
            "counts"
        ] = {
            event_id: {
                "label":
                    label,
                "count":
                    count_map.get(
                        event_id,
                        0,
                    ),
            }
            for event_id, label
            in persistence_labels.items()
        }

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                CAST(
                    windows_event_id
                    AS TEXT
                ) AS event_id,
                username,
                hostname,
                description
            FROM events
            WHERE
                {case_filter}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) IN ({placeholders})
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 100
            """,
            case_params
            + list(
                persistence_labels.keys()
            ),
        ).fetchall()

        enriched = []

        for row in rows:

            item = dict(row)

            attrs = event_attributes(
                con,
                item[
                    "event_uid"
                ],
            )

            payload = (
                parse_event_payload(
                    attrs
                )
            )

            item[
                "observation"
            ] = (
                persistence_observation(
                    item[
                        "event_id"
                    ],
                    payload,
                    attrs,
                )
            )

            item[
                "payload"
            ] = payload

            enriched.append(
                item
            )

        result[
            "persistence_account"
        ][
            "events"
        ] = enriched[:50]

    finally:

        con.close()

    return result


def activity_display_value(
    item,
):

    for field in [
        "target_path",
        "path",
        "executable",
        "command_line",
        "registry_value_data",
        "description",
    ]:

        value = clean(
            item.get(field)
        )

        if value:
            return value

    return "NOT AVAILABLE"


def render_windows_activity_sections(
    lines,
    sections,
    case_dir,
):

    # ========================================================
    # 5. User & Authentication Activity
    # ========================================================

    lines.append(
        "# 5. User & Authentication Activity"
    )

    lines.append("")

    auth = (
        sections.get(
            "authentication"
        )
        or {}
    )

    auth_counts = (
        auth.get(
            "counts"
        )
        or {}
    )

    auth_rows = []

    for event_id, item in (
        auth_counts.items()
    ):

        auth_rows.append([
            event_id,
            item.get(
                "label",
                "",
            ),
            item.get(
                "count",
                0,
            ),
        ])

    if auth_rows:

        lines.append(
            markdown_table(
                auth_rows,
                [
                    "Event ID",
                    "Activity",
                    "Normalized EVTX Events",
                ],
            )
        )

    else:

        lines.append(
            "No supported authentication-event "
            "telemetry was available."
        )

    lines.append("")

    auth_events = (
        auth.get(
            "events"
        )
        or []
    )

    if auth_events:

        rows = []

        for item in auth_events[:25]:

            rows.append([
                item.get(
                    "timestamp",
                    "",
                ),
                item.get(
                    "event_id",
                    "",
                ),
                item.get(
                    "username",
                    "",
                ),
                item.get(
                    "identity_class",
                    "",
                ),
                item.get(
                    "hostname",
                    "",
                ),
                item.get(
                    "event_uid",
                    "",
                ),
            ])

        lines.append(
            "### Recent Authentication Evidence"
        )

        lines.append("")

        lines.append(
            markdown_table(
                rows,
                [
                    "Timestamp",
                    "Event ID",
                    "Normalized User",
                    "Identity Class",
                    "Host",
                    "event_uid",
                ],
            )
        )

        lines.append("")

        lines.append(
            "**Interpretation note:** "
            "Authentication counts use EvtxECmd "
            "records only to avoid treating Hayabusa "
            "representation of the same EVTX family "
            "as independent corroboration. "
            "These counts are not SAM Login Count."
        )

    lines.append("")

    # ========================================================
    # 6. Program Execution
    # ========================================================

    lines.append(
        "# 6. Program Execution"
    )

    lines.append("")

    execution = (
        sections.get(
            "execution"
        )
        or {}
    )

    prefetch = (
        execution.get(
            "prefetch"
        )
        or []
    )

    if prefetch:

        lines.append(
            "## 6.1 Prefetch Execution Evidence"
        )

        lines.append("")

        rows = []

        for item in prefetch:

            executable = (
                clean(
                    item.get(
                        "executable"
                    )
                )
                or clean(
                    item.get(
                        "path"
                    )
                )
                or "UNKNOWN"
            )

            rows.append([
                safe_display_value(
                    executable,
                    case_dir,
                ),
                item.get(
                    "prefetch_hash",
                    "",
                ),
                item.get(
                    "run_count",
                    "NOT AVAILABLE",
                ),
                item.get(
                    "timestamp",
                    "",
                ),
                item.get(
                    "event_uid",
                    "",
                ),
            ])

        lines.append(
            markdown_table(
                rows,
                [
                    "Executable",
                    "Prefetch Hash",
                    "Native Run Count",
                    "Last Run",
                    "event_uid",
                ],
            )
        )

        lines.append("")

        lines.append(
            "**Forensic interpretation:** "
            "Run Count is the native Prefetch "
            "RunCount parsed by PECmd. Last Run "
            "uses the PECmd LastRun timestamp. "
            "Extraction/source filesystem timestamps "
            "are not used as execution timestamps."
        )

    else:

        lines.append(
            "No Prefetch execution evidence "
            "was available."
        )

    lines.append("")

    process_creation = (
        execution.get(
            "process_creation"
        )
        or []
    )

    lines.append(
        "## 6.2 Process Creation Events"
    )

    lines.append("")

    if process_creation:

        rows = []

        for item in process_creation:

            observed = (
                clean(
                    item.get(
                        "command_line"
                    )
                )
                or clean(
                    item.get(
                        "executable"
                    )
                )
                or clean(
                    item.get(
                        "path"
                    )
                )
                or clean(
                    item.get(
                        "description"
                    )
                )
            )

            rows.append([
                item.get(
                    "timestamp",
                    "",
                ),
                item.get(
                    "username",
                    "",
                ),
                safe_display_value(
                    observed,
                    case_dir,
                ),
                item.get(
                    "event_uid",
                    "",
                ),
            ])

        lines.append(
            markdown_table(
                rows,
                [
                    "Timestamp",
                    "User",
                    "Process / Command",
                    "event_uid",
                ],
            )
        )

    else:

        lines.append(
            "No normalized Windows Event ID 4688 "
            "process-creation evidence was available."
        )

    lines.append("")

    # ========================================================
    # 7. User File & Shell Activity
    # ========================================================

    lines.append(
        "# 7. User File & Shell Activity"
    )

    lines.append("")

    shell_items = (
        sections.get(
            "user_shell"
        )
        or []
    )

    if shell_items:

        rows = []

        for item in shell_items:

            observed = (
                item.get(
                    "display_value"
                )
                or safe_display_value(
                    activity_display_value(
                        item
                    ),
                    case_dir,
                )
            )

            detail = (
                clean(
                    item.get(
                        "timestamp_source"
                    )
                )
                or clean(
                    item.get(
                        "registry_value_name"
                    )
                )
                or clean(
                    item.get(
                        "registry_key"
                    )
                )
            )

            rows.append([
                item.get(
                    "timestamp",
                    "",
                ),
                item.get(
                    "activity_source",
                    "",
                ),
                item.get(
                    "username",
                    "",
                ),
                observed,
                detail,
                item.get(
                    "event_uid",
                    "",
                ),
            ])

        lines.append(
            markdown_table(
                rows,
                [
                    "Timestamp",
                    "Artifact / Source",
                    "User",
                    "Observed Value",
                    "Evidence Detail",
                    "event_uid",
                ],
            )
        )

        lines.append("")

        lines.append(
            "**Forensic interpretation:** "
            "LNK and shell/user-activity artifacts "
            "can establish interaction with paths, "
            "files, applications, or shell locations. "
            "They do not by themselves establish "
            "malicious intent."
        )

    else:

        lines.append(
            "No supported LNK, Jump List, "
            "RecentDocs, UserAssist, RunMRU, or "
            "TypedPaths evidence was available "
            "in the normalized dataset."
        )

    lines.append("")

    # ========================================================
    # 8. Persistence & Account Changes
    # ========================================================

    lines.append(
        "# 8. Persistence & Account Changes"
    )

    lines.append("")

    persistence = (
        sections.get(
            "persistence_account"
        )
        or {}
    )

    counts = (
        persistence.get(
            "counts"
        )
        or {}
    )

    rows = []

    for event_id, item in counts.items():

        rows.append([
            event_id,
            item.get(
                "label",
                "",
            ),
            item.get(
                "count",
                0,
            ),
        ])

    if rows:

        lines.append(
            markdown_table(
                rows,
                [
                    "Event ID",
                    "Activity",
                    "Normalized EVTX Events",
                ],
            )
        )

    else:

        lines.append(
            "No supported persistence/account-change "
            "event telemetry was available."
        )

    lines.append("")

    persistence_events = (
        persistence.get(
            "events"
        )
        or []
    )

    if persistence_events:

        detail_rows = []

        for item in persistence_events:

            observed = (
                clean(
                    item.get(
                        "observation"
                    )
                )
                or safe_display_value(
                    activity_display_value(
                        item
                    ),
                    case_dir,
                )
            )

            detail_rows.append([
                item.get(
                    "timestamp",
                    "",
                ),
                item.get(
                    "event_id",
                    "",
                ),
                item.get(
                    "username",
                    "",
                ),
                observed,
                item.get(
                    "event_uid",
                    "",
                ),
            ])

        lines.append(
            "### Persistence / Account Change Evidence"
        )

        lines.append("")

        lines.append(
            markdown_table(
                detail_rows,
                [
                    "Timestamp",
                    "Event ID",
                    "User",
                    "Observed Value",
                    "event_uid",
                ],
            )
        )

        lines.append("")

        lines.append(
            "**Interpretation note:** "
            "Presence of a service, task, account, "
            "or group-change event does not by itself "
            "establish maliciousness. Context and "
            "supporting current-case evidence are "
            "required."
        )

    lines.append("")



def select_high_value_evidence(
    db,
    case_id,
    investigative_findings,
    case_dir,
    limit=40,
):

    if not db.is_file():
        return []

    con = sqlite3.connect(
        "file:"
        + str(db)
        + "?mode=ro",
        uri=True,
    )

    con.row_factory = sqlite3.Row

    selected = []
    selected_uids = set()

    try:

        if not table_exists(
            con,
            "events"
        ):
            return []

        # ----------------------------------------------------
        # Build finding-supported UID map.
        # ----------------------------------------------------

        finding_support = {}

        for item in (
            investigative_findings
            or []
        ):

            title = clean(
                item.get(
                    "title"
                )
            ) or "Investigation finding"

            for uid in (
                item.get(
                    "event_uids"
                )
                or []
            ):

                uid = clean(uid)

                if not uid:
                    continue

                finding_support.setdefault(
                    uid,
                    [],
                ).append(
                    title
                )

        def add_row(
            row,
            reason,
            priority,
        ):

            if row is None:
                return

            item = dict(row)

            uid = clean(
                item.get(
                    "event_uid"
                )
            )

            if not uid:
                return

            if uid in selected_uids:
                return

            attrs = event_attributes(
                con,
                uid,
            )

            payload = parse_event_payload(
                attrs
            )

            artifact_type = clean(
                item.get(
                    "artifact_type"
                )
            )

            event_id = clean(
                item.get(
                    "windows_event_id"
                )
            )

            display = ""

            if artifact_type == "evtx":

                if event_id in {
                    "4697",
                    "4698",
                    "4720",
                    "4728",
                    "4732",
                    "4740",
                    "7045",
                }:

                    display = (
                        persistence_observation(
                            event_id,
                            payload,
                            attrs,
                        )
                    )

                else:

                    display = (
                        clean(
                            attrs.get(
                                "map_description"
                            )
                        )
                        or clean(
                            attrs.get(
                                "payload_data"
                            )
                        )
                    )

                    if display in {
                        "{}",
                        "[]",
                        "null",
                    }:
                        display = ""

            elif artifact_type == "registry":

                registry_key = clean(
                    item.get(
                        "registry_key"
                    )
                )

                value_name = clean(
                    item.get(
                        "registry_value_name"
                    )
                )

                value_data = clean(
                    item.get(
                        "registry_value_data"
                    )
                )

                parts = []

                if registry_key:
                    parts.append(
                        registry_key
                    )

                if value_name:

                    if value_data:
                        parts.append(
                            f"{value_name}={value_data}"
                        )
                    else:
                        parts.append(
                            value_name
                        )

                display = " | ".join(
                    parts
                )

            if not display:

                display = first_nonempty(
                    item,
                    [
                        "target_path",
                        "path",
                        "executable",
                        "command_line",
                        "description",
                    ],
                )

            display = safe_display_value(
                display,
                case_dir,
            )

            if (
                not display
                or display
                == "[workspace-derived provenance path]"
            ):
                return

            description = clean(
                item.get(
                    "description"
                )
            )

            event_type = clean(
                item.get(
                    "event_type"
                )
            )

            if (
                description
                == "Registry key LastWrite observation"
                and uid not in finding_support
            ):
                return

            item[
                "display"
            ] = display

            item[
                "selection_reason"
            ] = reason

            item[
                "selection_priority"
            ] = priority

            selected.append(
                item
            )

            selected_uids.add(
                uid
            )

        # ----------------------------------------------------
        # Stage A:
        # Evidence directly referenced by investigative findings.
        # ----------------------------------------------------

        for uid, titles in (
            finding_support.items()
        ):

            row = con.execute(
                """
                SELECT
                    event_uid,
                    timestamp,
                    timestamp_source,
                    source_tool,
                    artifact_type,
                    event_type,
                    path,
                    target_path,
                    executable,
                    command_line,
                    description,
                    hostname,
                    username,
                    windows_event_id,
                    registry_hive,
                    registry_key,
                    registry_value_name,
                    registry_value_data
                FROM events
                WHERE event_uid = ?
                LIMIT 1
                """,
                (uid,),
            ).fetchone()

            unique_titles = []

            for title in titles:

                if title not in unique_titles:
                    unique_titles.append(
                        title
                    )

            reason = (
                "Supports finding: "
                + "; ".join(
                    unique_titles[:2]
                )
            )

            add_row(
                row,
                reason,
                100,
            )

        # ----------------------------------------------------
        # Stage B:
        # Security-relevant Windows observations.
        # Selection means forensic relevance, not maliciousness.
        # ----------------------------------------------------

        high_value_event_ids = [
            "4625",
            "4648",
            "4672",
            "4697",
            "4698",
            "4720",
            "4728",
            "4732",
            "4740",
            "7045",
            "1102",
        ]

        placeholders = ",".join(
            "?"
            for _ in high_value_event_ids
        )

        case_clause = ""
        params = []

        cols = columns_for(
            con,
            "events"
        )

        if "case_id" in cols:
            case_clause = (
                "case_id = ? AND "
            )
            params.append(
                case_id
            )

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                timestamp_source,
                source_tool,
                artifact_type,
                event_type,
                path,
                target_path,
                executable,
                command_line,
                description,
                hostname,
                username,
                windows_event_id
            FROM events
            WHERE
                {case_clause}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'evtxecmd'
                AND CAST(
                    windows_event_id
                    AS TEXT
                ) IN ({placeholders})
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 250
            """,
            params
            + high_value_event_ids,
        ).fetchall()

        for row in rows:

            event_id = clean(
                row["windows_event_id"]
            )

            add_row(
                row,
                (
                    "Windows security/activity "
                    f"event {event_id}"
                ),
                70,
            )

        # ----------------------------------------------------
        # Stage C:
        # Prefetch execution evidence.
        # ----------------------------------------------------

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                timestamp_source,
                source_tool,
                artifact_type,
                event_type,
                path,
                target_path,
                executable,
                command_line,
                description,
                hostname,
                username,
                windows_event_id
            FROM events
            WHERE
                {case_clause}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'pecmd'
                AND coalesce(
                    timestamp_source,
                    ''
                ) NOT LIKE 'Source%'
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 150
            """,
            params,
        ).fetchall()

        for row in rows:

            add_row(
                row,
                "Prefetch execution evidence",
                50,
            )

        # ----------------------------------------------------
        # Stage D:
        # LNK target activity using same timestamp trust policy.
        # ----------------------------------------------------

        timestamp_policy = (
            report_timestamp_policy(
                case_dir
            )
        )

        lnk_extra = ""
        lnk_params = list(
            params
        )

        if (
            timestamp_policy.get(
                "source_filesystem_metadata_preserved"
            )
            is False
        ):
            lnk_extra += (
                " AND ("
                "timestamp_source IS NULL "
                "OR timestamp_source "
                "NOT LIKE 'LNK.Source%'"
                ") "
            )

        lnk_extra += (
            " AND NOT ("
            "timestamp = ? "
            "AND timestamp_source IN ("
            "'LNK.TargetCreated',"
            "'LNK.TargetModified',"
            "'LNK.TargetAccessed'"
            ")"
            ") "
        )

        lnk_params.append(
            "2000-01-01 00:00:00"
        )

        rows = con.execute(
            f"""
            SELECT
                event_uid,
                timestamp,
                timestamp_source,
                source_tool,
                artifact_type,
                event_type,
                path,
                target_path,
                executable,
                command_line,
                description,
                hostname,
                username,
                windows_event_id
            FROM events
            WHERE
                {case_clause}
                lower(
                    coalesce(
                        source_tool,
                        ''
                    )
                ) = 'lecmd'
                {lnk_extra}
            ORDER BY
                coalesce(
                    timestamp_sort,
                    timestamp
                ) DESC
            LIMIT 150
            """,
            lnk_params,
        ).fetchall()

        for row in rows:

            display = first_nonempty(
                dict(row),
                [
                    "target_path",
                    "path",
                    "executable",
                    "description",
                ],
            )

            normalized = (
                clean(display)
                .rstrip("\\/")
                .lower()
            )

            if normalized in {
                r"c:\users",
                "c:\\",
                "c:",
                "\\",
            }:
                continue

            add_row(
                row,
                "User file / shell activity",
                40,
            )

        # ----------------------------------------------------
        # Finding balance, semantic deduplication,
        # EVTX/Hayabusa family handling, and diversity.
        # ----------------------------------------------------

        selected.sort(
            key=lambda item: (
                -int(
                    item.get(
                        "selection_priority",
                        0,
                    )
                ),
                clean(
                    item.get(
                        "timestamp"
                    )
                ),
            )
        )

        # If a finding already has an EVTX observation,
        # do not use Hayabusa representation of the same
        # finding as independent representative evidence.
        reasons_with_evtx = {
            clean(
                item.get(
                    "selection_reason"
                )
            )
            for item in selected
            if clean(
                item.get(
                    "artifact_type"
                )
            ) == "evtx"
            and clean(
                item.get(
                    "selection_reason"
                )
            ).startswith(
                "Supports finding:"
            )
        }

        balanced = []

        finding_counts = {}

        semantic_seen = set()

        contextual_evtx_seen = set()

        contextual_prefetch_seen = set()

        for item in selected:

            reason = clean(
                item.get(
                    "selection_reason"
                )
            )

            family = clean(
                item.get(
                    "artifact_type"
                )
            ) or "other"

            display = clean(
                item.get(
                    "display"
                )
            )

            timestamp = clean(
                item.get(
                    "timestamp"
                )
            )

            if (
                family
                == "hayabusa_detection"
                and reason
                in reasons_with_evtx
            ):
                continue

            is_finding_supported = (
                reason.startswith(
                    "Supports finding:"
                )
            )

            # For contextual EVTX, keep one representative
            # observation per Event ID + normalized user.
            if (
                family == "evtx"
                and not is_finding_supported
            ):

                evtx_key = (
                    clean(
                        item.get(
                            "windows_event_id"
                        )
                    ),
                    clean(
                        item.get(
                            "username"
                        )
                    ).lower(),
                )

                if evtx_key in contextual_evtx_seen:
                    continue

                contextual_evtx_seen.add(
                    evtx_key
                )

            # For contextual Prefetch, keep one row per
            # executable. Finding-supported Prefetch remains
            # untouched.
            if (
                family == "prefetch"
                and not is_finding_supported
            ):

                executable_key = (
                    clean(
                        item.get(
                            "executable"
                        )
                    )
                    or display
                ).lower()

                if (
                    executable_key
                    in contextual_prefetch_seen
                ):
                    continue

                contextual_prefetch_seen.add(
                    executable_key
                )

            # Maximum three representative rows for
            # the exact same finding.
            if reason.startswith(
                "Supports finding:"
            ):

                current = finding_counts.get(
                    reason,
                    0,
                )

                if current >= 3:
                    continue

                finding_counts[
                    reason
                ] = current + 1

            # Semantic duplicate suppression.
            # Useful for multiple normalized Prefetch
            # timestamps representing the same observation.
            semantic_key = (
                family,
                display.lower(),
                timestamp[:19],
                reason,
            )

            if semantic_key in semantic_seen:
                continue

            semantic_seen.add(
                semantic_key
            )

            balanced.append(
                item
            )

        quotas = {
            "evtx": 18,
            "prefetch": 8,
            "lnk": 7,
            "registry": 5,
            "hayabusa_detection": 2,
        }

        family_counts = {}

        diversified = []

        for item in balanced:

            family = (
                clean(
                    item.get(
                        "artifact_type"
                    )
                )
                or "other"
            )

            quota = quotas.get(
                family,
                5,
            )

            current = family_counts.get(
                family,
                0,
            )

            if current >= quota:
                continue

            diversified.append(
                item
            )

            family_counts[
                family
            ] = current + 1

            if len(
                diversified
            ) >= limit:
                break

        # Present chronologically after relevance selection.
        diversified.sort(
            key=lambda item:
                clean(
                    item.get(
                        "timestamp"
                    )
                )
        )

        return diversified

    finally:

        con.close()


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--case",
        required=True
    )

    args = parser.parse_args()

    case_id = args.case

    case_dir = (
        WORKSPACE
        / case_id
    )

    evidence_db = (
        case_dir
        / "evidence.db"
    )

    findings_db = (
        case_dir
        / "findings.db"
    )

    synthesis_path = (
        case_dir
        / "investigation"
        / "case_synthesis_v1"
        / "case_synthesis_deterministic.json"
    )

    system_telemetry_path = (
        case_dir
        / "investigation"
        / "system_telemetry_v1"
        / "system_telemetry.json"
    )

    sam_telemetry_path = (
        case_dir
        / "investigation"
        / "sam_telemetry_v1"
        / "sam_telemetry.json"
    )

    report_dir = (
        case_dir
        / "report"
    )

    report_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output = (
        report_dir
        / f"{case_id}_DFIR_Report_V2.md"
    )

    evidence = query_events(
        evidence_db,
        case_id,
        case_dir
    )

    coverage = artifact_coverage(
        case_dir
    )

    finding_count = findings_count(
        findings_db,
        case_id
    )

    finding_view = report_finding_view(
        findings_db,
        case_id
    )

    investigative_findings = (
        finding_view.get(
            "investigative"
        )
        or []
    )

    execution_inventory = (
        finding_view.get(
            "execution_inventory"
        )
        or []
    )

    synthesis = load_json(
        synthesis_path,
        {}
    )

    system_telemetry = load_json(
        system_telemetry_path,
        {}
    )

    sam_telemetry = load_json(
        sam_telemetry_path,
        {}
    )

    assessment = (
        synthesis.get(
            "overall_assessment"
        )
        or (
            "INSUFFICIENT_EVIDENCE"
            if finding_count == 0
            else "NEEDS_REVIEW"
        )
    )

    priority = (
        synthesis.get(
            "priority"
        )
        or "LOW"
    )

    confidence = (
        synthesis.get(
            "confidence"
        )
        or "MEDIUM"
    )

    absent = [
        name
        for name, count
        in coverage.items()
        if count == 0
    ]

    source_summary = (
        ", ".join(
            f"{name} ({count:,})"
            for name, count
            in evidence[
                "sources"
            ].items()
        )
        if evidence["sources"]
        else "none"
    )

    artifact_summary = (
        ", ".join(
            f"{name} ({count:,})"
            for name, count
            in evidence[
                "artifact_types"
            ].items()
        )
        if evidence[
            "artifact_types"
        ]
        else "none"
    )

    windows_activity = (
        query_windows_activity_sections(
            evidence_db,
            case_id,
            case_dir,
        )
    )

    lines = []

    lines.append(
        "# Digital Forensics & Incident Response Report"
    )

    lines.append("")

    lines.append(
        f"**Case ID:** {case_id}"
    )

    lines.append(
        "**Generated:** "
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    )

    lines.append(
        "**Report Status:** "
        "Analytical Draft - "
        "Analyst Validation Required"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    render_system_telemetry(
        lines,
        system_telemetry,
        sam_telemetry,
    )

    lines.append(
        "# 2. Executive Summary"
    )

    lines.append("")

    lines.append(
        f"Analysis of the available current-case "
        f"forensic evidence identified "
        f"{evidence['total']:,} normalized "
        f"evidence events representing "
        f"{evidence['unique_event_uids']:,} "
        f"unique event_uids."
    )

    lines.append("")

    lines.append(
        f"Normalized artifact representation: "
        f"{artifact_summary}. "
        f"Parser/source representation: "
        f"{source_summary}."
    )

    lines.append("")

    if finding_count == 0:

        lines.append(
            "The investigation engine produced "
            "no finding-level detections from the "
            "available normalized evidence. "
            "This does not establish that the "
            "system or evidence is benign. "
            "It means the available artifact set "
            "and current correlation/detection "
            "logic did not produce a sufficiently "
            "grounded investigation finding."
        )

    else:

        lines.append(
            f"The investigation engine produced "
            f"{finding_count:,} findings. "
            f"The case-level assessment is "
            f"{assessment}, with priority "
            f"{priority} and confidence "
            f"{confidence}."
        )

    lines.append("")

    lines.append(
        f"**Overall Assessment:** "
        f"{assessment}"
    )

    lines.append(
        f"**Investigation Priority:** "
        f"{priority}"
    )

    lines.append(
        f"**Analytical Confidence:** "
        f"{confidence}"
    )

    lines.append("")
    lines.append(
        "# 3. Evidence Coverage"
    )
    lines.append("")

    coverage_rows = []

    for name, count in coverage.items():

        coverage_rows.append([
            name,
            (
                "AVAILABLE"
                if count > 0
                else "NOT AVAILABLE"
            ),
            count,
        ])

    lines.append(
        markdown_table(
            coverage_rows,
            [
                "Artifact Family",
                "Status",
                "Collected Files",
            ]
        )
    )

    lines.append("")

    if absent:

        lines.append(
            "**Evidence limitation:** "
            "The following artifact families "
            "were not available and therefore "
            "could not contribute to correlation "
            "or finding generation: "
            + ", ".join(absent)
            + "."
        )

    lines.append("")
    lines.append(
        "# 4. Normalized Evidence Summary"
    )
    lines.append("")

    lines.append(
        f"- Total normalized events: "
        f"{evidence['total']:,}"
    )

    lines.append(
        f"- Unique normalized event_uids: "
        f"{evidence['unique_event_uids']:,}"
    )

    lines.append(
        f"- Investigation findings: "
        f"{finding_count:,}"
    )

    if evidence["first_timestamp"]:

        lines.append(
            "- Earliest normalized timestamp observed: "
            + evidence[
                "first_timestamp"
            ]
        )

    if evidence["last_timestamp"]:

        lines.append(
            "- Latest normalized timestamp observed: "
            + evidence[
                "last_timestamp"
            ]
        )

    lines.append("")
    lines.append(
        "## 4.1 Evidence by Parser / Source"
    )
    lines.append("")

    source_rows = [
        [name, count]
        for name, count
        in evidence[
            "sources"
        ].items()
    ]

    if source_rows:

        lines.append(
            markdown_table(
                source_rows,
                [
                    "Source Tool",
                    "Normalized Events",
                ]
            )
        )

    else:

        lines.append(
            "No normalized source records "
            "were available."
        )

    lines.append("")
    lines.append(
        "## 4.2 Evidence by Artifact Type"
    )
    lines.append("")

    artifact_rows = [
        [name, count]
        for name, count
        in evidence[
            "artifact_types"
        ].items()
    ]

    if artifact_rows:

        lines.append(
            markdown_table(
                artifact_rows,
                [
                    "Artifact Type",
                    "Normalized Events",
                ]
            )
        )

    else:

        lines.append(
            "No normalized artifact-type "
            "records were available."
        )

    lines.append("")
    render_windows_activity_sections(
        lines,
        windows_activity,
        case_dir,
    )

    lines.append(
        "# 9. High-Value Current-Case Evidence"
    )
    lines.append("")

    lines.append(
        "The entries below were selected "
        "deterministically based on finding support, "
        "forensic relevance, and artifact diversity. "
        "Selection priority does not by itself "
        "establish maliciousness."
    )

    lines.append("")

    examples = (
        select_high_value_evidence(
            evidence_db,
            case_id,
            investigative_findings,
            case_dir,
            limit=40,
        )
    )

    example_rows = []

    for index, item in enumerate(
        examples,
        1
    ):

        display_value = safe_display_value(
            item.get(
                "display",
                ""
            ),
            case_dir
        )

        if (
            display_value
            == "[workspace-derived provenance path]"
        ):
            continue

        example_rows.append([
            len(example_rows) + 1,
            item.get(
                "timestamp",
                ""
            ),
            item.get(
                "artifact_type",
                ""
            ),
            item.get(
                "event_type",
                ""
            ),
            display_value,
            item.get(
                "selection_reason",
                "Forensic context"
            ),
            item.get(
                "event_uid",
                ""
            ),
        ])

    if example_rows:

        lines.append(
            markdown_table(
                example_rows,
                [
                    "#",
                    "Timestamp",
                    "Artifact",
                    "Event Type",
                    "Observed Value",
                    "Why Selected",
                    "event_uid",
                ]
            )
        )

    else:

        lines.append(
            "No representative normalized "
            "evidence records were available."
        )

    lines.append("")
    lines.append(
        "# 10. Investigation Findings"
    )
    lines.append("")

    if investigative_findings:

        lines.append(
            "The findings in this section "
            "represent activity selected for "
            "investigative review. Standalone "
            "Prefetch execution observations are "
            "reported separately in the execution "
            "inventory and are not treated as "
            "malicious findings by default."
        )
        lines.append("")

        for index, item in enumerate(
            investigative_findings,
            1
        ):

            title = (
                item.get("title")
                or f"Finding {index}"
            )

            lines.append(
                f"## 10.{index} {title}"
            )
            lines.append("")

            if item.get("confidence"):

                lines.append(
                    "- Confidence: "
                    + str(
                        item["confidence"]
                    )
                )

            if item.get("severity"):

                lines.append(
                    "- Assessment severity: "
                    + str(
                        item["severity"]
                    )
                )

            uids = (
                item.get(
                    "event_uids"
                )
                or []
            )

            if uids:

                lines.append(
                    "- Supporting event_uids:"
                )

                for uid in uids:

                    lines.append(
                        f"  - `{uid}`"
                    )

            lines.append("")

    else:

        lines.append(
            "No findings from the latest "
            "completed findings run were selected "
            "for active investigative review."
        )
        lines.append("")

    lines.append(
        "# 11. Execution Inventory"
    )
    lines.append("")

    if execution_inventory:

        lines.append(
            "The entries below are deterministic "
            "standalone Prefetch execution "
            "observations. Prefetch establishes "
            "that execution evidence exists; it "
            "does not by itself establish "
            "maliciousness, intent, or compromise."
        )
        lines.append("")

        inventory_rows = []

        for index, item in enumerate(
            execution_inventory,
            1
        ):

            inventory_rows.append([
                index,
                item.get(
                    "title",
                    ""
                ).replace(
                    "Standalone Prefetch execution lead: ",
                    ""
                ),
                item.get(
                    "confidence",
                    ""
                ),
                item.get(
                    "start_timestamp",
                    ""
                ),
                item.get(
                    "end_timestamp",
                    ""
                ),
                item.get(
                    "evidence_count",
                    ""
                ),
            ])

        lines.append(
            markdown_table(
                inventory_rows,
                [
                    "#",
                    "Executable",
                    "Lead Confidence",
                    "First Observed",
                    "Last Observed",
                    "Evidence Refs",
                ]
            )
        )

    else:

        lines.append(
            "No standalone Prefetch execution "
            "observations were recorded in the "
            "latest completed findings run."
        )

    lines.append("")
    lines.append(
        "# 12. Evidence Gaps"
    )
    lines.append("")

    if absent:

        for name in absent:

            lines.append(
                f"- {name} artifacts were not "
                f"available in the collected "
                f"evidence."
            )

    synthesis_gaps = (
        synthesis.get(
            "evidence_gaps"
        )
        or []
    )

    for gap in synthesis_gaps:

        if gap:

            lines.append(
                f"- {gap}"
            )

    if (
        not absent
        and not synthesis_gaps
    ):

        lines.append(
            "- No additional automated "
            "evidence gaps were recorded."
        )

    lines.append("")
    lines.append(
        "# 13. Recommended Next Investigation Steps"
    )
    lines.append("")

    if finding_count == 0:

        lines.append(
            "- Review representative normalized "
            "evidence directly, including paths, "
            "targets, timestamps, arguments, "
            "and artifact metadata."
        )

        lines.append(
            "- Acquire or collect missing "
            "artifact families where available "
            "before making a final incident "
            "determination."
        )

        lines.append(
            "- Treat absence of automated "
            "findings as absence of a detection, "
            "not proof of benign activity."
        )

    else:

        recommendations = (
            synthesis.get(
                "recommended_next_steps"
            )
            or synthesis.get(
                "recommendations"
            )
            or []
        )

        recommendations = filter_recommendations(
            recommendations,
            coverage
        )

        if recommendations:

            for item in recommendations:

                lines.append(
                    f"- {item}"
                )

        else:

            lines.append(
                "- Validate findings against "
                "their referenced current-case "
                "event_uid evidence."
            )

    lines.append("")
    lines.append(
        "# 14. Analytical Conclusion"
    )
    lines.append("")

    if finding_count == 0:

        lines.append(
            f"The current case contains "
            f"{evidence['total']:,} normalized "
            f"forensic events, but no "
            f"finding-level detections were "
            f"generated by the current "
            f"correlation and finding logic. "
            f"The automated assessment is "
            f"{assessment}. This must not be "
            f"interpreted as evidence that the "
            f"examined system was benign or "
            f"uncompromised."
        )

    else:

        conclusion = (
            synthesis.get(
                "analyst_conclusion"
            )
            or synthesis.get(
                "executive_summary"
            )
        )

        if conclusion:

            lines.append(
                conclusion
            )

        else:

            lines.append(
                f"The case produced "
                f"{finding_count:,} investigation "
                f"findings grounded in current-case "
                f"forensic evidence. Analyst "
                f"validation is required before "
                f"final determination."
            )

    lines.append("")
    lines.append(
        "# 15. Evidence and Analytical Safeguards"
    )
    lines.append("")

    lines.append(
        "- Original evidence modification: "
        "not performed by this report generator."
    )

    lines.append(
        "- Current-case normalized evidence "
        "is authoritative for this report."
    )

    lines.append(
        "- Historical RAG references are "
        "context only and are not current-case "
        "evidence."
    )

    lines.append(
        "- Artifact names or detection severity "
        "alone do not establish maliciousness."
    )

    lines.append(
        "- Missing artifact families are "
        "reported as evidence limitations, "
        "not treated as negative evidence."
    )

    lines.append("")
    lines.append(
        "# 16. Analyst Review Requirement"
    )
    lines.append("")

    lines.append(
        "This report is an AI-assisted and "
        "deterministic forensic investigation "
        "draft. All conclusions and "
        "classifications require validation "
        "by a qualified DFIR analyst against "
        "the referenced current-case evidence."
    )

    lines.append("")

    output.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print("=" * 72)
    print("FINAL DFIR REPORT GENERATOR V2")
    print("=" * 72)
    print()
    print(
        "Case:               ",
        case_id
    )
    print(
        "Normalized events:  ",
        f"{evidence['total']:,}"
    )
    print(
        "Evidence event_uids:",
        f"{evidence['unique_event_uids']:,}"
    )
    print(
        "Findings:            ",
        f"{finding_count:,}"
    )
    print(
        "Assessment:          ",
        assessment
    )
    print(
        "Priority:            ",
        priority
    )
    print(
        "Confidence:          ",
        confidence
    )
    print()
    print(
        "Report:",
        output
    )
    print()
    print(
        "Databases modified: 0"
    )
    print(
        "Qwen calls:         0"
    )
    print()
    print(
        "FINAL DFIR REPORT GENERATOR V2: COMPLETE"
    )


if __name__ == "__main__":
    main()
