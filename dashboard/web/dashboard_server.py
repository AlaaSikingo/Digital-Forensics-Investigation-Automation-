import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
from datetime import datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

MCP_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src" / "mcp"))
WORKSPACE_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "workspace"))
UPLOAD_ROOT = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "uploads"))
TEST_IMAGES = Path(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "test" / "images"))
PYTHON = MCP_ROOT / ".venv" / "Scripts" / "python.exe"
RUN_FULL = MCP_ROOT / "run_full_case_v1.py"
SCRIPT_DIR = Path(__file__).resolve().parent
WEB_ROOT = SCRIPT_DIR if (SCRIPT_DIR / "index.html").exists() else SCRIPT_DIR / "web"

CASES = {}
LOCK = threading.Lock()

PHASES = [
    "Evidence Upload",
    "Prepare Case",
    "Artifact Collection",
    "Parsing",
    "Normalization",
    "System Telemetry",
    "SAM Telemetry",
    "Correlation",
    "Clustering",
    "Findings",
    "Investigation Context",
    "Fast Triage",
    "Qwen 4B",
    "RAG",
    "Deep Preparation",
    "Selective Qwen 8B",
    "Synthesis",
    "Final Report",
]
PHASE_INDEX = {name: i for i, name in enumerate(PHASES)}

PHASE_PATTERNS = [
    ("Prepare Case", [r"PHASE 1 - IMAGE TO EVIDENCE\.DB", r"PREPARE CASE", r"prepare_case_from_image"]),
    ("Artifact Collection", [r"ARTIFACT COLLECTION", r"COLLECT", r"EvidenceReader", r"TRIAGE COLLECTOR", r"AD1"]),
    ("Parsing", [r"PARSING", r"EvtxECmd", r"Hayabusa", r"LECmd", r"PECmd", r"RECmd"]),
    ("Normalization", [r"NORMALIZATION", r"Finish normalization"]),
    ("System Telemetry", [r"SYSTEM TELEMETRY", r"System telemetry"]),
    ("SAM Telemetry", [r"SAM TELEMETRY", r"SAM telemetry"]),
    ("Correlation", [r"CORRELATION", r"Correlation"]),
    ("Clustering", [r"CORE CLUSTERS", r"CANDIDATE CLUSTERS", r"clusters"]),
    ("Findings", [r"FINDINGS", r"Findings"]),
    ("Investigation Context", [r"INVESTIGATION CONTEXT", r"Investigation contexts"]),
    ("Fast Triage", [r"FAST TRIAGE", r"Fast triage"]),
    ("Qwen 4B", [r"QWEN4", r"Qwen4 fast"]),
    ("RAG", [r"RAG", r"RAG enrichment"]),
    ("Deep Preparation", [r"DEEP PREPARATION", r"Prepare deep analysis"]),
    ("Selective Qwen 8B", [r"QWEN INVESTIGATOR", r"Qwen8 selective"]),
    ("Synthesis", [r"CASE SYNTHESIS", r"Case synthesis", r"Prepare synthesis"]),
    ("Final Report", [r"FINAL DFIR REPORT", r"Final report"]),
]

ARTIFACT_FAMILIES = {
    "Event Logs": [".evtx"],
    "Registry": ["\\registry\\", "\\software", "\\system", "\\sam", "ntuser.dat", "usrclass.dat"],
    "Prefetch": [".pf"],
    "LNK": [".lnk"],
    "Jump Lists": ["automaticdestinations-ms", "customdestinations-ms"],
}

SUPPORTED_EXT = {".ad1", ".e01", ".dd", ".raw", ".img"}

def now():
    return datetime.now().strftime("%H:%M:%S")

def safe_case(case_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", case_id):
        raise ValueError("Invalid case ID")
    return case_id

def safe_filename(name):
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    if not name:
        raise ValueError("Invalid filename")
    return name

def detect_phase(line):
    for name, pats in PHASE_PATTERNS:
        for pat in pats:
            if re.search(pat, line, re.I):
                return name
    return None

def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def unwrap_value(v):
    if isinstance(v, dict) and "value" in v:
        return v.get("value")
    return v

def first_value(obj, keys):
    if not isinstance(obj, dict):
        return None
    for k in keys:
        if k in obj and obj[k] not in (None, "", [], {}):
            return unwrap_value(obj[k])
    for v in obj.values():
        if isinstance(v, dict):
            x = first_value(v, keys)
            if x not in (None, "", [], {}):
                return unwrap_value(x)
    return None

def db_count(db, table):
    if not db.is_file():
        return 0
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        row = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        con.close()
        return int(row[0]) if row else 0
    except Exception:
        return 0

def artifact_snapshot(case_dir):
    triage = case_dir / "triage"
    rows = []
    counts = {k: 0 for k in ARTIFACT_FAMILIES}
    total_files = 0
    total_bytes = 0

    if triage.exists():
        files = [p for p in triage.rglob("*") if p.is_file()]
        total_files = len(files)
        for p in files:
            try:
                total_bytes += p.stat().st_size
            except Exception:
                pass
            s = str(p).lower()
            for family, needles in ARTIFACT_FAMILIES.items():
                if any(n.lower() in s for n in needles):
                    counts[family] += 1

        def mtime(p):
            try: return p.stat().st_mtime
            except Exception: return 0

        for p in sorted(files, key=mtime, reverse=True)[:100]:
            try:
                rel = p.relative_to(case_dir)
                size = p.stat().st_size
            except Exception:
                rel = p.name
                size = 0
            family = "Other"
            s = str(p).lower()
            for fam, needles in ARTIFACT_FAMILIES.items():
                if any(n.lower() in s for n in needles):
                    family = fam
                    break
            rows.append({"family": family, "path": str(rel), "size": size})

    return {"counts": counts, "total_files": total_files, "total_bytes": total_bytes, "recent": rows}

def telemetry(case_dir):
    result = {
        "hostname": None,
        "operating_system": None,
        "build": None,
        "primary_user": None,
        "ipv4": None,
        "time_zone": None,
        "machine_sid": None,
        "usb_devices": None,
        "usb_device_details": [],
        "users": [],
        "evidence_integrity": None,
    }

    sysj = read_json(
        case_dir
        / "investigation"
        / "system_telemetry_v1"
        / "system_telemetry.json"
    )

    samj = read_json(
        case_dir
        / "investigation"
        / "sam_telemetry_v1"
        / "sam_telemetry.json"
    )

    if sysj:
        result["hostname"] = first_value(
            sysj,
            ["computer_name", "hostname", "computerName"],
        )

        result["operating_system"] = first_value(
            sysj,
            ["operating_system", "os_name", "product_name"],
        )

        result["build"] = first_value(
            sysj,
            ["build", "current_build", "build_number"],
        )

        result["time_zone"] = first_value(
            sysj,
            ["time_zone", "timezone", "time_zone_name"],
        )

        result["machine_sid"] = first_value(
            sysj,
            ["machine_sid", "machineSid"],
        )

        network = sysj.get("network")
        if isinstance(network, list):
            for interface in network:
                if not isinstance(interface, dict):
                    continue
                ipv4 = interface.get("ipv4_address")
                if ipv4:
                    result["ipv4"] = ipv4
                    break

        if not result["ipv4"]:
            result["ipv4"] = first_value(
                sysj,
                ["ipv4", "ip_address", "ip"],
            )

        usb = sysj.get("usb_devices")

        if isinstance(usb, list):
            result["usb_device_details"] = usb
            result["usb_devices"] = str(len(usb)) + " device(s)"
        elif usb:
            result["usb_devices"] = str(usb)

        result["evidence_integrity"] = "PASS"

    if samj:
        users = samj.get("users") or samj.get("accounts") or []

        if isinstance(users, list):
            result["users"] = users

            candidates = []

            for u in users:
                if not isinstance(u, dict):
                    continue

                name = (
                    u.get("username")
                    or u.get("name")
                    or u.get("account_name")
                )

                rid = str(u.get("rid") or "")

                if name and rid not in ("500", "501"):
                    candidates.append(str(name))

            if candidates:
                result["primary_user"] = candidates[0]

        if not result["machine_sid"]:
            result["machine_sid"] = (
                samj.get("machine_sid")
                or samj.get("machineSid")
            )

    return result


def routing_counts(case_dir):
    out = {"fast_4b": 0, "deep_8b": 0, "store_only": 0}
    db = case_dir / "triage.db"
    if not db.is_file():
        return out
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        rows = con.execute("SELECT planned_route, COUNT(*) FROM triage_routes GROUP BY planned_route").fetchall()
        con.close()
        for route, n in rows:
            if route == "FAST_4B": out["fast_4b"] = n
            elif route == "DEEP_8B": out["deep_8b"] = n
            elif route == "STORE_ONLY": out["store_only"] = n
    except Exception:
        pass
    return out

def findings_preview(case_dir):
    db = case_dir / "findings.db"
    if not db.is_file():
        return []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cols = [r[1] for r in con.execute("PRAGMA table_info(findings)").fetchall()]
        select = [c for c in ["finding_id", "title", "finding_type", "severity"] if c in cols]
        rows = con.execute(f"SELECT {','.join(select)} FROM findings LIMIT 20").fetchall()
        con.close()
        out = []
        for row in rows:
            d = dict(row)
            out.append({
                "priority": d.get("severity", "INFO"),
                "title": d.get("title") or d.get("finding_type") or d.get("finding_id") or "Finding",
            })
        return out
    except Exception:
        return []

def metrics(case_dir):
    arts = artifact_snapshot(case_dir)
    counts = arts["counts"]
    return {
        "event_logs": counts["Event Logs"],
        "registry": counts["Registry"],
        "prefetch": counts["Prefetch"],
        "lnk": counts["LNK"],
        "jump_lists": counts["Jump Lists"],
        "normalized_events": db_count(case_dir / "evidence.db", "events"),
        "findings": db_count(case_dir / "findings.db", "findings"),
    }

def snapshot(case_id):
    with LOCK:
        state = dict(CASES.get(case_id, {}))
        if "events" in state:
            state["events"] = list(state["events"][-250:])
        if "logs" in state:
            state["logs"] = list(state["logs"][-300:])

    case_dir = WORKSPACE_ROOT / case_id
    state["metrics"] = metrics(case_dir)
    state["artifacts"] = artifact_snapshot(case_dir)
    state["telemetry"] = telemetry(case_dir)
    state["users"] = state["telemetry"].get("users", [])
    state["usb_devices"] = state["telemetry"].get("usb_device_details", [])
    state["routing"] = routing_counts(case_dir)
    state["findings"] = findings_preview(case_dir)
    report = case_dir / "report" / f"{case_id}_DFIR_Report_V2.md"
    state["report_ready"] = report.is_file()
    state["report_path"] = str(report) if report.is_file() else None
    return state

def worker(case_id, image_path, profile):
    cmd = [
        str(PYTHON), "-u", str(RUN_FULL),
        "--case", case_id,
        "--image", image_path,
        "--profile", profile,
    ]

    with LOCK:
        CASES[case_id].update({
            "status": "RUNNING",
            "phase": "Prepare Case",
            "phase_index": PHASE_INDEX["Prepare Case"],
            "progress": 4,
            "command": cmd,
        })
        CASES[case_id]["events"].append({
            "time": now(),
            "message": "Evidence ready. Background forensic pipeline started.",
            "type": "good",
        })

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(MCP_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        with LOCK:
            CASES[case_id]["pid"] = proc.pid

        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue

            phase = detect_phase(line)

            with LOCK:
                st = CASES[case_id]
                st["logs"].append(line)
                st["logs"] = st["logs"][-1200:]
                st["events"].append({"time": now(), "message": line, "type": "log"})
                st["events"] = st["events"][-400:]

                if phase:
                    idx = PHASE_INDEX[phase]
                    if idx >= st.get("phase_index", -1):
                        if phase != st.get("phase"):
                            st["events"].append({
                                "time": now(),
                                "message": f"{phase} started",
                                "type": "phase",
                            })
                        st["phase"] = phase
                        st["phase_index"] = idx
                        st["progress"] = max(
                            st.get("progress", 0),
                            round((idx / (len(PHASES) - 1)) * 100, 1),
                        )

        rc = proc.wait()

        with LOCK:
            st = CASES[case_id]
            st["returncode"] = rc

            if st.get("stop_requested"):
                st["status"] = "STOPPED"
                st["events"].append({
                    "time": now(),
                    "message": "Investigation stopped by user.",
                    "type": "phase",
                })
            elif rc == 0:
                st["status"] = "COMPLETE"
                st["phase"] = "Final Report"
                st["phase_index"] = len(PHASES) - 1
                st["progress"] = 100
                st["events"].append({
                    "time": now(),
                    "message": "Final Report V2 generated successfully.",
                    "type": "good",
                })
            else:
                st["status"] = "FAILED"
                st["events"].append({
                    "time": now(),
                    "message": f"Pipeline failed with exit code {rc}",
                    "type": "bad",
                })

    except Exception as exc:
        with LOCK:
            st = CASES[case_id]

            if st.get("stop_requested"):
                st["status"] = "STOPPED"
                st["events"].append({
                    "time": now(),
                    "message": "Investigation stopped by user.",
                    "type": "phase",
                })
            else:
                st["status"] = "FAILED"
                st["error"] = str(exc)
                st["events"].append({
                    "time": now(),
                    "message": f"Backend error: {exc}",
                    "type": "bad",
                })

class Handler(SimpleHTTPRequestHandler):

    def translate_path(self, path):
        rel = urlparse(path).path.lstrip("/") or "index.html"
        return str((WEB_ROOT / rel).resolve())

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/phases":
            return self.send_json({"phases": PHASES})

        if parsed.path == "/api/images":
            items = []
            if TEST_IMAGES.is_dir():
                for p in sorted(TEST_IMAGES.iterdir()):
                    if p.is_file() and p.suffix.lower() in SUPPORTED_EXT:
                        items.append({"name": p.name, "path": str(p)})
            return self.send_json({"images": items})

        if parsed.path == "/api/artifacts":
            q = parse_qs(parsed.query)

            case_id = (q.get("case") or [""])[0]
            family = (q.get("family") or [""])[0]

            if not case_id:
                return self.send_json(
                    {"error": "case required"},
                    400,
                )

            case_dir = WORKSPACE_ROOT / case_id
            triage = case_dir / "triage"

            if not triage.is_dir():
                return self.send_json({
                    "case_id": case_id,
                    "family": family,
                    "items": [],
                    "total": 0,
                })

            requested = family.strip()

            if requested == "File System":
                needles = None
            else:
                needles = ARTIFACT_FAMILIES.get(requested)

                if needles is None:
                    return self.send_json({
                        "case_id": case_id,
                        "family": requested,
                        "items": [],
                        "total": 0,
                    })

            items = []
            total = 0

            for p in triage.rglob("*"):
                if not p.is_file():
                    continue

                rel = p.relative_to(triage)
                low = str(p).lower()

                if needles is not None:
                    if not any(
                        n.lower() in low
                        for n in needles
                    ):
                        continue

                total += 1

                # Bounded response for UI.
                if len(items) >= 500:
                    continue

                try:
                    size = p.stat().st_size
                except Exception:
                    size = 0

                detected_family = requested

                if requested == "File System":
                    detected_family = "File"

                    for fam, fam_needles in ARTIFACT_FAMILIES.items():
                        if any(
                            n.lower() in low
                            for n in fam_needles
                        ):
                            detected_family = fam
                            break

                items.append({
                    "family": detected_family,
                    "path": str(rel),
                    "size": size,
                })

            return self.send_json({
                "case_id": case_id,
                "family": requested,
                "items": items,
                "total": total,
                "returned": len(items),
                "bounded": total > len(items),
            })

        if parsed.path == "/api/status":
            q = parse_qs(parsed.query)
            case_id = (q.get("case") or [""])[0]

            if not case_id:
                return self.send_json({"error": "case required"}, 400)

            return self.send_json(snapshot(case_id))

        return super().do_GET()

    def do_POST(self):

        if self.path == "/api/stop":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(
                    self.rfile.read(n).decode("utf-8")
                )

                case_id = safe_case(
                    str(payload.get("case_id", "")).strip()
                )

                with LOCK:
                    st = CASES.get(case_id)

                    if not st:
                        raise ValueError(
                            f"Case is not active in dashboard: {case_id}"
                        )

                    pid = st.get("pid")

                    if not pid:
                        raise ValueError(
                            f"No active pipeline PID for case: {case_id}"
                        )

                    if st.get("status") in {
                        "COMPLETE",
                        "FAILED",
                        "STOPPED",
                    }:
                        raise ValueError(
                            f"Case is already {st.get('status')}"
                        )

                    st["stop_requested"] = True
                    st["status"] = "STOPPING"

                    st["events"].append({
                        "time": now(),
                        "message": "Stop requested by user.",
                        "type": "phase",
                    })

                result = subprocess.run(
                    [
                        "taskkill",
                        "/PID",
                        str(pid),
                        "/T",
                        "/F",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                return self.send_json({
                    "ok": True,
                    "case_id": case_id,
                    "pid": pid,
                    "taskkill_returncode": result.returncode,
                    "message": "Stop request sent to investigation process tree.",
                })

            except Exception as exc:
                return self.send_json(
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                    400,
                )

        if self.path == "/api/start-existing":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(n).decode("utf-8"))

                case_id = safe_case(str(payload.get("case_id", "")).strip())
                image_path = str(payload.get("image_path", "")).strip()
                profile = str(payload.get("profile", "windows_standard")).strip() or "windows_standard"

                image = Path(image_path)
                if not image.is_file():
                    raise ValueError(f"Evidence image not found: {image}")

                case_dir = WORKSPACE_ROOT / case_id
                if case_dir.exists():
                    raise ValueError(f"Case already exists: {case_dir}. Use a fresh case ID.")

                with LOCK:
                    CASES[case_id] = {
                        "case_id": case_id,
                        "image_path": image_path,
                        "profile": profile,
                        "status": "STARTING",
                        "phase": "Prepare Case",
                        "phase_index": PHASE_INDEX["Prepare Case"],
                        "progress": 0,
                        "events": [],
                        "logs": [],
                    }

                threading.Thread(
                    target=worker,
                    args=(case_id, image_path, profile),
                    daemon=True,
                ).start()

                return self.send_json({"ok": True, "case_id": case_id})

            except Exception as exc:
                return self.send_json({"ok": False, "error": str(exc)}, 400)

        if self.path == "/api/upload-start":
            upload_dir = None
            destination = None

            try:
                case_id = safe_case(
                    str(self.headers.get("X-Case-ID", "")).strip()
                )

                profile = (
                    str(self.headers.get("X-Profile", "windows_standard")).strip()
                    or "windows_standard"
                )

                filename = safe_filename(
                    str(self.headers.get("X-Filename", "")).strip()
                )

                if not filename:
                    raise ValueError("X-Filename header is required")

                if Path(filename).suffix.lower() not in SUPPORTED_EXT:
                    raise ValueError(
                        "Unsupported evidence extension. Expected AD1, E01, DD, RAW, or IMG."
                    )

                content_length = int(
                    self.headers.get("Content-Length", "0")
                )

                if content_length <= 0:
                    raise ValueError("Upload body is empty")

                case_dir = WORKSPACE_ROOT / case_id

                if case_dir.exists():
                    raise ValueError(
                        f"Case already exists: {case_dir}. Use a fresh case ID."
                    )

                upload_dir = UPLOAD_ROOT / case_id

                if upload_dir.exists():
                    raise ValueError(
                        f"Upload directory already exists: {upload_dir}. "
                        "Use a fresh case ID."
                    )

                upload_dir.mkdir(
                    parents=True,
                    exist_ok=False,
                )

                destination = upload_dir / filename

                sha256 = hashlib.sha256()
                total = 0
                remaining = content_length
                chunk_size = 4 * 1024 * 1024

                with destination.open("wb") as out:
                    while remaining > 0:
                        chunk = self.rfile.read(
                            min(chunk_size, remaining)
                        )

                        if not chunk:
                            raise ConnectionError(
                                "Client connection closed before upload completed"
                            )

                        out.write(chunk)
                        sha256.update(chunk)

                        size = len(chunk)
                        total += size
                        remaining -= size

                if total != content_length:
                    raise RuntimeError(
                        f"Upload size mismatch: received {total}, expected {content_length}"
                    )

                try:
                    subprocess.run(
                        ["attrib", "+R", str(destination)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                except Exception:
                    pass

                digest = sha256.hexdigest()

                with LOCK:
                    CASES[case_id] = {
                        "case_id": case_id,
                        "image_path": str(destination),
                        "original_filename": filename,
                        "profile": profile,
                        "status": "STARTING",
                        "phase": "Prepare Case",
                        "phase_index": PHASE_INDEX["Prepare Case"],
                        "progress": 3,
                        "upload": {
                            "bytes": total,
                            "sha256": digest,
                            "stored_path": str(destination),
                        },
                        "events": [
                            {
                                "time": now(),
                                "message": f"Evidence upload complete: {filename}",
                                "type": "good",
                            },
                            {
                                "time": now(),
                                "message": f"SHA256: {digest}",
                                "type": "good",
                            },
                        ],
                        "logs": [],
                    }

                threading.Thread(
                    target=worker,
                    args=(case_id, str(destination), profile),
                    daemon=True,
                ).start()

                return self.send_json({
                    "ok": True,
                    "case_id": case_id,
                    "stored_path": str(destination),
                    "sha256": digest,
                    "bytes": total,
                })

            except Exception as exc:
                try:
                    if destination and destination.exists():
                        destination.unlink()

                    if (
                        upload_dir
                        and upload_dir.exists()
                        and not any(upload_dir.iterdir())
                    ):
                        upload_dir.rmdir()
                except Exception:
                    pass

                return self.send_json(
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                    400,
                )

        return self.send_json({"error": "not found"}, 404)

if __name__ == "__main__":
    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("DFIR-AI LIVE DASHBOARD V3")
    print("=" * 72)
    print("Open: http://127.0.0.1:8765")
    print("Supports browser evidence upload OR existing image selection.")
    print("Uploaded evidence is stored under C:\\DFIR-AI\\uploads\\<CASE>\\")
    print("Pipeline starts automatically after upload.")
    print("=" * 72)

    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
