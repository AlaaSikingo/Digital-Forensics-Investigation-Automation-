from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable
import json
import uuid


WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")
JOBS_ROOT = WORKSPACE_ROOT / ".jobs"

JOBS_ROOT.mkdir(parents=True, exist_ok=True)

_executor = ThreadPoolExecutor(max_workers=2)
_lock = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_file(job_id: str) -> Path:
    return JOBS_ROOT / f"{job_id}.json"


def _write_job(job: dict[str, Any]) -> None:
    path = _job_file(job["job_id"])
    temp_path = path.with_suffix(".json.tmp")

    with _lock:
        temp_path.write_text(
            json.dumps(job, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temp_path.replace(path)


def _read_job(job_id: str) -> dict[str, Any] | None:
    path = _job_file(job_id)

    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def create_job(
    job_type: str,
    tool: str,
    action: str,
    case_id: str,
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())

    job = {
        "job_id": job_id,
        "job_type": job_type,
        "tool": tool,
        "action": action,
        "case_id": case_id,
        "status": "QUEUED",
        "created_at": _utc_now(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
    }

    _write_job(job)
    return job


def _run_job(
    job_id: str,
    func: Callable[..., dict[str, Any]],
    args: tuple,
    kwargs: dict,
) -> None:
    job = _read_job(job_id)

    if job is None:
        return

    job["status"] = "RUNNING"
    job["started_at"] = _utc_now()
    _write_job(job)

    try:
        result = func(*args, **kwargs)

        job = _read_job(job_id) or job
        job["result"] = result
        job["completed_at"] = _utc_now()

        if isinstance(result, dict) and result.get("success") is True:
            job["status"] = "COMPLETED"
        else:
            job["status"] = "FAILED"

            if isinstance(result, dict):
                job["error"] = result.get("error")

        _write_job(job)

    except Exception as exc:
        job = _read_job(job_id) or job
        job["status"] = "FAILED"
        job["completed_at"] = _utc_now()
        job["error"] = str(exc)
        _write_job(job)


def submit_job(
    job_type: str,
    tool: str,
    action: str,
    case_id: str,
    func: Callable[..., dict[str, Any]],
    *args,
    **kwargs,
) -> dict[str, Any]:
    job = create_job(
        job_type=job_type,
        tool=tool,
        action=action,
        case_id=case_id,
    )

    _executor.submit(
        _run_job,
        job["job_id"],
        func,
        args,
        kwargs,
    )

    return {
        "success": True,
        "job_id": job["job_id"],
        "status": "QUEUED",
        "tool": tool,
        "action": action,
        "case_id": case_id,
    }


def get_job_status_record(job_id: str) -> dict[str, Any]:
    job = _read_job(job_id)

    if job is None:
        return {
            "success": False,
            "error_type": "JOB_NOT_FOUND",
            "error": f"Unknown job_id: {job_id}",
        }

    return {
        "success": True,
        "job_id": job["job_id"],
        "job_type": job["job_type"],
        "tool": job["tool"],
        "action": job["action"],
        "case_id": job["case_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "completed_at": job["completed_at"],
        "error": job["error"],
    }


def get_job_result_record(job_id: str) -> dict[str, Any]:
    job = _read_job(job_id)

    if job is None:
        return {
            "success": False,
            "error_type": "JOB_NOT_FOUND",
            "error": f"Unknown job_id: {job_id}",
        }

    if job["status"] in ("QUEUED", "RUNNING"):
        return {
            "success": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "ready": False,
        }

    return {
        "success": True,
        "job_id": job["job_id"],
        "status": job["status"],
        "ready": True,
        "result": job["result"],
        "error": job["error"],
    }
