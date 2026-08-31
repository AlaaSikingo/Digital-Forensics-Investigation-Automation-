import json
from pathlib import Path


MANIFEST_PATH = (Path(__file__).resolve().parents[2] / "tools" / "manifests" / "tools.json")
WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")


class PolicyError(Exception):
    pass


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise PolicyError(f"Manifest not found: {MANIFEST_PATH}")

    with MANIFEST_PATH.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def get_tool(tool_id: str) -> dict:
    manifest = load_manifest()

    for tool in manifest.get("tools", []):
        if tool.get("id") == tool_id:
            return tool

    raise PolicyError(f"Tool not found in manifest: {tool_id}")


def require_action(tool_id: str, action: str, required_policy: str = "AUTO") -> dict:
    tool = get_tool(tool_id)

    if tool.get("status") != "installed":
        raise PolicyError(f"{tool_id} is not marked as installed")

    action_policies = tool.get("action_policies", {})

    actual_policy = action_policies.get(action)

    if actual_policy is None:
        raise PolicyError(
            f"Action '{action}' is not defined for tool '{tool_id}'"
        )

    if actual_policy != required_policy:
        raise PolicyError(
            f"Action '{action}' is {actual_policy}; required policy is {required_policy}"
        )

    return tool


def resolve_executable(tool: dict) -> Path:
    install_path = Path(tool["install_path"])
    executable = install_path / tool["executable"]

    if not executable.exists():
        raise PolicyError(f"Executable not found: {executable}")

    return executable.resolve()


def validate_evtx_input(evidence_path: str) -> tuple[Path, str]:
    path = Path(evidence_path).expanduser()

    if not path.exists():
        raise PolicyError(f"Evidence path does not exist: {path}")

    path = path.resolve()

    if path.is_file():
        if path.suffix.lower() != ".evtx":
            raise PolicyError("Only .evtx files are allowed")
        return path, "file"

    if path.is_dir():
        evtx_files = list(path.rglob("*.evtx"))

        if not evtx_files:
            raise PolicyError(
                f"No .evtx files found in directory: {path}"
            )

        return path, "directory"

    raise PolicyError("Evidence path must be a file or directory")


def validate_case_id(case_id: str) -> str:
    case_id = case_id.strip()

    if not case_id:
        raise PolicyError("case_id cannot be empty")

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_"
    )

    if any(c not in allowed for c in case_id):
        raise PolicyError(
            "case_id may contain only letters, numbers, hyphen and underscore"
        )

    if len(case_id) > 80:
        raise PolicyError("case_id is too long")

    return case_id


def get_case_output_directory(case_id: str, tool_name: str) -> Path:
    case_id = validate_case_id(case_id)

    root = WORKSPACE_ROOT.resolve()
    output = (root / case_id / tool_name).resolve()

    try:
        output.relative_to(root)
    except ValueError:
        raise PolicyError("Output path escaped DFIR-AI workspace")

    output.mkdir(parents=True, exist_ok=True)

    return output
