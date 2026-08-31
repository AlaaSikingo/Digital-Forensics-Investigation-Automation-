import re
from pathlib import Path


WORKSPACE_ROOT = (Path(__file__).resolve().parents[2] / "workspace")


CASE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)


def validate_case_id(case_id: str) -> str:

    case_id = str(case_id).strip()

    if not case_id:
        raise ValueError(
            "Case ID cannot be empty."
        )

    if not CASE_ID_PATTERN.fullmatch(
        case_id
    ):
        raise ValueError(
            "Invalid case ID. Allowed characters: "
            "letters, numbers, dot, underscore, hyphen."
        )

    return case_id


def get_case_dir(
    case_id: str,
) -> Path:

    case_id = validate_case_id(
        case_id
    )

    workspace = WORKSPACE_ROOT.resolve()

    case_dir = (
        workspace
        / case_id
    ).resolve()

    try:
        case_dir.relative_to(
            workspace
        )

    except ValueError:
        raise ValueError(
            "Case path escapes workspace."
        )

    return case_dir


def require_existing_case(
    case_id: str,
) -> Path:

    case_dir = get_case_dir(
        case_id
    )

    if not case_dir.is_dir():
        raise FileNotFoundError(
            f"Case directory does not exist: "
            f"{case_dir}"
        )

    return case_dir


def case_db(
    case_id: str,
    name: str,
) -> Path:

    if not name.endswith(".db"):
        raise ValueError(
            "Database name must end in .db"
        )

    return (
        get_case_dir(case_id)
        / name
    )


def investigation_dir(
    case_id: str,
    name: str,
) -> Path:

    if not name:
        raise ValueError(
            "Investigation directory name cannot be empty."
        )

    return (
        get_case_dir(case_id)
        / "investigation"
        / name
    )
