from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERSION = "rag_enrich_v1"

DEFAULT_QDRANT_URL = "http://localhost:6333"
DEFAULT_COLLECTION = "dfir_reports"

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_EMBED_MODEL = "nomic-embed-text"

DEFAULT_TOP_K = 8
DEFAULT_MAX_REPORTS = 4

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

IMPORTANT_STATES = {
    "REVIEW_REQUIRED",
    "SUSPICIOUS",
    "AMBIGUOUS",
    "ESCALATED",
}

QUERY_JSON_FIELDS = (
    "detection_rules_json",
    "executables_json",
    "paths_json",
    "evidence_families_json",
    "source_tools_json",
)

HISTORICAL_METADATA_FIELDS = (
    "platform",
    "threat_actors",
    "malware",
    "tools",
    "behaviors",
    "attack_phases",
    "mitre_techniques",
    "iocs",
    "evidence_sources",
    "observed_artifacts",
    "investigation_actions",
    "containment_actions",
    "eradication_actions",
    "recovery_actions",
    "detection_opportunities",
    "investigation_findings",
    "investigation_sequence",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def http_json(
    url: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    data = None
    headers = {}

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {exc.code} calling {url}: {details}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Connection failed calling {url}: {exc}"
        ) from exc


def safe_json_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]

    if not isinstance(value, str):
        return [str(value)]

    value = value.strip()
    if not value:
        return []

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return [value]

    if isinstance(parsed, list):
        return [str(x).strip() for x in parsed if str(x).strip()]

    return [str(parsed)]


def unique_strings(items: list[str]) -> list[str]:
    seen = set()
    result = []

    for item in items:
        normalized = item.strip()
        if not normalized:
            continue

        key = normalized.casefold()

        if key in seen:
            continue

        seen.add(key)
        result.append(normalized)

    return result


def open_findings_read_only(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(f"findings.db not found: {path}")

    connection = sqlite3.connect(
        f"file:{path}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    return connection


def load_finding(
    connection: sqlite3.Connection,
    finding_id: str,
) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM findings WHERE finding_id = ?",
        (finding_id,),
    ).fetchone()

    if row is None:
        raise KeyError(f"Finding not found: {finding_id}")

    finding = dict(row)

    evidence_rows = connection.execute(
        """
        SELECT
            event_uid,
            source_tool,
            evidence_family,
            evidence_role
        FROM finding_evidence
        WHERE finding_id = ?
        ORDER BY
            evidence_role,
            evidence_family,
            event_uid
        """,
        (finding_id,),
    ).fetchall()

    finding["supporting_evidence"] = [
        dict(item) for item in evidence_rows
    ]

    return finding


def list_candidate_findings(
    connection: sqlite3.Connection,
) -> list[str]:
    rows = connection.execute(
        """
        SELECT
            finding_id,
            finding_type,
            state,
            confidence,
            severity,
            title,
            detection_rules_json,
            executables_json,
            paths_json,
            evidence_count,
            independent_family_count
        FROM findings
        ORDER BY
            CASE UPPER(severity)
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            evidence_count DESC,
            finding_id
        """
    ).fetchall()

    selected = []
    review_signatures = set()

    for row in rows:
        severity = str(row["severity"] or "").upper()
        state = str(row["state"] or "").upper()

        # Highest-priority findings are always eligible.
        if severity in {"CRITICAL", "HIGH"}:
            selected.append(row["finding_id"])
            continue

        # Explicitly suspicious/ambiguous/escalated findings are always eligible.
        if state in {"SUSPICIOUS", "AMBIGUOUS", "ESCALATED"}:
            selected.append(row["finding_id"])
            continue

        # Unassessed findings remain unresolved and benefit from historical context.
        if severity == "UNASSESSED":
            selected.append(row["finding_id"])
            continue

        # REVIEW_REQUIRED is too broad to use by itself.
        # For MEDIUM findings, query only one representative for each
        # distinct semantic detection/artifact signature.
        if severity == "MEDIUM" and state == "REVIEW_REQUIRED":
            signature = (
                str(row["finding_type"] or ""),
                str(row["title"] or ""),
                str(row["detection_rules_json"] or ""),
                str(row["executables_json"] or ""),
                str(row["paths_json"] or ""),
            )

            if signature not in review_signatures:
                review_signatures.add(signature)
                selected.append(row["finding_id"])

    return selected


def build_search_query(
    finding: dict[str, Any],
) -> str:
    parts = []

    title = str(finding.get("title") or "").strip()
    summary = str(finding.get("summary") or "").strip()
    finding_type = str(finding.get("finding_type") or "").strip()

    if title:
        parts.append(title)

    if finding_type:
        parts.append(f"finding type: {finding_type}")

    if summary:
        parts.append(summary)

    labels = {
        "detection_rules_json": "detections",
        "executables_json": "executables",
        "paths_json": "paths",
        "evidence_families_json": "evidence",
        "source_tools_json": "source tools",
    }

    for field in QUERY_JSON_FIELDS:
        values = unique_strings(
            safe_json_list(finding.get(field))
        )

        if values:
            parts.append(
                f"{labels[field]}: {', '.join(values[:8])}"
            )

    evidence = finding.get("supporting_evidence") or []

    evidence_families = unique_strings([
        str(item.get("evidence_family") or "")
        for item in evidence
    ])

    if evidence_families:
        parts.append(
            "supporting evidence families: "
            + ", ".join(evidence_families[:8])
        )

    query = " | ".join(parts)

    # Keep embeddings concise and avoid stuffing entire finding records.
    return query[:3000]


def embed_text(
    text: str,
    ollama_url: str,
    model: str,
) -> list[float]:
    base = ollama_url.rstrip("/")

    # Preferred modern Ollama endpoint.
    try:
        response = http_json(
            f"{base}/api/embed",
            method="POST",
            body={
                "model": model,
                "input": text,
            },
            timeout=180,
        )

        embeddings = response.get("embeddings")

        if (
            isinstance(embeddings, list)
            and embeddings
            and isinstance(embeddings[0], list)
        ):
            return [float(x) for x in embeddings[0]]

    except RuntimeError:
        pass

    # Compatibility fallback.
    response = http_json(
        f"{base}/api/embeddings",
        method="POST",
        body={
            "model": model,
            "prompt": text,
        },
        timeout=180,
    )

    embedding = response.get("embedding")

    if not isinstance(embedding, list) or not embedding:
        raise RuntimeError(
            "Ollama returned no embedding vector."
        )

    return [float(x) for x in embedding]


def search_qdrant(
    vector: list[float],
    qdrant_url: str,
    collection: str,
    limit: int,
) -> list[dict[str, Any]]:
    base = qdrant_url.rstrip("/")

    body = {
        "vector": vector,
        "limit": limit,
        "with_payload": True,
        "with_vector": False,
    }

    try:
        response = http_json(
            f"{base}/collections/{collection}/points/search",
            method="POST",
            body=body,
            timeout=120,
        )

        result = response.get("result", [])

        if isinstance(result, list):
            return result

    except RuntimeError:
        pass

    # Qdrant newer query endpoint fallback.
    response = http_json(
        f"{base}/collections/{collection}/points/query",
        method="POST",
        body={
            "query": vector,
            "limit": limit,
            "with_payload": True,
            "with_vector": False,
        },
        timeout=120,
    )

    result = response.get("result", {})

    if isinstance(result, dict):
        points = result.get("points", [])
        if isinstance(points, list):
            return points

    raise RuntimeError(
        "Qdrant returned an unexpected search response."
    )


def historical_metadata(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        field: payload.get(field)
        for field in HISTORICAL_METADATA_FIELDS
        if field in payload
    }


def deduplicate_results(
    raw_hits: list[dict[str, Any]],
    max_reports: int,
) -> list[dict[str, Any]]:
    """
    Keep the highest-scoring chunk per historical report.

    document_id is the primary report-level dedup key.
    filename/source/title are fallback keys only.
    """
    reports: dict[str, dict[str, Any]] = {}

    for hit in raw_hits:
        payload = hit.get("payload") or {}

        document_id = str(
            payload.get("document_id")
            or payload.get("filename")
            or payload.get("source_url")
            or payload.get("title")
            or hit.get("id")
        )

        score = float(hit.get("score") or 0.0)

        candidate = {
            "reference_type": "historical_reference",
            "historical_only": True,
            "case_fact": False,

            "similarity_score": score,

            "qdrant_point_id": hit.get("id"),

            "document_id": payload.get("document_id"),
            "source": payload.get("source"),
            "title": payload.get("title"),
            "source_url": payload.get("source_url"),
            "published_date": payload.get("published_date"),
            "filename": payload.get("filename"),
            "file_hash": payload.get("file_hash"),

            "chunk_id": payload.get("chunk_id"),
            "chunk_count": payload.get("chunk_count"),

            "metadata": historical_metadata(payload),

            "retrieved_text": payload.get("text", ""),
        }

        previous = reports.get(document_id)

        if (
            previous is None
            or score > previous["similarity_score"]
        ):
            reports[document_id] = candidate

    ranked = sorted(
        reports.values(),
        key=lambda item: item["similarity_score"],
        reverse=True,
    )

    return ranked[:max_reports]


def build_output(
    finding: dict[str, Any],
    query: str,
    references: list[dict[str, Any]],
    collection: str,
    embed_model: str,
) -> dict[str, Any]:
    event_uids = unique_strings([
        str(item.get("event_uid") or "")
        for item in finding.get("supporting_evidence", [])
    ])

    return {
        "schema_version": "1.0",
        "engine": VERSION,
        "created_utc": utc_now(),

        "case_id": finding.get("case_id"),
        "finding_id": finding.get("finding_id"),

        "grounding": {
            "finding_id": finding.get("finding_id"),
            "event_uids": event_uids,
            "source_database": "findings.db",
            "source_database_access": "read_only",
        },

        "case_finding": {
            "finding_type": finding.get("finding_type"),
            "state": finding.get("state"),
            "confidence": finding.get("confidence"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "summary": finding.get("summary"),
            "source_kind": finding.get("source_kind"),
            "source_id": finding.get("source_id"),
            "start_timestamp": finding.get("start_timestamp"),
            "end_timestamp": finding.get("end_timestamp"),
            "evidence_count": finding.get("evidence_count"),
            "independent_family_count":
                finding.get("independent_family_count"),
            "supporting_evidence":
                finding.get("supporting_evidence", []),
        },

        "retrieval": {
            "purpose": "historical_context_enrichment",
            "search_query": query,
            "embedding_model": embed_model,
            "qdrant_collection": collection,
            "reference_count": len(references),
        },

        "safety": {
            "retrieved_material_class":
                "historical_reference",
            "historical_reports_are_case_evidence": False,
            "historical_reports_create_case_facts": False,
            "historical_similarity_implies_maliciousness": False,
            "investigation_sequence_semantic_authority": False,
            "analyst_validation_required": True,
        },

        "historical_references": references,
    }


def save_result(
    output_dir: Path,
    result: dict[str, Any],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    finding_id = str(result["finding_id"])

    path = output_dir / f"{finding_id}.rag.json"

    path.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path


def enrich_one(
    connection: sqlite3.Connection,
    finding_id: str,
    output_dir: Path,
    qdrant_url: str,
    collection: str,
    ollama_url: str,
    embed_model: str,
    top_k: int,
    max_reports: int,
    dry_query: bool,
) -> dict[str, Any]:
    finding = load_finding(connection, finding_id)
    query = build_search_query(finding)

    print()
    print("=" * 72)
    print(f"Finding: {finding_id}")
    print(f"Severity: {finding.get('severity')}")
    print(f"State: {finding.get('state')}")
    print(f"Title: {finding.get('title')}")
    print()
    print("RAG QUERY:")
    print(query)

    if dry_query:
        return {
            "finding_id": finding_id,
            "query": query,
            "dry_query": True,
        }

    vector = embed_text(
        query,
        ollama_url=ollama_url,
        model=embed_model,
    )

    if len(vector) != 768:
        raise RuntimeError(
            f"Unexpected embedding dimension: "
            f"{len(vector)}; expected 768"
        )

    raw_hits = search_qdrant(
        vector=vector,
        qdrant_url=qdrant_url,
        collection=collection,
        limit=top_k,
    )

    references = deduplicate_results(
        raw_hits=raw_hits,
        max_reports=max_reports,
    )

    output = build_output(
        finding=finding,
        query=query,
        references=references,
        collection=collection,
        embed_model=embed_model,
    )

    path = save_result(
        output_dir=output_dir,
        result=output,
    )

    print()
    print(f"Historical references: {len(references)}")

    for index, ref in enumerate(references, 1):
        print(
            f"{index}. "
            f"score={ref['similarity_score']:.4f} | "
            f"{ref.get('source')} | "
            f"{ref.get('title')} | "
            f"chunk={ref.get('chunk_id')}"
        )

    print()
    print(f"Written: {path}")

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "RAG Enrichment v1 - historical DFIR report "
            "retrieval only. No Qwen inference."
        )
    )

    parser.add_argument(
        "--case-dir",
        required=True,
        help="Case directory, e.g. C:\\DFIR-AI-PUBLIC\\workspace\\CASE-DEMO",
    )

    parser.add_argument(
        "--finding-id",
        help="Enrich one specific finding.",
    )

    parser.add_argument(
        "--important",
        action="store_true",
        help=(
            "Enrich dynamically selected important findings "
            "(HIGH/CRITICAL or review/suspicious/ambiguous states)."
        ),
    )

    parser.add_argument(
        "--dry-query",
        action="store_true",
        help=(
            "Build and display queries only. "
            "Does NOT call Ollama or Qdrant vector search."
        ),
    )

    parser.add_argument(
        "--qdrant-url",
        default=DEFAULT_QDRANT_URL,
    )

    parser.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
    )

    parser.add_argument(
        "--ollama-url",
        default=DEFAULT_OLLAMA_URL,
    )

    parser.add_argument(
        "--embed-model",
        default=DEFAULT_EMBED_MODEL,
    )

    parser.add_argument(
        "--top-k",
        type=int,
        default=DEFAULT_TOP_K,
    )

    parser.add_argument(
        "--max-reports",
        type=int,
        default=DEFAULT_MAX_REPORTS,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.finding_id and not args.important:
        raise SystemExit(
            "Specify --finding-id or --important."
        )

    if args.finding_id and args.important:
        raise SystemExit(
            "Use either --finding-id or --important, not both."
        )

    case_dir = Path(args.case_dir).resolve()

    findings_db = case_dir / "findings.db"

    output_dir = (
        case_dir
        / "investigation"
        / "rag_v1"
        / "results"
    )

    connection = open_findings_read_only(findings_db)

    try:
        if args.finding_id:
            finding_ids = [args.finding_id]
        else:
            finding_ids = list_candidate_findings(connection)

        print("=" * 72)
        print("RAG ENRICHMENT V1")
        print("=" * 72)
        print(f"Case: {case_dir.name}")
        print(f"Findings DB: {findings_db}")
        print("Findings DB mode: READ ONLY")
        print(f"Collection: {args.collection}")
        print(f"Embedding model: {args.embed_model}")
        print(f"Selected findings: {len(finding_ids)}")
        print(f"Dry query: {args.dry_query}")
        print("Qwen calls: ZERO")

        results = []

        for finding_id in finding_ids:
            result = enrich_one(
                connection=connection,
                finding_id=finding_id,
                output_dir=output_dir,
                qdrant_url=args.qdrant_url,
                collection=args.collection,
                ollama_url=args.ollama_url,
                embed_model=args.embed_model,
                top_k=args.top_k,
                max_reports=args.max_reports,
                dry_query=args.dry_query,
            )
            results.append(result)

        print()
        print("=" * 72)
        print("RAG V1 COMPLETE")
        print("=" * 72)
        print(f"Processed: {len(results)}")

        if args.dry_query:
            print("No embeddings requested.")
            print("No vector searches performed.")
            print("No result JSON written.")

        return 0

    finally:
        connection.close()


if __name__ == "__main__":
    sys.exit(main())
