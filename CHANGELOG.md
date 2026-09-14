# Changelog

All notable public changes to DFIR-AI are documented here.

## [2.0.0] - 2026-09-14

### Added

- Live local DFIR web dashboard
- Browser-based forensic evidence upload
- Existing evidence-image selection
- Supported evidence extensions: AD1, E01, DD, RAW, IMG
- Live case/pipeline status polling
- Live investigation phase display
- Stop Investigation control for the active case process tree
- System Telemetry stage
- SAM Telemetry stage
- User-account presentation from current-case SAM evidence
- USB telemetry presentation when available
- On-demand artifact inspector
- Artifact family counts and recent-artifact view
- Bounded deterministic AI routing
- Qwen 4B fast-analysis route
- Selective Qwen 8B deep-analysis route
- STORE_ONLY route for findings that do not require LLM analysis
- RAG-aware deep preparation
- Historical DFIR RAG enrichment with current-case evidence guardrails
- Deterministic case synthesis
- Final DFIR Report V2
- Dashboard findings view
- Live normalized-event and finding counters
- Sequential 3-second sidebar workflow visualization
- Dashboard Stop/Stopped state handling

### Changed

- AI analysis is bounded to routed investigation candidates rather than full-case free-form inference.
- Current-case forensic evidence remains authoritative over historical RAG.
- System facts and account facts are produced deterministically instead of being inferred by an LLM.
- Final synthesis is deterministic and evidence-grounded.
- Dashboard artifact inspection is loaded on demand to keep normal status polling lightweight.
- Pipeline sequencing now places RAG/deep preparation before selective Qwen 8B analysis in the intended V2 workflow.

### Forensic Safeguards

- Original evidence is treated as read-only.
- `event_uid` and provenance are preserved through normalized case facts.
- Correlation does not imply causation.
- Historical similarity is not current-case evidence.
- Detection severity/title alone is not proof of malicious activity.
- Duplicate parser representations of the same source are not automatically independent corroboration.
- Missing artifact families are handled as capability states rather than automatically being fatal.

### Security / Publication

- Evidence images and real case workspaces are excluded from the public repository.
- Generated forensic databases and reports are excluded.
- Local model storage and Qdrant/vector databases are excluded.
- Secrets, `.env` files, credentials, private keys, and local configuration are excluded.
- Development backups and private publication-audit files are excluded.

### Disclaimer

**AI-assisted forensic investigation; analyst validation required. Original evidence remains read-only.**
