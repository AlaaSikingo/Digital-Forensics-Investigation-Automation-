# DFIR-AI

Local AI-Assisted Digital Forensics and Incident Response Investigation Platform.

> Status: V0.1 Preview / Active Development

DFIR-AI is a fully local investigation pipeline designed to assist digital forensics and incident response workflows while preserving forensic evidence integrity, provenance, and analyst control.

## Core Design Principles

- Original forensic evidence is never modified.
- Current-case evidence is authoritative.
- Historical DFIR reports are contextual knowledge only.
- RAG similarity is not proof of malicious activity.
- Detection titles and severity values are not proof of malicious activity.
- Every factual finding preserves its event_uid and provenance.
- Hayabusa and EvtxECmd are treated as the same EVTX evidence family.
- Local AI inference runs sequentially.
- Deterministic processing is preferred wherever practical.
- AI output is investigative assistance, not final analyst determination.

## Investigation Pipeline

Evidence Image
      |
      v
Artifact Collection
      |
      v
Forensic Parsing
      |
      v
Normalization
      |
      v
SQLite Evidence Database
      |
      v
Correlation
      |
      v
Evidence Clustering
      |
      v
Findings
      |
      v
Investigation Contexts
      |
      v
Fast Local AI Triage
      |
      v
Selective Deep AI Investigation
      |
      v
Historical DFIR RAG Enrichment
      |
      v
Deterministic Case Synthesis
      |
      v
Final DFIR Report

## Supported DFIR Components

The current implementation integrates or supports:

- MFTECmd
- EvtxECmd
- PECmd
- RECmd
- LECmd
- Hayabusa
- KAPE
- The Sleuth Kit
- SQLite
- Qwen local models through Ollama
- Qdrant
- nomic-embed-text

Third-party forensic tools, binaries, AI models, and evidence images are not distributed with this repository.

## Local AI Investigation

DFIR-AI uses a two-stage local AI workflow.

### Fast Triage

A smaller local Qwen model performs structured triage of findings and determines whether additional deep analysis is required.

### Deep Investigation

Higher-priority or escalated findings are processed by a larger local Qwen model using evidence-grounded investigation contexts.

The AI receives structured evidence references while the application preserves the original finding IDs, event_uids, and provenance outside the model-facing prompt.

## Historical DFIR RAG

Historical incident reports can be indexed in Qdrant and retrieved as investigation context.

The design intentionally separates historical knowledge from current-case evidence.

Historical similarity:

- does not create evidence,
- does not modify current-case facts,
- does not independently establish maliciousness,
- and must not be treated as corroboration of the current investigation.

The historical corpus itself is not distributed in this repository.

## Evidence Provenance

Normalized forensic records preserve unique event identifiers and source provenance.

The investigation pipeline is designed so that findings, correlation results, investigation contexts, and reporting can be traced back to underlying evidence records.

## Validated Pipeline Results

The current pipeline has been validated against publicly available DFIR training evidence.

One fresh E01 validation produced:

- 1,788,878 normalized evidence events
- 1,788,878 unique event_uids
- 1,788,878 provenance records
- 1,054 correlation edges
- 1,036 core clusters
- 2 candidate cross-artifact clusters
- 45 findings
- SQLite integrity check: OK
- Foreign-key errors: 0

Historical DFIR experience retrieval was also validated with:

- The DFIR Report: 1,430 indexed records
- Mandiant: 366 indexed records
- Total Qdrant points: 1,796
- Retrieval testing across 20 realistic DFIR scenarios

These figures represent development validation results and are not performance guarantees.

## Repository Scope

V0.1 contains selected sanitized production source code demonstrating:

- forensic evidence handling
- normalization
- evidence database construction
- deterministic correlation
- evidence clustering
- finding generation
- investigation-context preparation
- local AI triage
- selective deep investigation
- RAG enrichment
- deterministic synthesis
- final report generation

The repository intentionally excludes:

- forensic evidence images
- investigation workspaces
- case databases
- client or company data
- Qdrant storage
- local AI models
- downloaded historical DFIR reports
- third-party forensic binaries
- credentials and local configuration
- development backups and migration utilities

## Security and Privacy

This public repository is prepared from a separate sanitized staging environment.

The private development project is not published directly.

Before release, source files are reviewed for:

- hard-coded local paths
- case-specific regression data
- usernames
- email addresses
- credentials and tokens
- private IP addresses
- internal domains and hostnames
- evidence paths
- client or company identifiers
- embedded private test data
- copyrighted historical report content

## Evidence Used for Development Testing

Development testing uses publicly available DFIR training and challenge evidence, including CyberDefenders material.

Challenge evidence files are not redistributed by this repository. Users should obtain training evidence directly from the original provider.

## Project Status

DFIR-AI is under active development.

V0.1 is intended to demonstrate the forensic architecture, evidence-grounding model, local AI integration, RAG design, and automated investigation workflow.

It should not be treated as a replacement for qualified forensic analysis or analyst validation.

## License

License information will be added before the public V0.1 release.
