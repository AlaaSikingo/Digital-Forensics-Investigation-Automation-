# DFIR-AI V2.0.0 Release Checklist

## Freeze

- [ ] Current dashboard `dashboard/web/index.html` is the accepted stable version.
- [ ] `dashboard_server.py` is the tested version used by the accepted dashboard.
- [ ] Upload works with a real forensic image.
- [ ] Stop Investigation works and leaves generated outputs intact.
- [ ] Artifact inspection works for users, USB, and on-demand artifact families.
- [ ] 3-second sidebar visualization is confirmed.
- [ ] No further UI patches are applied after release candidate creation.

## Pipeline

- [ ] Fresh full-case test completes using `run_full_case_v1.py`.
- [ ] Existing-case resume works using `run_case_v2.py`.
- [ ] System Telemetry is generated.
- [ ] SAM Telemetry is generated.
- [ ] Correlation completes.
- [ ] Clustering completes.
- [ ] Findings are generated.
- [ ] Fast triage routes findings.
- [ ] Qwen 4B only processes FAST_4B routes.
- [ ] Qwen 8B only processes selective DEEP_8B routes.
- [ ] STORE_ONLY is not sent to an LLM.
- [ ] RAG is contextual only.
- [ ] Deep preparation runs before selective Qwen 8B.
- [ ] Deterministic synthesis completes.
- [ ] Final Report V2 is generated.

## Forensic Integrity

- [ ] Original evidence hash remains unchanged during acceptance testing.
- [ ] SQLite integrity checks pass.
- [ ] Foreign key errors = 0.
- [ ] Provenance coverage is validated.
- [ ] `event_uid` grounding is preserved.
- [ ] No current-case fact was sourced only from historical RAG.

## Publication Safety

- [ ] `.gitignore` is installed before `git add`.
- [ ] No AD1/E01/DD/RAW/IMG evidence is tracked.
- [ ] No real `CASE-*` workspace is tracked.
- [ ] No `triage.db`, `evidence.db`, `correlation.db`, or `findings.db` is tracked.
- [ ] No real telemetry JSON is tracked.
- [ ] No generated DFIR report containing case data is tracked.
- [ ] No `.env` is tracked.
- [ ] No API key/token/secret/private key is tracked.
- [ ] No Qdrant database is tracked.
- [ ] No Ollama/local model files are tracked.
- [ ] No historical report corpus is tracked.
- [ ] No private local project-root path remains in public source.
- [ ] No Windows user-profile path remains in public source.
- [ ] No organization-specific hostname/domain/IP/email remains.
- [ ] No development backup file is tracked.

## Documentation

- [ ] README updated for V2.
- [ ] Architecture diagram reviewed.
- [ ] Supported evidence types documented.
- [ ] Installation/run instructions validated.
- [ ] Dashboard screenshot added.
- [ ] CHANGELOG updated.
- [ ] Analyst-validation disclaimer is visible.

## Git

- [ ] `git status` reviewed.
- [ ] `git diff --stat` reviewed.
- [ ] `git diff` reviewed.
- [ ] Release commit created.
- [ ] Tag `v2.0.0` created.
- [ ] Main branch pushed.
- [ ] Tag pushed.
- [ ] GitHub Release notes created from CHANGELOG.
