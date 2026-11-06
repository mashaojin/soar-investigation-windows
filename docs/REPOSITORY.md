# Repository contents and publication

## Source layout

Runtime Python modules remain at the repository root to preserve sibling imports and victim-side helper loading. `config/` contains public examples, `fixtures/` deterministic synthetic inputs, `tests/` offline regressions, `web/` dashboard assets, `rules/` the sensor rule, `prompts/` exported instructions, and `docs/` reproducible guides and sanitized evaluation results. Existing Mac/UTM defaults are retained alongside the Windows profile.

## Private operational state

Keep `.env`, `*.local.json`, `rule-editor-enabled.json`, actual plan registries, databases, locks, model receipts and private logs local. They are ignored. `configure_local.py` initializes absent files; it preserves an existing live configuration rather than silently resetting it. Never force-add these files or copy Mac operational state into a new Windows profile.

`local-artifacts/` is ignored and contains diagnostic archives, prior documentation, upstream reference copies, release checks and optional review checkouts. Archival session scripts are historical evidence, not setup dependencies. Preserve archives privately; never upload them as release assets. Nothing in the cleanup requires deletion of evidence or credentials.

## Preparing a review checkout

This repository is `mashaojin/soar-investigation-windows`, a separate private Windows project with `main` as its default branch. The original Mac project remains at `mashaojin/soc-pipeline`. Its existing Windows-port branch is historical and is not the clone target for this distribution.

Clone the Windows repository, then use a topic branch for future changes. Preserve upstream attribution and compare incoming changes before applying them; do not overwrite local differences or copy operational state from either project.

The offline suite must pass from this clean checkout without VMs, Ollama, Telegram credentials or operational databases. Also run the dashboard JavaScript syntax checks. Review untracked files as well as tracked changes: a new module or workflow must not be omitted accidentally.

```sh
python3 -m unittest discover -s tests -q
node --check web/app.js
node --check web/experiments.js
python3 tools/check_release.py
git diff --check
git status --short
```

Before committing, inspect the complete selected-file list and diff for credentials, private keys, actual authorization records, approved plans, incident databases, private logs and host-specific paths. Secret-pattern scans are a useful check, not a guarantee. Do not force-add ignored content. Examples must contain placeholders, not working credentials or approvals. Existing screenshot assets should be reviewed before changing repository visibility.

A release export follows Git's included-file list, never a recursive copy of the live workspace. Do not include local archives or the archive manifest. Describe actual verification precisely: helper deny/rollback was verified separately; the complete valid-AI → Telegram YES → worker path remains unverified on Windows. Keep known model-quality failures visible.

Commit, push, PR publication and repository visibility changes require explicit operator instructions. This preparation does not perform them. No license grant is inferred; preserve existing licensing and obtain a separate decision if a license is needed.
