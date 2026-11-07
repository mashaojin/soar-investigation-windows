# Settings and operations

## Settings panel

- **Gemma prompt:** save a version, compare it on saved evidence, then explicitly activate it. Activation affects future assessment requests, not historical reports or an in-flight request. `prompts/current.txt` is the final instruction exported at repository preparation; a fresh local setup seeds it. `prompts/default.txt` records the built-in fallback instruction.
- **Suricata rule:** read the actual victim rule through its fixed helper, edit the allowed fields, validate, inspect the diff, then explicitly apply. Applying uses the helper's fixed path, configuration test, reload and rollback checks. Host-side edits alone do not change the victim.
- **AI model selection:** choose Ollama or Gemini and activate a provider/model. The tables below the selector give read-only explanations of correlation timing, approved scope, AI/Python roles, model identity and token budgets. These are not editable Python source. Context and output budgets come from the selected lab profile: Mac defaults are 65,536/1,024; Windows defaults are 8,192/1,024. Capacity is not per-incident consumption.

The rule editor controls one SSH rule, not arbitrary files or shell commands. Unknown deployment status requires reading current victim state before another apply.

## Telegram messages

Python templates in `response.py` and `human_review.py` select report, block-request and manual-review messages. Incident metadata supplies the number/time; validated Gemma reports supply assessments/recommendations. Review notices use a short reason and conclusion buttons. Block requests use distinct incident-bound approval/denial buttons. The first-alert timestamp is presented with the Vancouver timezone and UTC offset; it is not the send time.

Do not run the legacy Hermes loop, standalone pilot poller or another bot consumer alongside the monitor. Exactly one configured handler owns polling. Requests expire without action if no authorized answer arrives. Uncertain message delivery is not automatically resent.

## Restart and health

Stop the foreground monitor with Ctrl-C, wait for shutdown, then run the documented monitor command again. The database retains evidence, cursor, labels, reviews and approvals. Stopping the dashboard does not stop the monitor. Starting the dashboard does not start collection.

Use heartbeat-backed Monitor running plus recent collector output and evidence to confirm health. Progress bars show completed workflow stages; they do not promise inference completion time. Pending model calls have a bounded timeout. Manual review can remain open until an operator reviews it or adds a follow-up conclusion.

A reported collection gap stops collection instead of pretending unread history was retained. Inspect the retained files and cursor before recovery. `recover_compressed_rotation.py` is an explicit audited recovery utility for a narrowly verified copytruncate case, not a generic cursor reset. It requires a stopped monitor and a matching retained compressed tail. Never delete state or rebaseline just to hide a gap.

## Private runtime state

The live database is `ssh-live.sqlite3`; `plan-editor.sqlite3` and `lab-experiments.sqlite3` store drafts and experiment state. Back up open SQLite databases with the SQLite backup API, or stop their writers before file copying. Preserve state during demos; a clean database represents a new baseline, not continuity of the old evidence.

Do not publish actual journals, incident databases, approval records, operator identifiers, local configuration or Telegram credentials. The Git ignore rules exclude these from ordinary Git staging. Review files before publishing or sharing a ZIP, since a ZIP made from the entire folder does not honor `.gitignore` automatically.
