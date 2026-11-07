# Dashboard guide — Windows / WSL2 / Hyper-V

This guide follows the controls in the current dashboard: **New test plan**, **Plans**, **Settings**, incident evidence and **Human review**. Complete the platform setup first. Opening a panel or changing browser text does not start the monitor or apply a saved version.

Inside the initialized WSL checkout, start `python3 windows_lab.py dashboard` and open [http://127.0.0.1:8765](http://127.0.0.1:8765) in Windows. The dashboard launcher does not load bot credentials or start collection, inference or polling. Follow [Windows setup and explicit operating modes](WINDOWS.md).

## Contents

- [Read the overview and incident details](#1-read-the-overview-and-incident-details)
- [Create, validate and approve a test plan](#2-create-validate-and-approve-a-test-plan)
- [View and repeat existing plans](#3-view-and-repeat-existing-plans)
- [Read, validate and apply a Suricata rule](#4-read-validate-and-apply-a-suricata-rule)
- [Save, compare and activate a prompt](#5-save-compare-and-activate-a-prompt)
- [Select an AI model](#6-select-an-ai-model)
- [Record a human review](#7-record-a-human-review)
- [Know when changes take effect](#8-know-when-changes-take-effect)
- [Repeat an experiment and troubleshoot](#9-repeat-an-experiment-and-troubleshoot)

## 1. Read the overview and incident details

![Shared dashboard illustrated by the original Mac/UTM lab](images/dashboard-overview.jpg)

*This is a historical Mac/UTM screenshot of the shared UI, not evidence of Windows live enforcement or current Windows model quality. Use your configured Windows identities and see [screenshot provenance](SCREENSHOTS.md).*

| Area/control | What to inspect | What it does |
| --- | --- | --- |
| Response mode in the header | Dry run versus LIVE, and any assessment-mode notice | Reports the configured mode; it is not a toggle or approval |
| Monitor health strip | Fresh heartbeat and collector/worker state | Distinguishes a running service from merely saved data |
| Incident history | Source, incident number/time, AI verdict and workflow status | Selects one saved incident for inspection |
| Selected incident | Source → Victim TCP/22, revision and correlation window | Identifies exactly which retained case is displayed |
| Investigation stages | Completed stages and the current phase | Shows workflow completion, not a predictable percentage of elapsed processing time |
| AI assessment | Advisory explanation, citations, suggested next step and model identity | Displays model interpretation alongside recorded facts and a separate human conclusion |
| Observed facts / Python scope comparisons | Journal counts, account names, recorded plan, limits and coverage | Shows the evidence supporting or limiting that assessment |
| Authorization context | Recorded plan match or no match | Distinguishes the incident's saved authorization from a merely scheduled future plan |
| Telegram and response | Delivery, pending decision, denial, expiry, block and rollback state | Reports the separate response workflow and any execution receipt |
| Next test plan | Next active/upcoming approved plan | A scheduling aid; it may not be the plan matched to the selected incident |
| Refresh | Latest saved dashboard state | Reads state again; it does not rerun a model, retry an action or start a stopped monitor |

Severity and workflow answer different questions. A red **Suspicious** AI verdict can coexist with yellow **More evidence requested** workflow status. If validation rejected the output, there is no accepted AI verdict even if the retained raw text contains a label. A separate human conclusion can disagree with the model without replacing its original output.

Expand **Original AI output and evidence references**, **Checked factual claims**, **Inspect recorded data** and **Live execution receipt** when present. Use them to distinguish an interpretation from actual observations, a proposal from an approval, and a dispatch from verified rollback. A report-only incident need not have a live receipt.

**Before a demonstration:** confirm a healthy collector, intended response mode and available inference path. Windows collection-only mode defers assessment. An experimental/unverified banner means every result requires review and response actions are disabled in that mode. An accepted live mode still requires a valid assessment and exact Telegram approval; the dashboard does not grant model readiness.

## 2. Create, validate and approve a test plan

A plan authorizes a bounded failed-login test. It does not authorize successful authentication, create network traffic or approve a firewall block.

![Shared plan editor illustrated by an unsaved Mac/UTM example](images/test-plan-editor.jpg)

*The image uses Mac lab addresses. For Windows, enter the current configured guest addresses; do not copy the screenshot’s `.4` / `.6` / `.8` identities.*

### Fill in the scope

1. Click **New test plan** in the header or plan panel.
2. Fill the fields below. Use the real configured lab identities; the form checks its allowed source and Victim configuration.
3. Review the timezone shown beneath the form. Inputs are in that browser timezone and stored as UTC. Use whole-minute times.

| Field | Example/meaning |
| --- | --- |
| Operator name | Your operator/reviewer identity, 1–80 characters |
| Source IP | The current Trust-Client IP from your reviewed Windows lab profile, not an address copied from a Mac screenshot |
| Target IP | The configured Windows-lab Victim IP; this editor supports SSH TCP/22 |
| Permitted accounts | `soc_test`; comma-separated if several accounts are explicitly permitted, maximum eight names |
| Failed-attempt limit | `10`, meaning the total permitted failed passwords over the whole plan window; allowed range 1–100 |
| Start time | A future whole minute, allowing enough time to validate and approve |
| End time | After start; the plan duration must be 1–10 minutes |

For an approved-test demonstration, permit only the intended test account and run within the window. For an intentional root scope-violation demonstration, still permit only `soc_test`; the later `root` attempt is then outside that approved account scope. Do not expand a plan after the event to excuse a violation.

### Validate, review and approve

4. Click **Validate**. This saves a validated draft and displays **Review the validated scope**; it is not yet an active authorization.
5. Check the exact source, target, accounts, total failure limit, operator and start/end times in the review. If you edit any field, validate again.
6. Click **Approve plan** before the start time. Confirm the dashboard says the approval was saved and retains run instructions for that exact plan.
7. Wait until its start, then run the named client's command manually. Keep the monitor running.
8. After the window ends, allow the arrival margin, collection catch-up and model processing. Read the resulting evidence and assessment.

**Use fresh times** helps replace an expired preview. **Cancel draft** abandons the form; it does not revoke an already approved plan. An overlapping approved window for the same source/Victim is rejected. If preview approval fails because start has passed, choose new times, validate and review again.

The failure limit is an authorization constraint, **not a model Suspicious threshold**. An approved plan is evidence to consider, not a forced Benign verdict. Activity before/after the window or against another account does not inherit that authorization.

## 3. View and repeat existing plans

1. Click **Plans**, then expand **Plan history**.
2. Use **View plan** to inspect the retained scope and **Show run instructions** for the named client and timing.
3. For another rehearsal, choose **Repeat with new times**. It copies the scope into a fresh draft; inspect every field, validate, and explicitly approve the new version before its start.
4. Run the helper manually only during the newly approved window.

Approved versions are retained rather than edited in place. **Repeat with new times** is not automatic reapproval, and **Show run instructions** does not execute the displayed command. There is no general dashboard editor for rewriting an approved plan or silently changing the authorization of an old incident.

The registry is bounded (32 retained plan entries / 64 KiB in the current implementation). If full, stop and perform a deliberate archival/maintenance procedure with backups rather than deleting approvals or changing the registry during an active investigation. A registry change that conflicts with a bound investigation can require manual review.

## 4. Read, validate and apply a Suricata rule

### Prerequisite and scope

Follow [Windows helper preparation and verification](WINDOWS.md#7-prepare-and-review-privileged-helpers), including the optional rule helper (`--with-rule-editor`) and `verify_windows_helpers.py --rule-editor`. Review installation and its privileges separately. The local receipt must match the `windows-hyperv` platform and current Victim IP. Do not run the upstream Mac/UTM installer for this Windows profile.

This control targets one file **on Victim**, `/etc/suricata/rules/ssh_bruteforce.rules`, through the provisioned fixed helper. It is not a general remote file editor. The file must be included in the active Suricata configuration, and its supported command socket/reload path must work.

The template preserves TCP/22, client-to-server SYN matching, threshold tracking by source, classification and SID `9001001`. Editable parts are:

| Part | Meaning / supported bound |
| --- | --- |
| `msg` | Plain alert text, 1–160 characters; retain the template and avoid embedded quotes, backslashes and control characters |
| Threshold `count` | Number of matching connection packets for the rule's threshold logic; 1–100 |
| Threshold `seconds` | Sensor threshold interval; 1–300 seconds |
| `rev` | Positive rule revision; increase it whenever the rule text changes |

This is connection-threshold evidence, not a count of password failures or a security verdict. The **plan's failure limit** and **Suricata's threshold count** are different controls.

### Apply one reviewed change

1. Open **Settings → Suricata rule**.
2. Click **Read current rule from Victim**. Wait for the returned text, observed time, file hash, Suricata service state and available activation status. Cached host text alone is not a new Victim read.
3. Change one supported field in **Rule draft**, and increase `rev`. For example, compare a threshold count of `5` with `4` while keeping the interval and other settings fixed. This is a chosen experiment, not a recommended production threshold.
4. Click **Validate on Victim**. The helper tests a candidate full configuration without activating it.
5. Inspect the diff and successful configuration-test result. Validation lasts ten minutes and binds to the current file/configuration hashes. Editing the draft or a concurrent Victim change requires a new read/validation.
6. Click **Apply validated rule and reload** only when that exact diff is intended. This step writes the rule on Victim and waits for its reload result.
7. Confirm the returned status is `active`, then read current Victim status again. Retain the revision/hash when comparing later incidents. A file read with no verified editor activation is a different state from a confirmed applied version.
8. Run a **new manual rehearsal** to observe new alert behavior. Old EVE records and saved incident evidence are not regenerated.

### Restore or handle uncertainty

**Restore previous rule and reload** is available when the current read has a recorded editor backup. Review the intended restore and use that control; the helper validates the backup and restores it with a fresh revision. It is not an unrestricted history picker.

A failed activation attempts to restore the earlier file. Treat an `unknown`, error or mismatched receipt as unresolved: **read Victim's current status before another apply**. Do not blindly click Apply repeatedly or assume a disabled button means the remote operation never happened. A successful validation alone does not change the running sensor.

## 5. Save, compare and activate a prompt

The Windows tab is labeled **AI prompt**. Model identity and budgets come from the selected runtime/lab settings. The public Windows example uses `gemma3:1b`, whose investigation quality has documented failures; selecting an instruction does not make that model qualified.

Prompt changes affect model instructions. They do not change the Suricata rule, Python evidence collection, JSON schema, fact/coverage validators or response policy. Saving or activating a prompt does not qualify a model for live response.

### Save a candidate without activating it

1. Open **Settings → AI prompt** and note the label/hash beside **Active**.
2. Choose a **Saved version** and click **Load selected version** to put its text into the editor. Merely selecting the dropdown does not load it. **Load default draft** loads the built-in instruction into a draft; it does not restore the active version automatically.
3. Edit **Instruction**, changing one thing for the experiment, and give it a meaningful **Version label**, such as `Explain evidence limitations clearly`.
4. Click **Save and validate version**. Check for the saved/validated confirmation and selected candidate. Instructions must be 200–12,000 UTF-8 bytes with no NUL; labels must be 1–80 characters. A saved-evidence input-budget check may also reject a candidate.
5. Keep the current **Active** label unchanged while you evaluate the candidate. Validation means it can be saved within the implemented constraints; it does not prove good judgments or safe reasoning.

Save or copy an unsaved draft before loading another version or refreshing. Identical instruction text reuses its content-derived saved version; changing only the label does not create a new instruction version.

Text in the editor is not automatically a stored version. To activate edited text, **save it first**, then select that saved version. **Activate selected version** acts on the selected stored record, not unsaved textarea contents.

### Compare on saved evidence

6. Under **Compare on saved evidence**, select a **Saved SSH incident** and the saved candidate prompt version.
7. Click **Compare original vs selected prompt**. Read the queue/running/completed status rather than clicking again because inference takes time.
8. Inspect both arms: **Original instruction** and **Selected instruction**, the evidence hash, verdict or validation error, explanations, recommendations, timing and **Inspect result and provenance**.
9. Judge whether the candidate better explains the same facts without inventing intent, weakening uncertainty or contradicting recorded authorization. A preferred label or fluent prose is not proof of better security judgment.

Each comparison runs **two fresh inference requests** against identical saved evidence, using the configured model/options at comparison start. The original arm reconstructs the incident's original instruction; it is a new request, not just a redisplay of its old answer. If today's model/options differ from the historical run, the pair is a controlled prompt comparison under today's snapshot, not an exact reproduction of the historical execution.

Comparisons collect no new logs, send no Telegram messages, create no response approvals and apply no firewall changes. They share the inference queue with live assessments and can delay them. Queue capacity is three pending/running comparison jobs; wait for results instead of repeatedly submitting.

The selector requires complete saved SSH evidence and reconstructable original prompt provenance. A fresh empty database, collection-only evidence without an assessment snapshot, or old records lacking that provenance may offer no usable comparison. Create an appropriate normal assessment first or inspect the recorded error. Do not fabricate missing evidence or remove validation to make the comparison run.

### Activate or revert explicitly

10. Select the saved candidate you reviewed and click **Activate selected version**.
11. Check that **Active** now shows the intended label/hash. New assessment requests use it; an in-flight request and historical assessments retain their original instruction/provenance.
12. To revert, select the previous saved version and click **Activate selected version** again. Loading its text or closing Settings alone does not revert anything.

A “current active version changed” conflict means another activation occurred: refresh the saved state, review the current active record and deliberately select the desired version. Preserve unsaved text before refreshing a failed page.

## 6. Select an AI model

Open **Settings → AI model selection**. The provider selector lets you activate Ollama or Gemini and test a candidate with fixed synthetic evidence. The pipeline configuration tables are read only. [Gemini setup and evidence-sharing controls](GEMINI_PROVIDER.md)

| Item | Why it matters |
| --- | --- |
| Unapproved grouping | How related alerts are combined into a fixed incident scope |
| Log arrival allowance | Why analysis waits after the evidence window closes |
| Pre-alert evidence | How earlier SSH activity can be included before the first alert |
| Approved-test evidence | Why the full approved-plan window is considered |
| Assessment roles | Which decisions belong to the model and which checks belong to Python |
| Model | Which configured model assesses the supplied evidence |
| Context capacity | Configured input/output capacity; not token usage for every incident |
| Output limit | The generation cap; a cut-off response is not accepted as complete |

Windows displays the model/options resolved from the current runtime/lab settings. Read those displayed values rather than assuming the historical Mac screenshot’s Gemma4/65,536-token configuration. The public Windows example uses `gemma3:1b` with 8,192 context / 1,024 output tokens. Neither this panel nor prompt activation changes collection-only, experimental review-only or separately authorized live mode; follow [explicit operating modes](WINDOWS.md#8-select-an-explicit-assessmentresponse-mode).

Changing a prompt does not change these controls. Changing source constants or platform configuration is a separate reviewed operation with appropriate restart/testing, outside this panel. The panel is not an editor for credentials, guest networking, response authorization or arbitrary Python code.

## 7. Record a human review

![Shared assessment layout illustrated by a historical Mac/UTM incident](images/incident-assessment.jpg)

*The screenshot is a Mac/Gemma4 example. It does not qualify the configured Windows model or establish a Windows Telegram-to-worker live result.*

When an incident is awaiting human review:

1. Select it in **Incident history** and confirm its number/revision and source/target.
2. Read **AI assessment**, **Observed facts**, **Python scope comparisons**, coverage and retained errors. Windows SSH prose uses the verdict on the first line when it explicitly states Benign or Suspicious. The badge otherwise shows **No verdict yet**.
3. In **Human review**, enter **Reviewer name**, choose a conclusion and optionally enter **Review notes** explaining the evidence checked. Notes have no minimum or maximum character-count validation; general request-size/text protections still apply.
4. Click **Save human review** and check the resulting workflow state and **Review history**.

| Conclusion | Effect |
| --- | --- |
| Benign / authorized activity | Saves an independent human conclusion and resolves this review |
| Suspicious / unauthorized activity | Saves an independent human conclusion and resolves this review |
| Need more evidence — keep open | Records your finding and keeps the case open for operator investigation |

**Add follow-up review** opens another entry after resolution. Reviews are append-only rather than overwriting the original AI report or an older human conclusion. **Send Telegram review notice** queues an incident-bound review notice for the existing monitor's handler; it does not make the dashboard a new bot poller. A running Telegram-enabled monitor is required, and existing sent/uncertain/resolved notices are not simply resent by repeated clicks.

The Telegram notice includes an excerpt of the AI assessment and a link to the full incident. The conclusion buttons record the same independent human review. **Need more evidence** keeps the case open for the operator. A changed revision or newer review requires inspecting the current case.

## 8. Know when changes take effect

| Action | Stored/changed state | Takes effect | Does not do |
| --- | --- | --- | --- |
| Type in a form/editor | Browser draft | Only that form | Grant authorization or activate a rule/prompt |
| Validate a test plan | Validated draft/review scope | Enables explicit approval before start | Authorize traffic yet |
| Approve plan | Exact approved version in the local registry | Only its recorded source, target, accounts and future window | Run a test or approve a response |
| Validate rule | Victim candidate test and bound validation receipt | For that reviewed candidate before expiry | Reload active rules |
| Apply validated rule | Victim rule/configuration activation | Future sensor processing after successful reload | Regenerate historical evidence or decide the model verdict |
| Save and validate prompt | Versioned stored instruction | Available for selection/comparison | Make it active |
| Run comparison | Isolated comparison result | Two new requests on saved evidence | Collect traffic, activate a prompt, send Telegram or execute a response |
| Activate selected prompt | Active instruction pointer | Future assessment requests | Rewrite old reports or an in-flight request |
| Save human review | Separate append-only conclusion | Current reviewed snapshot/workflow | Approve a firewall block or rerun an investigation |
| Approve an eligible Telegram block | Exact authorized response decision | Only after independent worker revalidation in the selected mode | Grant blanket permission for future incidents |

## 9. Repeat an experiment and troubleshoot

### A controlled demonstration

1. Confirm readiness and use dry-run responses for an initial test. For an unqualified Windows model, follow the explicitly authorized experimental review-only mode and keep actions disabled. Collection-only mode does not produce normal model assessments to compare.
2. Create and approve one fresh plan when the scenario requires it; run one bounded helper invocation manually.
3. Wait for the evidence window, arrival margin and assessment, then retain the incident number/revision, observed facts, original instruction, rule revision/hash and result.
4. To study **prompt influence**, compare one saved candidate against that same incident's original instruction. Keep evidence/model/options fixed within the pair.
5. To study **rule influence**, validate/apply one rule change and generate fresh authorized test traffic. Save the new rule provenance and actual evidence; a saved-evidence comparison cannot evaluate packets the old sensor never retained.
6. Revert or retain each chosen version explicitly, and use a separate fresh plan/window for the next scenario. Do not merge several simultaneous runs and then assume each command produced its own incident.

### Common dashboard problems

| Symptom | Next check |
| --- | --- |
| Page cannot connect | Restart the dashboard service with the platform command and inspect its terminal; copy unsaved editor text before refreshing |
| Saved incidents display but no new activity | Collector/monitor heartbeat and actual source/service health; a page can display historical state while monitoring is stopped |
| Plan approval fails | Future whole-minute start, 1–10 minute duration, allowed identities, exact validated fields and no overlapping approved scope |
| Cancel/Repeat did not change an old approved plan | Those controls cancel a draft or create a new draft; they do not rewrite the approved record |
| Rule Read fails | Correct Victim helper provisioning/receipt, SSH identity, fixed file inclusion and command socket |
| Rule Apply is disabled | Read current state, edit/increase `rev`, validate the exact candidate and inspect the diff; editing afterward invalidates it |
| Validation passed but behavior is unchanged | Validate did not apply; inspect activation state/revision/hash and test new traffic after a successful reload |
| Comparison is unavailable or rejected | Complete saved evidence, original prompt provenance, current input budget and model connectivity |
| Comparison is slow | Shared inference queue and two requests per job; do not keep adding jobs |
| Edited prompt did not affect a new report | Confirm the saved candidate was selected and activated before that request started |
| Human review cannot be saved | Current revision/snapshot, another operator's review or an active response request; refresh and inspect before retrying |
| Human review is saved but no block happens | Review conclusions and response approval are separate workflows |

Use the platform [setup guide](WINDOWS.md) for service startup, credentials, helpers and response modes. Actual plans, reviews, prompt history and response records remain local private state; do not copy another operator's databases to reproduce a fresh installation.
