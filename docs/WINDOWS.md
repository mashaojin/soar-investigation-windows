# soar-investigation-windows: setup

Run Python in **WSL2 Ubuntu**, not native Windows Python: the pipeline uses Unix locking and ownership checks. Windows runs Ollama; Hyper-V hosts the Linux guests. This separate repository is the Windows distribution of [soc-pipeline](https://github.com/mashaojin/soc-pipeline); retained Mac modules/examples are compatibility references, not the Windows setup path.

This guide describes setup, not authorization to modify a VM or block traffic. New configuration defaults to **dry run**. Initialization preserves existing local files; inspect the actual response mode before starting.

## Verification and limitations

| Area | Observed result |
| --- | --- |
| Offline suite | 292 tests passed, including from a source-only copy without credentials or operational databases |
| Transport | Strict-key WSL SSH through the process-only Windows bridge; Windows loopback Ollama through curl.exe |
| Three guided scenarios | Actual sensor/journal evidence, dashboard, Telegram delivery and incident-bound human reviews verified |
| Actual firewall helper | Scoped deny, active rollback timer, protected management SSH, removal after approximately 60.43 seconds and restored client connectivity verified |
| Full live approval path | Offline tests pass; actual valid assessment → Telegram YES → worker → rollback has not completed |
| Model quality | Gemma3:1b is unreliable; valid JSON and matching fact fields do not establish sound judgment or factual prose |
| Mac compatibility | Existing offline regressions pass; no new Mac/UTM VM rehearsal was performed for this port |

See [model results](WINDOWS_MODEL_EVALUATION.md), [Qwen3 results](WINDOWS_QWEN3_EVALUATION.md), [prompt diagnosis](WINDOWS_PROMPT_DIAGNOSIS.md) and [cloud probe](WINDOWS_CLOUD_EVALUATION.md). These are bounded lab results, not production-readiness claims.

## 1. Inventory and address stability

Prerequisites: Windows 11 Pro with Hyper-V, WSL2 Ubuntu with Python 3.12+, Windows Ollama, Windows curl.exe, PowerShell 7 reachable from WSL, and Linux guests with SSH. Python dependencies are from the standard library. Inspect existing software before installing anything. On a 16 GB host, run only the guests needed for the current scenario and measure memory during actual inference.

Read-only Hyper-V inventory in elevated Windows PowerShell:

```powershell
Get-VM | Select-Object Name,State,Generation,MemoryAssigned
Get-VMNetworkAdapter -All | Select-Object VMName,SwitchName,IPAddresses
Get-VMMemory -VMName 'Victim','Trust-Client','Kali Linux'
```

On each guest console:

```sh
hostname; id -un; ip -br -4 address; ip -4 route
systemctl is-active ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Compare prefix lengths and routes; similar prefixes alone do not establish a shared subnet. Hyper-V Default Switch uses DHCP: reverify addresses and host keys after reboot. A dedicated internal switch with a checked non-overlapping subnet and documented addressing/NAT is a stable alternative requiring separate review before implementation. Do not silently assign static addresses inside an unmanaged DHCP range.

## 2. Fresh Windows configuration

In WSL, from the repository root:

```sh
python3 configure_local.py --profile windows-hyperv
```

Review the ignored `lab.local.json`: actual Victim, Trust-Client, Kali, usernames, and management source observed by Victim. Example addresses are examples, not discovery. Set an absolute WSL-accessible PowerShell 7 executable path in `ssh.windows_powershell`. Never copy the old Mac protected management address.

Initialization creates absent profiles and an empty plan registry, and refuses introducing Windows configuration over old operational state. Do not copy Mac incident databases, cursors, bot offsets, active plans, approvals or helper receipts. Existing profiles are not overwritten. Keep model settings in the lab and runtime profiles consistent.

Windows defaults: `gemma3:1b`, 8,192 context, 1,024 maximum output tokens; optional `num_thread` accepts 1–4 and defaults to 2. Display timezone is configurable and defaults to `America/Vancouver`.

## 3. Verified SSH and Suricata prerequisites

Use a dedicated key in WSL home with private permissions. Populate its known-hosts file only after comparing public host fingerprints with guest consoles. Never disable host-key checking or copy private keys to guests. Review key installation, allowed management sources, journal-group membership and log permissions before granting access.

`ssh_transport.py` retains WSL OpenSSH authentication and strict host checking. `windows_tcp_proxy.ps1` permits profile-listed guests on TCP/22 only. It opens no listener and changes no firewall or execution policy. No Linux PowerShell Direct support is assumed.

After key/trust setup, verify read-only batch access:

```sh
python3 - <<'PY'
import subprocess
from pathlib import Path
from lab_config import load_profile
from ssh_transport import command
lab = load_profile(root=Path.cwd())
for role in ('victim', 'trust_client', 'attacker'):
    subprocess.run(command(lab, role, 'id -un'), check=True, timeout=20)
PY
```

Victim must have SSH and Suricata correctly configured. Include `rules/ssh_bruteforce.rules` (SID 9001001) in its active rule configuration, after reviewing the exact change. Validate before reload:

```sh
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Verify the monitored interface actually sees client-to-Victim SSH, readable `/var/log/suricata/eve.json`, root-origin `ssh.service` journal evidence, synchronized clocks, routes and firewall state. Discover management source from Victim's `SSH_CONNECTION`. An active sensor alone does not prove capture coverage. Installation, service configuration and access grants are explicit prerequisites, not automatic launcher actions.

Do not enable UFW for Windows setup. The Windows response helper uses an isolated nftables table and preserves other rules.

## 4. Windows loopback Ollama

WSL localhost is not guaranteed to reach Windows localhost. Prefer `ollama.transport: windows-stdio`, using Windows curl.exe against the Windows loopback origin. It needs no Ollama bind or firewall change. Other endpoints are configurable; review exposure before changing them.

Verify tags and a small synthetic inference:

```sh
python3 - <<'PY'
from pathlib import Path
from lab_config import load_profile
from ollama_transport import request_json
c = load_profile(root=Path.cwd())['ollama']
print(request_json(c, '/api/tags', timeout=10))
print(request_json(c, '/api/chat', {
    'model': c['model'], 'stream': False, 'think': False,
    'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
    'options': {'num_ctx': 8192, 'num_predict': 16}
}, timeout=120))
PY
```

Confirm the installed model identity matches configuration. A smoke request does not qualify its judgment. Pipeline inference is serialized by a shared lock, has bounded time/output, validates returned identity and checks complete prompt/output context accounting. Evidence is not silently truncated.

## 5. Dashboard, collection and evaluation

Use separate WSL terminals from the repository root:

```sh
# Terminal 1
python3 windows_lab.py dashboard
# Terminal 2: model assessment deferred
python3 windows_lab.py monitor --collection-only
```

Open `http://127.0.0.1:8765` in Windows. Confirm monitor heartbeat/component health separately: the dashboard does not collect or poll Telegram.

Synthetic-only model evaluation, without activating candidates:

```sh
python3 verify_gemma.py --output verification-model-base.json
python3 evaluate_model_boundaries.py --output verification-model-boundaries.json
```

Optional `--model`, `--threads`, `--claims-first` and `--instruction-file` affect evaluation only. Review explanations as well as JSON acceptance and label agreement. Missing evidence, malformed output and invalid facts must fail closed. Do not force verdicts or weaken validators to pass a model.

## 6. Telegram and one polling handler

Create an ignored `.env` from `.env.example`. Enter the token and private chat/operator IDs locally, never in source, plans or chat. The launcher's `--env-file` parser reads quoted literals; it does not execute or shell-source the file. Environment exports are an alternative.

Stop every other poller of the bot before explicitly setting `exclusive_polling_confirmed` in local policy. Authorize any test notification separately. Append `--telegram --env-file .env` to the chosen monitor command. Never start a separate response poller alongside it; locks reject duplicate owners. Assessment additionally requires readiness or explicit authorization for one of the modes below.

## 7. Prepare and review privileged helpers

These host commands prepare and stage files only:

```sh
python3 prepare_windows_response.py --output local-artifacts/helper-package --with-rule-editor
python3 stage_windows_helpers.py --package local-artifacts/helper-package
```

Review manifest, helper code, installer, configuration and sudoers before approving new privileges. The fixed response operations are inspect/read/apply/rollback, restricted to the two configured clients, protected management and Victim, TCP/22 and 60 seconds. The optional rule helper permits one fixed isolated Python invocation. These grants permit bounded root operations independently of Telegram; installation needs explicit approval.

Destinations: `/etc/soc-pipeline/windows-response.json` (0600), `/usr/local/libexec/soc-windows-response.py` (0755), its sudoers entry (0440), and optionally `soc-rule-editor.py` with its separate sudoers entry. Differing existing installations are refused: review migrations separately after code/address changes.

On Victim, inspect without privileges first:

```sh
python3 ~/soc-windows-helpers/install.py
```

Only after approving the exact changes, apply on Victim's console:

```sh
sudo python3 ~/soc-windows-helpers/install.py --apply
```

Then, while policy is still dry run, verify from WSL and stage public client inputs:

```sh
python3 verify_windows_helpers.py --rule-editor
python3 stage_demo_clients.py
```

Verification does not authorize live response or set model readiness. Client staging copies the bounded helper, public profile and verified Victim host key, never executes attempts, and preserves differing files in backups.

## 8. Select an explicit assessment/response mode

**Normal dry run:** after successful evaluation, record actual model readiness in local policy. Run `python3 windows_lab.py monitor --telegram --env-file .env`. Do not claim evaluation passed when it did not.

**Experimental review only:** record matching `experimental_assessment` objects in runtime and response profiles with configured `model`, timezone-aware `authorized_at`, and `mode: dry_run_human_review`. Keep policy dry run. Start with `--experimental-assessment --telegram --env-file .env`. All assessments are labelled unverified and require separate human review; response actions are disabled.

After an explicit dashboard provider/model selection, also set `provider` and `provider_binding` in both `experimental_assessment` objects. Read the selected `provider`, `model` and `binding` from the local dashboard's `/api/experiments` response under `provider`. Back up the local profiles and stop the monitor before updating the two settings. Restart from WSL after they match. [Gemini setup](GEMINI_PROVIDER.md)

New Windows SSH assessments are advisory prose and go through human review. The live mode below documents the separately guarded workflow for eligible structured assessments.

**Human-approved LIVE:** obtain explicit authorization for the actual firewall scope, plus acceptance of known model limitations if unqualified. Back up profiles. Remove mutually exclusive `experimental_assessment` fields. Record matching `human_approved_live` objects in runtime/policy with configured `model`, fresh timezone-aware `authorized_at`, and `accept_unqualified_model: true`. Set policy `mode: live`, and set `live_enabled_after` and `live_rehearsal_authorized_at` to that same timestamp. Keep `model_evaluation_passed` false if evaluation failed. Current provisioning hashes, address restrictions, protected management, 60-second duration and 600-second approval expiry must still pass.

After that specific scope is authorized, start:

```sh
python3 windows_lab.py monitor --human-approved-live --telegram --env-file .env
```

Activation is not approval for any block. A fresh post-activation incident needs a valid Suspicious assessment, supported `REQUEST_BLOCK_APPROVAL`, independent Python eligibility, then current Telegram `YES — Approve LIVE 60s block` or `NO — Deny block / report only`. Decisions bind operator, private chat, message, incident revision, evidence, status and expiry. No answer expires after 10 minutes with no action.

The worker revalidates before one dispatch, arms Victim rollback before deny, verifies kernel state and protected management, and checks removal and actual-source connectivity afterward. Uncertain or interrupted execution is reconciled, never blindly repeated.

## 9. Manual scenarios and independent human conclusions

Run one scenario at a time. For approved and scope-violation scenarios, create a fresh dashboard plan, Validate, then Approve plan. Review source, target, `soc_test` scope, attempt limit and future window first.

```sh
# Trust-Client: approved activity within the plan window
python3 ~/soc-demo/ssh_demo_client.py --mode approved --execute --lab-config ~/soc-demo/lab.local.json
# Kali: controlled demonstration without a matching approved plan
python3 ~/soc-demo/ssh_demo_client.py --mode unapproved --execute --lab-config ~/soc-demo/lab.local.json
# Trust-Client: deliberate root attempt outside a soc_test-only account scope
python3 ~/soc-demo/ssh_demo_client.py --mode scope-violation --execute --lab-config ~/soc-demo/lab.local.json
```

Each makes six bounded failed attempts, checks actual route source, uses strict host trust, and stops on unexpected success. Run once per authorized rehearsal; never repeat to obtain a desired verdict. Verify Victim journal counts and sensor evidence, not client Permission denied alone. Assessment waits for the whole evidence window and arrival allowance. Inputs do not predetermine verdicts or actions.

Missing evidence, invalid output or a request for more evidence routes to manual review: **Benign / Suspicious / Need more evidence**. These record independent human conclusions, not firewall approval. Need more evidence leaves investigation to the operator; it does not rerun the model. Test-plan approval also cannot authorize a block. Rejected AI output and separate human conclusions remain preserved.

## Stop, restart and recovery

For services started in foreground WSL terminals, press Ctrl-C and wait for exit, then restart with the same command and mode flags. Preserve databases/cursors across restarts. Run one monitor and one Telegram handler. Starting the dashboard alone starts neither collection nor responses.

Keep Victim running during a block: its timer does not depend on WSL or Telegram. If dispatch is uncertain, inspect the recorded run ID/helper state; never repeat apply. Emergency recovery on Victim's console is the fixed helper's `rollback <run-id>` for the recorded operation only. Do not flush unrelated rules or disable safeguards.

After DHCP changes, reverify host identities, update active/staged profiles and review/reverify the root-owned helper scope before live response. Keep credentials, actual authorizations, plans, incident databases, logs, archives and provisioning receipts local. See [publication checks](REPOSITORY.md).
