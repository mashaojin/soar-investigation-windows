# Optional Gemini API provider

Ollama remains the default. Gemini uses Google's fixed HTTPS API endpoint; there is no automatic fallback. The provider adapter is independent of the VM platform. The original Mac repository is unchanged.

In the dashboard, open **Settings → AI model selection → Assessment provider and model**. Select **Gemini API**, review the explicit model ID and expected returned version, and activate the selection. The initial suggested model is `gemini-2.5-flash-lite`; availability and quota depend on the API project. Selection alone makes no API request and does not grant evidence-upload consent or firewall authorization.

Save `GEMINI_API_KEY='your-key'` in the ignored `.env.gemini` file beside the Python entry points, or set the environment variable locally. Never enter a key in the dashboard, commit it or send it in chat. Both legacy and newer authentication-key formats are accepted; whitespace and header injection are rejected.

Verify the exact API project's free-tier quota or applicable redeemed credits in AI Studio. A Gemini subscription does not establish API allowance. To authorize a bounded synthetic check from WSL:

```bash
python3 configure_gemini.py --model gemini-2.5-flash-lite \
  --expected-model-version gemini-2.5-flash-lite \
  --quota-kind free_tier --max-requests 3 --hours 1 \
  --confirm-project-allowance
python3 verify_gemma.py --provider gemini --model gemini-2.5-flash-lite \
  --expected-model-version gemini-2.5-flash-lite \
  --output verification-gemini.local.json
```

This creates an ignored, expiring operator-attested allowance receipt. It does not automatically verify billing, grant unlimited quota, authorize paid usage or enable real-evidence uploads. Requests are serialized across providers, have a 120-second total deadline and no retries. The complete input and reserved output must fit their configured limits; evidence is never silently truncated. Provider schemas do not replace Python's factual and evidence validation.

The dashboard's synthetic check uses one fixed public approved-test fixture. Saved incident comparisons are real evidence and remain denied without separate consent. A real integration-test receipt permits at most one generation for an incident whose window starts after consent; historical evidence and comparisons are rejected. Free-tier content may be used by Google to improve its products: obtain informed consent before sending lab evidence.

Provider activation affects future assessments and invalidates pending response approvals. Historical assessments retain their provider, model and returned version. Unresolved response actions prevent a switch. A changed provider requires fresh model-bound response authorization; selection, evidence consent and a human security conclusion never approve a block.

New Windows SSH investigations use a plain-text advisory report with inline citations and a suggested next step. Python checks the report length and whether cited IDs exist in the supplied evidence. Review the prose alongside the recorded facts. Telegram offers human-review choices for these reports. Advisory prose cannot create a firewall approval request.

For ongoing lab testing, after confirming Free tier and agreeing to send new incident evidence to Google, run the same configuration command with `--ongoing-live`. This creates the ignored `.gemini-live-access.local.json` authorization without a local request cap or expiry. It applies to new advisory incidents and is bound to the configured key and model. Google Free tier quota still applies. Remove that file to revoke ongoing access. Synthetic checks still use their own allowance.

## Initial measured evaluation of the earlier structured format

Three synthetic scenarios were evaluated with `gemini-2.5-flash-lite`, an 8,192-token context budget and a 1,024-token output budget. All three passed structured/factual validation, but only two verdicts matched the references. The approved test was Benign, unapproved activity was Suspicious, and the root/account-scope violation was incorrectly Benign despite correctly identifying `root` as unexpected. End-to-end API latency was 1.515–1.652 seconds. This small evaluation establishes API compatibility, not reliable security judgment or full live-response qualification.
