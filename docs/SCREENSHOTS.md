# Screenshot provenance

The five original cropped images were already part of the original repository and are retained as UI documentation. They depict the Mac/UTM lab, not the Windows lab and not synthetic renderings. No new desktop capture containing unrelated applications is included.

| Image | What it illustrates | Important limit |
| --- | --- | --- |
| [Dashboard overview](images/dashboard-overview.jpg) | Incident history, readable IDs, stage progress and recorded response status | Original Mac/UTM data; not Windows live-worker proof |
| [Test-plan editor](images/test-plan-editor.jpg) | Source/target, permitted accounts, attempt limit and timing | Unsaved example; it is not an authorization record for this installation |
| [Incident assessment](images/incident-assessment.jpg) | Model explanation, evidence and response display | Historical model/platform context |
| [Telegram live response](images/telegram-live-response.png) | A historical Mac/UTM temporary response and completed rollback message | Completed state; pending approval buttons are no longer shown |
| [Telegram manual review](images/telegram-manual-review.png) | A short incident-bound review notice with reason/dashboard link | Older notice layout; current notices additionally offer human-conclusion buttons |

Current response-approval and investigation-review choices are described in the README and setup guides. Do not infer that Windows completed an actual Telegram YES → worker response from these older images. The Windows helper's real deny/rollback was verified separately by a manual console operation; its full Telegram-to-worker live path remains unverified.

Screenshots are cropped to the relevant application content. No bot tokens, private keys, private conversation overlays, account settings, database exports or live credential files were added. Existing expired incident/request identifiers inside the historical images are UI context, not reusable approvals. Keep screenshots separate from machine-readable operational state and review them before changing repository visibility.

## Current dashboard captures

| Image | What it shows |
| --- | --- |
| [Completed live rollback](images/dashboard-live-rollback.jpg) | macOS/UTM incident `INC-20261107-006`, revision 1, with six resolved stages and restored SSH access |
| [AI model settings](images/dashboard-model-settings.jpg) | The macOS dashboard’s Settings drawer with Ollama active, model selection and synthetic test controls |

The live view is cropped above the private reviewer identity. The settings image is cropped to the drawer. These are actual macOS dashboard captures shared by both READMEs.
