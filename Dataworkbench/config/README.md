# Configuration

Copy `settings.example.json` to `settings.json` for local overrides. `settings.json` is ignored by source control.

Copy `response-flows.default.json` to `response-flows.json` to customize the declarative response library. Supported action types in this version are:

- `incidentPatch`
- `emailAffectedUsers`

Live flow execution uses the same global live-apply gate and confirmation phrase as bulk remediation.

The `ai` section configures Response Studio's optional AI Helper. Credentials must be supplied through `AZURE_OPENAI_REPORTING_KEY`, `AZURE_OPENAI_API_KEY2`, or `AZURE_OPENAI_API_KEY`; never put API keys in a settings file.
