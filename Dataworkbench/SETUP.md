# Setup guide

This guide takes DLP Response Studio from a fresh checkout to a read-only first run. Microsoft Foundry, protected evidence, custom response flows, and live actions are optional and are configured separately below.

## 1. Prerequisites

DLP Response Studio is designed to run locally on Windows with:

- Node.js 20 or later
- PowerShell 7 (`pwsh`)
- The Microsoft Graph PowerShell authentication module
- A Microsoft 365 operator account with the delegated permissions needed for the operations you use

Check the installed runtimes from PowerShell:

```powershell
node --version
pwsh --version
```

Install the Graph authentication module for the current user if it is not already available:

```powershell
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
}
```

## 2. Set up permissions

There are two independent Microsoft 365 authorization checks, and both must pass:

1. **Microsoft Graph delegated consent** allows the Microsoft Graph PowerShell client to request a scope.
2. **Operator role and service access** determine what the signed-in user can do in Microsoft Defender, Microsoft Purview, Exchange, Teams, and Microsoft Entra. For DLP operations, the operator must be assigned an appropriate role group in the Microsoft Purview portal before the Graph commands will be authorized.

Grant only the permissions for the features that will be used. The application requests scopes interactively and acts as the signed-in operator; it does not use application permissions, a service principal identity, a client secret, or a stored Graph access token.

> **What delegated access means:** The Studio can act only while a person is signed in, and only within both the approved scopes and that person's existing access. Approving a delegated scope does not give the Studio unrestricted tenant access, create a background service identity, or let it bypass the operator's roles, licenses, Conditional Access policies, or resource restrictions. When the sign-in session ends or is revoked, the Studio can no longer call Microsoft Graph.

### Choose the delegated Graph scopes

| Feature | Delegated Graph scopes | Tenant administrator consent normally required | Operator access |
| --- | --- | --- | --- |
| Synchronize DLP alerts and events | `SecurityAlert.Read.All`, `SecurityEvents.Read.All`, `CustomTags.Read.All` | Yes | Membership in an appropriate Microsoft Purview role group, such as **View-Only DLP**, plus access to the relevant DLP alerts; tenants may also require **Security Reader** |
| Resolve departments | `User.Read.All` | Yes | Permission to read the target users in Microsoft Entra ID |
| Update incident status/tags and add comments | `SecurityIncident.ReadWrite.All` | Yes | A supported incident-management role, normally **Security Operator** or **Security Administrator** |
| Email affected users | `Mail.Send` | Tenant consent policy dependent | A licensed Exchange Online mailbox from which the operator may send |
| Send one-to-one Teams notifications | `Chat.Create`, `ChatMessage.Send`, `User.ReadBasic.All` | Tenant consent policy dependent | A Teams-enabled operator account permitted to create chats and message the recipients |

Microsoft Graph consent does not elevate the operator's Microsoft 365 roles. For DLP collection, assigning the Graph scopes without assigning the operator in the Microsoft Purview portal is not sufficient: authentication can succeed while every DLP Graph request is denied. Conditional Access, user-assignment requirements, Defender role groups, Purview role groups, Exchange restrictions, Teams policies, licensing, and resource scope can also deny an operation after scope consent succeeds. Use separate read-only and response operator accounts when your organization requires separation of duties.

### Assign the operator in Microsoft Purview

Before testing any DLP Graph command, a Purview administrator must assign the routine operator to a role group that permits access to the DLP alerts and events the Studio collects:

1. Open the **Microsoft Purview portal** and go to **Settings** > **Roles and scopes** > **Role groups**.
2. Assign the operator to **View-Only DLP**, or to your organization's narrower custom role group containing the equivalent DLP viewing permissions.
3. Confirm that any required administrative-unit or data-source scope includes the alerts the operator must collect.
4. Allow time for the role assignment to propagate, then have the operator start a new sign-in session.

Purview role-group membership does not grant a Graph scope, and Graph consent does not grant Purview access. The same signed-in account needs both. Record the approved role group and its scope as part of the deployment handoff.

### Grant tenant-wide delegated consent

Have a tenant administrator perform this once for the scopes you approved. The administrator must hold a role permitted by your tenant's consent policy, such as **Privileged Role Administrator** or **Global Administrator**. Do not use that account for routine Studio operation.

In a fresh PowerShell 7 session, set only the approved scopes and connect:

```powershell
$approvedScopes = @(
    'SecurityAlert.Read.All'
    'SecurityEvents.Read.All'
    'CustomTags.Read.All'
    'User.Read.All'
    'SecurityIncident.ReadWrite.All'
    'Mail.Send'
    'Chat.Create'
    'ChatMessage.Send'
    'User.ReadBasic.All'
)

Connect-MgGraph -Scopes $approvedScopes -ContextScope Process -NoWelcome
Get-MgContext | Select-Object Account, TenantId, Scopes
Disconnect-MgGraph
```

Review the consent screen carefully. If the tenant displays **Consent on behalf of your organization**, select it only after the scope list has been approved. Organizations that block interactive admin consent should grant the same delegated permissions to the **Microsoft Graph PowerShell** enterprise application through their normal Entra consent workflow.

For a read-only deployment, omit `SecurityIncident.ReadWrite.All`, `Mail.Send`, `Chat.Create`, and `ChatMessage.Send`. Omit `User.Read.All` when department enrichment is not used. You can grant additional scopes later without reinstalling the application.

### Verify the operator

Sign in as the routine operator and request only the scopes needed for the first operation:

```powershell
$readScopes = @(
    'SecurityAlert.Read.All'
    'SecurityEvents.Read.All'
    'CustomTags.Read.All'
)

Connect-MgGraph -Scopes $readScopes -ContextScope Process -NoWelcome
$context = Get-MgContext
$context | Select-Object Account, TenantId, Scopes
Disconnect-MgGraph
```

Verify that the account and tenant are correct and that every requested scope appears in `Scopes`. Then run the collector in step 4. A successful token does not prove service-level role access; the collector is the final read-access check.

### Optional Purview policy administration

The required read assignment above does not need to include policy-edit permissions. The Studio does not change DLP policies or sensitive information types. A separate administrator who implements a generated Detection Assurance plan needs the appropriate Microsoft Purview role group, typically:

- **Data Loss Prevention** or the organization's narrower custom Purview role group to edit and test DLP policies and rules.
- The applicable sensitive-information-type permissions when copying or creating a custom SIT.

Assign these roles in the Microsoft Purview portal using your organization's privileged-access process. Keep plan generation and production policy approval separated where required.

### Optional Microsoft Foundry access

The current application authenticates to the Foundry/Azure OpenAI Responses endpoint with an API key in `AZURE_OPENAI_REPORTING_KEY`. It does not currently use Microsoft Entra token authentication or a managed identity.

- A resource administrator needs Azure RBAC sufficient to view the endpoint, deployments, and keys. **Cognitive Services OpenAI Contributor** is suitable when deployment management is required; use a narrower custom role for key retrieval when available.
- The runtime operator needs the endpoint, deployment names, and one valid resource key. The runtime operator does not need an Azure subscription role after those values are supplied securely.
- Store the key in the process environment only. Do not put it in `config/settings.json`, a script, source control, or a PowerShell profile.
- If local key authentication has been disabled on the Azure AI resource, AI features will not work with this version. Keep AI features disabled or add Entra authentication support before enforcing keyless access.

### Local Windows permissions

Run the server and PowerShell workers as the same non-administrator Windows user. That identity needs read/write access to `config/settings.json` and `data/`. Protected evidence uses DPAPI `CurrentUser`; the collector restricts `data/protected/` to that Windows identity and `SYSTEM`, and a different account cannot decrypt it.

## 3. Start with safe defaults

From the repository directory:

```powershell
npm start
```

No npm package installation is required. The application uses Node.js built-ins and starts with the public defaults in `config/settings.example.json`.

Open <http://127.0.0.1:3100>. Confirm the service from another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:3100/api/health
```

The health response should report `ok: true`. At this point:

- The server listens only on `127.0.0.1`.
- Query, planning, and dry-run operations are available.
- Live actions are disabled.
- Microsoft Foundry is not required.
- No Graph authentication occurs until an operator starts a Graph-backed operation.

## 4. Synchronize DLP data

1. Open **DLP Response** from the start page.
2. Select **Sync DLP alerts**.
3. Complete interactive Microsoft Graph authentication when PowerShell prompts you.
4. Return to the browser after synchronization completes and run a query.

Synchronization requests delegated `SecurityAlert.Read.All`, `SecurityEvents.Read.All`, and `CustomTags.Read.All`. The normal stores contain redacted data and are written under `data/`.

You can also start synchronization directly:

```powershell
pwsh -NoProfile -File ./workers/Collect-DlpAlerts.ps1
```

## 5. Create local settings only when needed

The defaults are sufficient for the read-only first run. To override them, create the ignored local settings file:

```powershell
Copy-Item ./config/settings.example.json ./config/settings.json
```

Edit `config/settings.json`, then restart the server. Common settings include the loopback port, scan and result limits, collector lookback, live-action gate, and Detection Assurance options. Keep API keys and other secrets out of this file.

Environment variables override matching file settings:

| Variable | Purpose |
| --- | --- |
| `HOST`, `PORT` | Listener address and port |
| `DLP_STUDIO_LIVE_APPLY` | Enable the server-side live-action gate when set to `true` |
| `AZURE_OPENAI_REPORTING_ENDPOINT` | Microsoft Foundry Responses endpoint |
| `AZURE_OPENAI_REPORTING_MODEL` | Reporting deployment name |
| `AZURE_OPENAI_REPORTING_KEY` | Microsoft Foundry API key; environment only |
| `SIT_ANALYSIS_MODEL` | Detection Assurance analysis deployment name |
| `SIT_OPTIMIZE_ROOT` | Detection Assurance profile root |
| `SIT_SENSITIVE_CONTENT_ENABLED` | Enable protected evidence when set to `true` |

## 6. Optional: configure Microsoft Foundry

Foundry is needed for AI Helper and Detection Assurance model analysis, but not for DLP synchronization, local queries, plans, or dry runs.

1. Open **Configuration** in the workbench.
2. Enter the Responses endpoint and the reporting and analysis deployment names.
3. Save the non-secret settings.
4. In the PowerShell terminal that will start the server, set the API key:

```powershell
$env:AZURE_OPENAI_REPORTING_KEY = Read-Host 'Microsoft Foundry API key' -MaskInput
npm start
```

Saved configuration becomes active after restart. The browser does not accept, read, or persist the API key.

## 7. Optional: customize response flows

The built-in flow library works without a local file. To maintain a local declarative flow library:

```powershell
Copy-Item ./config/response-flows.default.json ./config/response-flows.json
```

Use **Response Studio** to review and edit flows. Flow definitions support allow-listed declarative actions only; executable PowerShell is not accepted from configuration.

## 8. Optional: enable protected evidence

Protected evidence is only for explicitly authorized Detection Assurance work that requires matched content.

1. Copy the example settings file as shown above if `config/settings.json` does not exist.
2. Set `sitOptimize.sensitiveContent.enabled` to `true` in the local settings file.
3. Restart the server.
4. In **Detection Assurance**, type the configured capture phrase and select **Rebuild protected evidence**.
5. Use the separate analysis phrase when starting protected analysis.

Raw events are encrypted with Windows DPAPI for the current Windows user and stored under `data/protected/`. They can be decrypted only by the same Windows identity. Protected analysis sends authorized, profile-scoped content to the configured Foundry endpoint and produces sensitive output that requires controlled handling.

## 9. Optional: enable live actions last

Do this only after validating synchronization, query results, plans, and dry runs:

1. Set `liveApplyEnabled` to `true` in `config/settings.json`, or set `$env:DLP_STUDIO_LIVE_APPLY = 'true'` before startup.
2. Restart the server and confirm `/api/health` reports `liveApplyEnabled: true`.
3. Review the generated plan and affected-object caps.
4. Type the configured confirmation phrase exactly.
5. Accept the separate browser confirmation.

Keep the listener on loopback. Do not enable live actions on a shared or unauthenticated network listener.

## Validate the checkout

Run the JavaScript syntax checks and test suite:

```powershell
npm run check
npm test
```

## Troubleshooting

**`node` or `pwsh` is not recognized**

Install the missing runtime, open a new terminal, and rerun the version checks from step 1.

**Graph sign-in or consent fails**

Confirm that `Microsoft.Graph.Authentication` is installed, `Get-MgContext` shows the intended tenant and requested scopes, and the operator has the required service role from step 2. Consent success alone does not grant access to security incidents, DLP data, mailboxes, or Teams.

**Port 3100 is already in use**

Start on another loopback port:

```powershell
$env:PORT = '3200'
npm start
```

Then open <http://127.0.0.1:3200>.

**AI features report that configuration is missing**

Confirm that the endpoint and deployment names are configured, the API key exists in the same terminal session that starts the server, and the server was restarted after configuration changes.

**Local changes appear to be ignored**

Restart the server after changing `config/settings.json`. Environment variables take precedence over values saved in that file.