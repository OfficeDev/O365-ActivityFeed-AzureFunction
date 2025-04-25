# Analyst Assistant

## Overview
Analyst Assistant is a PowerShell-based Azure Function code designed to streamline the analysis and management of data security incidents detected by Microsoft Purview DLP. It leverages Azure OpenAI (GPT-4o-mini) to intelligently assess data security incidents, classify their risk levels, and automate incident resolution or escalation based on predefined policies.

## Features
- **Automated Incident Retrieval**: Fetches recent security incidents from Microsoft Graph Security API.
- **AI-Powered Analysis**: Utilizes Azure OpenAI to analyze incident data contextually and classify risk levels (high, medium, low).
- **Policy-Based Incident Handling**: Supports multiple predefined policies (e.g., Financial Data, PII Policy, Healthcare) with custom instructions for AI analysis.
- **Incident Resolution Automation**: Automatically resolves low-risk incidents or escalates medium/high-risk incidents.
- **Integration with Power BI**: Sends incident data to Power BI for reporting and visualization.

## Prerequisites
- Azure subscription with access to:
  - Azure OpenAI Service (GPT-4o-mini deployment)
  - Microsoft Graph Security API
- Managed identity or identity with the following permissions:
  - user.read.all
  - securityincident.readwrite.all
  - securityincident.read.all
  - Mail.Read
  - mail.readbasic
  - files.read.all
  - sites.read.all

## Configuration
Update the following variables in [`run.ps1`](\run.ps1):

- **Azure OpenAI Endpoint and API Key**:
  ```powershell
  $openAIEndpoint = "<Your Azure OpenAI Endpoint>"
  $apiKey = "<Your Azure OpenAI API Key>"

- **DLP Report Mailbox**:
  ```powershell
  $dlpreportmbx = "<Your DLP Report Mailbox Email>"
  
- **Policies and Instructions**:
  - Customize the $policiesAndInstructions array to define your own policies and AI instructions.

## Project Structure
│
├──        # Main script for incident analysis and handling
├── spoperm.ps1                 # Helper script for SharePoint permissions (optional)
└── odbperm.ps1                 # Helper script for OneDrive permissions (optional)

## Security Considerations
- Store sensitive information (API keys, tokens) securely using Azure Key Vault or Managed Identities.
- Regularly rotate API keys and tokens.
- Limit permissions and access scopes to the minimum required.

## Contributing
Contributions are welcome. Please open an issue or submit a pull request for improvements or bug fixes.
