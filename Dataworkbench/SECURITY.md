# Security policy

## Reporting a vulnerability

Do not open a public issue containing credentials, tenant data, DLP evidence, detected values, personal information, or exploit details. Contact the repository maintainers privately through the security reporting channel configured for the GitHub repository.

## Operational safety

- Keep the HTTP listener on loopback unless an authenticated reverse proxy and tenant isolation controls are added.
- Keep live apply disabled until plans and dry runs have been reviewed.
- Supply Microsoft Foundry or Azure OpenAI credentials through environment variables only.
- Never commit `config/settings.json`, `.env`, or any file under `data/` other than `data/.gitkeep`.
- Treat protected evidence and AI reports as sensitive organizational data.
