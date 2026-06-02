# Security Policy

HoneyMind is a local-first, cloud-optional honeypot platform. Because honeypots intentionally collect attacker interaction data, security reports and deployments should be handled carefully.

HoneyMind is based on the original [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot) project and preserves the original license and attribution.

## Supported Versions

Security fixes are provided for:

| Version | Supported |
| ------- | --------- |
| `main` | Yes |
| Latest tagged release | Yes |
| Older tagged releases | Best effort |

## Reporting a Vulnerability

Please do not disclose vulnerabilities publicly before maintainers have had a reasonable opportunity to investigate.

Preferred reporting path:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is not available, open a GitHub issue with a short, non-sensitive summary and ask maintainers to establish a private channel.

Do not include exploit details, credentials, tokens, captured attacker data, or private infrastructure information in a public issue.

Useful details for a private report:

- Affected component or protocol.
- Impact and expected risk.
- Reproduction steps or proof of concept.
- Whether the issue affects local-only deployments, hosted LLM providers, AWS Bedrock, logging, or Docker packaging.
- Any suggested remediation.

## Expected Response

Maintainers will triage reports as soon as practical. Accepted reports should receive:

- Confirmation that the report was received.
- A severity assessment.
- A remediation plan or explanation if the report is not accepted.
- Coordinated disclosure timing when a fix is needed.

## Secret Handling

Never commit real credentials, API keys, host keys, cloud tokens, private keys, or production configuration files.

HoneyMind supports local environment files such as `config/llm.env.list`, `config/aws.env.list`, and `config/.env`; these files are intentionally ignored by Git. Keep secrets in local environment files, GitHub Actions secrets, or a dedicated secret manager.

The repository may contain synthetic honeypot lure content. Synthetic values must be clearly fake and must never include real private keys, real cloud credentials, real API tokens, personal data, or host-specific secrets.

## Deployment Notes

- Run HoneyMind only on systems and networks where you are authorized to operate a honeypot.
- Review local laws, privacy obligations, and acceptable-use rules before collecting attacker interaction data.
- Local LLM endpoints keep fallback prompts on your own infrastructure.
- Hosted LLM providers receive interaction data when LLM fallback is used. Review provider terms and data handling policies before enabling them.
- AWS Bedrock, CloudWatch, S3, Glue, and Athena are optional integrations and should only be configured intentionally.

## Disclosure Scope

Security reports can include issues in:

- Protocol handlers and authentication behavior.
- Dataset-first and LLM fallback handling.
- Local JSONL logging and log conversion.
- Docker packaging and runtime configuration.
- CI/CD workflows and release automation.
- Secret redaction and API token handling.

Operational reports about internet-exposed test deployments are also welcome when they identify a project-level security issue. Reports about a specific user's deployment should be sent to that deployment owner whenever possible.
