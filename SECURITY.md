# Security policy

This repository provides educational, low-impact website configuration checks; it is **not** a penetration-testing suite or an attestation of safety.

## Reporting a vulnerability in this toolkit

Please avoid publicly sharing proof-of-concept exploit details, credentials, or sensitive scan evidence. Contact the project maintainer privately through the publicly listed Byson Cyber contact channel, or use GitHub private vulnerability reporting if enabled for this repository.

## Safety guidelines

- Only assess sites you own or have explicit authorization to test.
- Prefer Standard or Deep mode first. Full mode sends intentionally invalid POST requests to explicitly supplied API routes and can cause logs, alerts, or side effects.
- Never commit API keys, credentials, user data, customer scan reports, or secrets to this repository.
- HTTP status codes and individual header observations are not proof of a vulnerability; validate findings before remediation.
