# Manual owner security checklist

- [ ] Domain registration, lock, renewals, MFA/passkeys, recovery and contact ownership.
- [ ] Proper DNSSEC chain of trust, CAA issue/iodef addresses, CT alerts and certificate renewal.
- [ ] HTTP -> HTTPS redirect coverage and subdomain inventory before HSTS preload submission.
- [ ] TLS version/cipher and certificate-chain validation using a comprehensive independent test.
- [ ] CSP and other security headers reviewed for the site's actual features; check Chrome Console/Issues.
- [ ] No unintended public preview, staging, `workers.dev`, source code, source maps or credentials.
- [ ] Proper identity/authorization, server-side validation, body limits, CSRF protection where applicable.
- [ ] WAF/rate limiting on intended requests; review false positives, shared-IP issues and bypass routes.
- [ ] Logs and analytics don't record unnecessary personal data, passwords, secrets or session tokens.
- [ ] Mail providers and signing (SPF, DKIM, DMARC) tested end-to-end, not assumed from DNS.
- [ ] Actual contact/newsletter flows tested with authorized test addresses and expected notifications.
- [ ] Keyboard/screen-reader/contrast manual accessibility tests; Lighthouse mobile/desktop.
- [ ] Privacy/accessibility statements accurate; security.txt contact mailbox actually monitored.
- [ ] Backups, code repository controls, dependency updates, rollback and incident response.

This checklist supplements the script; neither constitutes a penetration test or compliance attestation.
