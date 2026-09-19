# V2.1 Capability Matrix

## Controlled vulnerability validation
- XSS reflection: benign marker reflection check
- Boolean SQL injection: non-destructive response-difference check
- IDOR/BOLA: cross-object access check
- Path traversal: bounded local fixture disclosure check
- Open redirect: redirect Location observation without following it
- Configuration exposure: exposed training configuration check
- Session cookie flags: login response cookie-attribute review

## Persistence validation
Four disposable marker simulations:
- startup_marker
- scheduled_task_marker
- service_marker
- application_marker

These prove that the engine can distinguish and record multiple persistence classes without installing real persistence, stealth code, cron jobs, services, or startup backdoors.

## Lateral movement validation
Three second-host authentication paths:
- http_basic
- lab_token
- credential_auth

The engine proves reachability and authentication to a second disposable host. It does not execute commands on the second host.

## Decision quality
The evidence reasoner is deterministic, auditable, and evidence-first. A confirmed observation can create a justified next-step recommendation; an unconfirmed observation cannot create an automatic attack step.
