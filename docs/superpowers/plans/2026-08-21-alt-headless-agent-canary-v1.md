# ALT headless agent staging canary v1

## Scope

Run one staging-only `context.diagnostic.collect` through the Endpoint
Operations API and Gateway WSS to one installed ALT headless agent. The
Endpoint service owns the device identity, bearer, Gateway delivery, operation
state and safe result; it receives no Helpdesk ticket or requester data.

## Gates

- The deployment has an explicit staging marker, separate database and service
  unit, and an approved change identifier.
- The configured origin is HTTPS, DNS-based and validated against the supplied
  CA; neither IP substitution nor insecure TLS is permitted.
- The installed unit must use `/opt/endpoint-agent/launcher`, `gateway_wss`,
  and no HTTP-pull migration fallback.
- Evidence is an owner-only directory of bounded JSON projections. It must not
  contain credentials, authorization values, private keys, raw agent results or
  Helpdesk data.

## Execution outline

1. Deploy exact reviewed Endpoint and Helpdesk revisions into separate service
   units and PostgreSQL databases.
2. Run `tools/canary/verify_installed_alt_agent.py` read-only on the ALT host.
3. Verify a staging-scoped service credential and exact device mapping.
4. Enable the diagnostic mode temporarily, issue exactly one operation, and
   observe terminal delivery and the bounded agent completion marker.
5. Reconcile once more without issuing another command, assert no duplicates,
   then return feature flags to fail-closed settings without a database
   downgrade.

## Stop conditions

Stop and roll back on an origin/CA failure, wrong deployed revision, a disabled
or non-WSS agent, fallback activation, duplicate operation/evidence, ticket
status drift, legacy Helpdesk dispatch, or any evidence redaction failure.
