# ALT Ansible RPM 3.2.14 rollout design

## Goal

Replace the obsolete `endpoint_agent_alt` Ansible role with a first-install
rollout for `endpoint-agent-3.2.14-alt1.x86_64.rpm`.  It must create a
per-host, short-lived, single-use Gateway campaign and leave the installed
agent running only after durable enrollment has succeeded.

## Installation order

The old wording, "install RPM immediately after claim issuance", is replaced
by the following two-phase contract:

```text
verify pristine target
-> install reviewed RPM without config, CA, or claim
-> use its official fingerprint helper as endpoint-agent
-> create a per-host campaign and request a host-bound claim
-> install config, CA, and claim
-> start the service for enrollment
-> verify durable state, remove claim, restart without it
-> revoke the campaign in all outcomes
```

This is safe because the canonical RPM only enables inactive units during the
RPM transaction; it does not start an unconfigured agent.  The claim is still
created immediately before the first service start and is never retained in
the controller inventory, Vault, Git, or Ansible output.

## Trust boundaries

- Gateway communication uses only `https://endpoint.sosnadmin.local` with
  certificate verification enabled and an externally supplied CA file.
- `vault_endpoint_provisioning_token` is the only Gateway secret accepted by
  the role.  It needs only campaign create, campaign revoke, and install-claim
  issue scopes.
- Gateway requests, their responses, the fingerprint, and the claim use
  `no_log: true`.
- The role never creates a Gateway service credential and never uses Helpdesk.
- The only claim location on a target is
  `/etc/credstore/endpoint-enrollment-claim`, owned by `root:root` with mode
  `0600`; its parent directory has mode `0700`.

## Target state and validation

Before pre-staging the RPM, the role requires no installed `endpoint-agent`,
no endpoint configuration or CA, no one-time claim, and no durable enrollment
credential or identity.  It validates the supplied RPM SHA-256, DNS, and the
requested `rpm`, `rpm2cpio`, and `cpio` utilities.  A partially provisioned
host is an explicit failure, not an idempotent re-enrollment attempt.

The role installs the package first, confirms the service remains inactive,
then invokes `/usr/lib/endpoint-agent/endpoint-agent-fingerprint` as the
`endpoint-agent` account.  That helper executes the selected frozen core's
own canonical algorithm; no duplicate Python implementation or external
`psutil` dependency is required.

## Gateway and enrollment

Each target receives a separate campaign with `max_uses: 1`, a configurable
short lifetime, target platform `linux`, and controller-provided allowed CIDRs.
The role then requests a claim bound to the generated installation ID and
fingerprint, writes the non-secret canonical `config.yaml` and CA, and writes
the secret claim exactly once.

It starts `endpoint-agent-update.path` and `endpoint-agent.service`, waits for
the canonical service-owned durable credential and enrollment identity, removes
the claim, restarts the service, and confirms both units are active without a
claim.  Its `always` block removes any local claim and revokes a campaign that
was created, including failures.

## Scope

The changes are limited to the external Ansible playbook, role defaults,
template, tests, and documentation in this repository.  They do not deploy
the role, issue live claims, alter Gateway configuration, or change Helpdesk.
