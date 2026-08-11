# Ansible-controlled ALT agent rollout

## Goal

Allow an Ansible controller to enrol a clean ALT Linux host with the reviewed
Endpoint Agent RPM without an administrator browser session, manual claim
handling, or persistence of a one-time claim.  The controller must use a
single narrow Gateway service credential kept only in Ansible Vault.

## Trust boundary

The initial deployment service credential is deliberately not created by a
playbook.  A Gateway administrator creates it once, records its raw value only
in the existing Ansible Vault, and grants exactly these scopes:

- `provisioning.campaigns.create`
- `provisioning.campaigns.revoke`
- `provisioning.install-claims.issue`

The service client is named `ansible-alt-deployer`.  It is not an administrator
and cannot access device data, updates, users, or arbitrary enrollment
campaigns.  The stored Vault variable is
`vault_endpoint_provisioning_token`; claims never enter Vault, facts, normal
task output, or persistent inventory.

## Gateway API

Add service-authenticated provisioning endpoints under `/api/v1/provisioning`:

- `POST /campaigns` creates one bounded Linux enrollment campaign and returns
  its UUID and non-secret metadata.  It accepts the existing campaign policy
  fields, rejects unknown fields, requires a bounded expiry, canonical CIDRs,
  a positive `max_uses`, and an explicit platform.
- `POST /campaigns/{campaign_id}/revoke` revokes a campaign that was created
  by the authenticated service client.  A different service client receives a
  non-oracular not-found response.

Every create and revoke operation produces the existing immutable audit events
with `actor_kind=service`; no bearer material is logged.  Claim issuance
continues to use the existing endpoint and scope.  The service API never
returns campaign bearer tokens because Ansible uses only hardware-bound,
short-lived install claims.

Campaign ownership must be persisted so that revocation authorization remains
correct across requests.  The migration adds a nullable owner service-client
foreign key to enrollment campaigns.  Existing administrator-created campaigns
remain ownerless and inaccessible to service-client revocation.

## Ansible role

Add a self-contained `deploy/ansible/roles/endpoint_agent_alt` role and a
pilot playbook.  Inputs are the RPM path, Gateway CA path, target CIDRs,
campaign lifetime, and `vault_endpoint_provisioning_token`.

The playbook delegates Gateway API calls to the controller.  It creates one
campaign for the play, determines each target's Linux hardware fingerprint,
requests a per-host claim, writes the three RPM bootstrap files with root-only
permissions, and installs the local RPM immediately.  The claim task and all
derived results use `no_log: true`.  It waits for the durable credential,
absence of the handoff, and the three active systemd units.  In an `always`
block it revokes the campaign, including when a host fails.

The role performs no direct database access and never disables TLS verification
or substitutes an IP address for `endpoint.sosnadmin.local`.  DNS resolution is
a preflight requirement.  The role documents that a campaign has to cover the
target host CIDRs and enough uses for the inventory batch.

## Failure handling and verification

If campaign creation, claim issuance, package installation, or enrollment
fails, Ansible reports a redacted task failure and executes the revocation
step.  It does not delete a previously working agent automatically.  A clean
host test explicitly uninstalls only Endpoint Agent files before the role runs.

Automated tests cover scope enforcement, owner-only revoke, audit-safe
responses, and campaign migration/model behavior.  Role checks cover
`no_log`, TLS/DNS preflight, root-only bootstrap modes, immediate package
installation, enrollment verification, and revocation in the `always` path.
The final integration test will clean `192.168.101.56`, issue a fresh campaign
through the service API, install the RPM, and verify server-side enrollment and
Gateway-ready mode.
