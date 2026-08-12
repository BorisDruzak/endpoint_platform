# Endpoint Agent ALT Ansible role

Run `playbooks/endpoint_agent_alt_pilot.yml` from an external Linux Ansible
controller with GNU `date`, access to ALT hosts, and access to
`https://endpoint.sosnadmin.local`.

Before rollout, a Gateway administrator creates one service credential with
only these scopes:

- `provisioning.campaigns.create`
- `provisioning.campaigns.revoke`
- `provisioning.install-claims.issue`

Store its raw token only in the controller's existing Ansible Vault:

```yaml
vault_endpoint_provisioning_token: "svc_..."
```

Do not store an enrollment claim, campaign bearer, or device credential in
Vault, inventory, or Git. The Gateway CA is an external controller file and
is also not committed.

## First-install order

For a pristine target, the role verifies the reviewed RPM SHA-256 and installs
the RPM without configuration, CA, or claim. The RPM creates the
`endpoint-agent` service account and enables its units, but the agent stays
inactive because the required bootstrap inputs do not exist.

The role renders the fixed non-secret config and then runs the RPM-shipped
`/usr/lib/endpoint-agent/endpoint-agent-fingerprint --enrollment-binding` as
root. The helper reads only the root-owned `installation_id`, drops to
`endpoint-agent`, and asks the selected frozen core for the binding. Gateway
claim issuance uses both returned values, so the claim and the later agent
request cannot use independently rendered fingerprint or installation-ID data.

Only after that pre-stage phase does the role create a unique `max_uses: 1`
campaign, request the host-bound one-time claim, and install the bootstrap
files. The claim is created immediately before its first service start and is
written only to:

```text
/etc/credstore/endpoint-enrollment-claim
```

with `root:root` ownership and `0600` permissions. `config.yaml` and the CA
are at `/etc/endpoint-agent/`, also root-owned `0600` files.

Before copying a fresh claim to ALT, the controller calls the Gateway
non-consuming claim preflight. It returns only success or a generic failure;
the bearer is neither logged, stored, nor consumed. If the preflight fails,
the role stops before installing bootstrap authority or starting the RPM.

After enrollment creates the durable credential and identity, the role removes
the claim, restarts the service, and verifies it is active without a claim. A
campaign is revoked from the role's `always` block even if any installation
step fails. All claim, fingerprint, Gateway request, and Gateway response
handling is `no_log`.

The role intentionally rejects a partial or already-enrolled installation.
For a failed rollout, an operator may explicitly set
`endpoint_agent_recover_partial_install: true`. The role first proves that no
durable credential or enrollment identity exists, then stops the partial
service, removes only its config, CA, one-time claim and RPM. It also removes a
strictly recognized, unowned legacy unit that would shadow the packaged unit.
It never recovers an enrolled machine automatically; do not use this option
while another rollout is in progress.

## Controller inputs

Copy `group_vars/endpoint_agent_alt_pilot.example.yml` outside this repository
and provide:

- the reviewed RPM path and its SHA-256;
- the CA path on the controller for target copy and TLS validation;
- the CIDRs from which each target reaches Gateway;
- the Vault file containing `vault_endpoint_provisioning_token`.

The role uses only the named HTTPS Gateway, with certificate verification and
proxy use disabled. It never creates service credentials and does not use
Helpdesk.

Example invocation:

```bash
ansible-playbook -i inventory.ini playbooks/endpoint_agent_alt_pilot.yml --ask-vault-pass
```
