# Endpoint Agent ALT Ansible role

Run `playbooks/endpoint_agent_alt_pilot.yml` from an external Ansible
controller. The controller must be Linux with GNU `date`, and needs network
access to the target hosts and to
`https://endpoint.sosnadmin.local`.

Before the first rollout, a Gateway administrator creates one service client
named `ansible-alt-deployer` and one active credential with exactly these
scopes:

- `provisioning.campaigns.create`
- `provisioning.campaigns.revoke`
- `provisioning.install-claims.issue`

Store its raw token only in the controller's existing Ansible Vault:

```yaml
vault_endpoint_provisioning_token: "svc_..."
```

Do not store an enrollment claim in Vault. The role creates a separate
single-use bounded campaign for each host, obtains that host-bound claim over
TLS immediately before RPM installation, and revokes the campaign in its
`always` block.

Build a new reviewed RPM from this rollout revision (it includes the automatic
enrollment finalizer) and copy it to the controller at the path in
`group_vars/endpoint_agent_alt_pilot.example.yml`, copy the Gateway CA to the
two indicated controller paths, then provide inventory and Vault files outside
this repository. Make `endpoint_agent_campaign_cidrs` include each target's
source network. The target must resolve `endpoint.sosnadmin.local`; the role
rejects an IP-address endpoint by not accepting one.
The ALT targets must provide the standard `rpm2cpio` and `cpio` utilities; the
role checks them before it requests any campaign or claim.

Example invocation from that controller:

```bash
ansible-playbook -i inventory.ini playbooks/endpoint_agent_alt_pilot.yml --ask-vault-pass
```
