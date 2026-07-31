# ALT test-agent pilot controller

Run this controller only from the primary Endpoint Platform worktree. It is
hard-wired to `test-agent-lin`; it has no target-host or endpoint option and
must never be used for a production host.

It accepts only a reviewed local bundle, local CA trust anchor, bounded
installation ID, and administrator username. The administrator password is
requested from the controlling TTY; do not supply it in a command, file, or
environment variable.

```bash
python tools/provision_alt_test_agent.py \
  --bundle /path/to/endpoint-agent-test-pilot-bundle \
  --ca-file /path/to/sosnadmin-local-ca.crt \
  --installation-id <installation-id> \
  --admin-username <administrator-name>
```

The command stages only the reviewed bundle and CA on `test-agent-lin`, derives
its canonical SHA-256 hardware proof, obtains a short service credential with
only the install-claim scope, and writes the resulting one-time claim to the
root-owned handoff file through standard input. It revokes the temporary
service credential and administrator session before returning.

Expected output is one redacted JSON object containing only the installation
ID, hardware fingerprint, campaign UUID, and claim expiry. It never prints a
password, campaign bearer, service bearer, claim, device credential, or raw
server error.

Immediately run the staged installer dry-run on `test-agent-lin`, then repeat
without `--dry-run` only after it succeeds:

```bash
sudo bash /root/input/endpoint-agent-installer/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --installation-id <installation-id> \
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /etc/endpoint-agent/provisioning-claim \
  --agent-bundle /root/input/endpoint-agent-test-pilot-bundle \
  --dry-run
```

The controller stages the immutable release bundle and the reviewed installer
package separately. After a successful install, use the fixed finalizer in
`ALT_AGENT_INSTALL.md`; do not manually remove the handoff file.
