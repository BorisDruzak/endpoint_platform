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
  --agent-bundle /opt/endpoint-agent-test-pilot-bundle \
  --dry-run
```

The controller stages the immutable release bundle and the reviewed installer
package separately. The public bundle is root-owned and service-readable under
`/opt/endpoint-agent-test-pilot-bundle` so fingerprint collection can run as
the service user. CA and installer inputs remain under root-only `/root/input`.
Staging stops on the first failed filesystem operation.
The offline install commands above apply only to the legacy `pc_agent/pc_agent`
bundle layout. After a successful install, use the fixed finalizer in
`ALT_AGENT_INSTALL.md`; do not manually remove the handoff file.

## Native headless RPM claim delivery

For a reviewed `endpoint-agent/endpoint-agent` bundle, the same controller
validates its manifest, selects that exact fingerprint entrypoint, and delivers
the claim to `/etc/credstore/endpoint-enrollment-claim`. It creates the root-only
credential directory and sends the claim through stdin with mode `0600`.
The legacy bundle continues to use `/etc/endpoint-agent/provisioning-claim`.
Mixed layouts, payload digest mismatches, and unexpected files are rejected
locally before SSH. A headless manifest may exclude the separately reviewed
stable launcher supplied with the local bundle.

This headless path only stages inputs and delivers a claim. The native RPM
must already be installed and its configuration, CA and installation ID must
match the reviewed inputs. Follow `packaging/alt/README.md` for its service
credential/start procedure; do not run the legacy offline installer against
the headless bundle. The controller does not install an RPM or start an agent.
