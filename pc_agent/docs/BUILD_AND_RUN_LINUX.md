# Build and run the Linux Endpoint Agent

Build the isolated headless artifact on Linux:

```bash
python -m pip install -r requirements/build-linux.txt
python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
python tools/build_linux_agent.py --channel canary
```

For an ALT RPM, use `packaging/alt/build-rpm.sh`. It constructs the core and
launcher artifacts, validates immutable manifests, and stages the RPM inputs.
The installed executable is `endpoint-agent`; it starts
`pc_agent/runtime/main.py` and requires Endpoint enrollment identity and a
device credential in the configured data directory.

Do not add GUI, requester/ticket, Helpdesk WebSocket, or Remote Assist runtime
dependencies to this artifact.
