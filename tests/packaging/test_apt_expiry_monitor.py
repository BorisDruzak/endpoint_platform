"""Run the expiry monitor against signed fixtures from two independent issuers."""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
from threading import Thread
import unittest


CHECK = Path(__file__).resolve().parents[2] / "tools/release/check_endpoint_apt_expiry.sh"
CHANNELS = {"ubuntu": "noble", "debian": "bookworm"}


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@unittest.skipUnless(
    os.name == "posix"
    and all(shutil.which(name) for name in ("curl", "gpg", "gpgv", "gpgconf", "openssl", "sh")),
    "requires POSIX shell, curl, GnuPG and OpenSSL",
)
class TestAptExpiryMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "--quick-generate-key" not in subprocess.check_output(["gpg", "--dump-options"], text=True).splitlines():
            raise unittest.SkipTest("requires GnuPG quick key generation")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.signing_home = cls.root / "signing"
        cls.signing_home.mkdir(mode=0o700)
        cls.addClassCleanup(
            subprocess.run, ["gpgconf", "--homedir", cls.signing_home, "--kill", "gpg-agent"], check=True
        )
        cls.gpg = ["gpg", "--homedir", cls.signing_home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        cls.old = cls._generate("Old test issuer")
        cls.new = cls._generate("Successor test issuer")
        cls.keyring = cls.root / "trusted.gpg"
        subprocess.run([*cls.gpg, "--output", cls.keyring, "--export", cls.old, cls.new], check=True, capture_output=True)
        http_root = cls.root / "web"
        http_root.mkdir()
        cls.http_root = http_root
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=http_root))
        cls.addClassCleanup(server.server_close)
        cls.ca = cls.root / "localhost.crt"
        key = cls.root / "localhost.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                "-keyout", key, "-out", cls.ca,
            ],
            check=True, capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.ca, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join, 5)
        cls.addClassCleanup(server.shutdown)
        cls.port = server.server_port

    @classmethod
    def _generate(cls, uid):
        subprocess.run([*cls.gpg, "--quick-generate-key", uid, "ed25519", "sign", "0"], check=True, capture_output=True)
        output = subprocess.check_output([*cls.gpg, "--with-colons", "--list-keys", uid], text=True)
        return next(line.split(":")[9] for line in output.splitlines() if line.startswith("fpr:"))

    def _index(self, channel, fingerprint):
        root = self.http_root / channel / "dists" / CHANNELS[channel]
        root.mkdir(parents=True, exist_ok=True)
        date = datetime.now(UTC) - timedelta(hours=1)
        release = root / "Release"
        release.write_text(
            f"Codename: {CHANNELS[channel]}\nDate: {format_datetime(date, usegmt=True)}\n"
            f"Valid-Until: {format_datetime(date + timedelta(days=7), usegmt=True)}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [*self.gpg, "--yes", "--local-user", fingerprint, "--output", root / "InRelease", "--clearsign", release],
            check=True, capture_output=True,
        )

    def _check(self, ubuntu, debian, **overrides):
        self._index("ubuntu", ubuntu)
        self._index("debian", debian)
        env = {key: value for key, value in os.environ.items() if not key.startswith("ENDPOINT_APT_")}
        env.update(
            ENDPOINT_APT_BASE_URL=f"https://127.0.0.1:{self.port}",
            ENDPOINT_APT_CA=str(self.ca),
            ENDPOINT_APT_KEYRING=str(self.keyring),
            ENDPOINT_APT_FINGERPRINT=self.old,
            NO_PROXY="127.0.0.1",
            no_proxy="127.0.0.1",
            **overrides,
        )
        return subprocess.run(["sh", CHECK], env=env, capture_output=True, text=True, timeout=30)

    def test_common_pin_still_verifies_both_suites(self):
        result = self._check(self.old, self.old)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_channel_can_switch_first(self):
        for channel, ubuntu, debian in (("UBUNTU", self.new, self.old), ("DEBIAN", self.old, self.new)):
            with self.subTest(channel=channel):
                result = self._check(ubuntu, debian, **{f"ENDPOINT_APT_{channel}_FINGERPRINT": self.new})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_keyring_does_not_admit_wrong_channel_signer(self):
        result = self._check(self.old, self.old, ENDPOINT_APT_UBUNTU_FINGERPRINT=self.new)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("InRelease signer does not match the pinned fingerprint", result.stderr)
        self.assertIn("metadata check failed for ubuntu/noble", result.stderr)
        self.assertNotIn("metadata check failed for debian/bookworm", result.stderr)

    def test_published_keyring_must_verify_current_index(self):
        published = {}
        for channel in CHANNELS:
            published[channel] = self.http_root / channel / "endpoint-apt-transition.gpg"
            published[channel].write_bytes(self.keyring.read_bytes())
        settings = {
            "ENDPOINT_APT_UBUNTU_FINGERPRINT": self.new,
            "ENDPOINT_APT_DEBIAN_FINGERPRINT": self.new,
            "ENDPOINT_APT_VERIFY_PUBLIC_KEYRING": "1",
        }
        result = self._check(self.new, self.new, **settings)
        self.assertEqual(result.returncode, 0, result.stderr)

        published["ubuntu"].write_bytes(subprocess.check_output([*self.gpg, "--export", self.old]))
        result = self._check(self.new, self.new, **settings)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("published keyring check failed for ubuntu/noble", result.stderr)
        self.assertNotIn("published keyring check failed for debian/bookworm", result.stderr)

        published["debian"].unlink()
        result = self._check(self.new, self.new, **settings)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("published keyring check failed for debian/bookworm", result.stderr)


if __name__ == "__main__":
    unittest.main()
