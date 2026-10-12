"""Native restrictive storage; retained ancestry and permanent original-step claim."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
from uuid import uuid4

from .codec import canonical, digest, require, uuid
from . import windows


class ProtectedStore:
    def __init__(self, root, *, require_protected=True):
        self.root = Path(root).absolute()
        self.require_protected = require_protected
        with self._ancestry():
            pass

    @classmethod
    def create_root(cls, root):
        root = Path(root).absolute()
        require(root.parent.is_dir(), "existing parent required")
        with ExitStack() as stack:
            for ancestor in reversed((root.parent, *root.parent.parents)):
                stack.enter_context(windows.retained(ancestor, directory=True, security=False))
            with windows.security_attributes() as attributes:
                windows.checked(windows.api()[0].CreateDirectoryW(str(root), attributes))
        return cls(root)

    @contextmanager
    def _ancestry(self):
        with ExitStack() as stack:
            for ancestor in reversed(self.root.parents):
                stack.enter_context(windows.retained(ancestor, directory=True, security=False))
            stack.enter_context(windows.retained(self.root, directory=True,
                                                  protected=self.require_protected))
            yield

    def _path(self, name):
        require(type(name) is str and name and Path(name).name == name and name not in (".", "..")
                and not any(c in name for c in '\\/:') and not name.endswith((".", " ")),
                "single unambiguous file name required")
        return self.root / name

    def read(self, name):
        path = self._path(name)
        with self._ancestry(), windows.retained(path, protected=self.require_protected) as handle:
            return windows.read_handle(handle, path)

    def create(self, name, raw):
        path = self._path(name)
        with self._ancestry(), windows.retained(path, writable=True, create=True, protected=True) as handle:
            windows.write_handle(handle, raw)
            windows.flush_volume(path)

    def publish(self, name, raw):
        destination = self._path(name)
        stage = self._path("candidate-" + str(uuid4()) + ".bin")
        with self._ancestry(), windows.retained(stage, writable=True, create=True, protected=True) as handle:
            windows.write_handle(handle, raw)
            # Native non-replacing rename retains the file identity across publication.
            windows.rename_handle(handle, destination)
            windows.information(handle, destination, False)
            windows.flush_volume(destination)
        require(self.read(name) == raw, "published bytes mismatch")

    def claim(self, prefix, continuation_id):
        uuid(continuation_id)
        original = prefix.binding
        key = {"original_run_seal_sha256": original["original_run_seal_sha256"],
               "original_tip": original["original_tip"], "seq": 4}
        claim = {"schema": "task13_dispatch_claim_v1", **key, "continuation_id": continuation_id}
        self.create("claim-" + digest(key) + ".json", canonical(claim))
        return claim
