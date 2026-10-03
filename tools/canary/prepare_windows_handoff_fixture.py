"""Reviewed source-only A/B preparation contract, NOT an installed fixture tool.

Native adapters, immutable83-87 builds, fixed-image authority helper/entry/spec
and supplemental86 MSI belong to a separate post-canonical-freeze source branch.
There is deliberately no CLI, shell execution, native resolver or production
runtime import here. An absent backend always fails NOT READY. Adapter evidence
is trusted only after independent native review; model tests cannot attest it.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol
from uuid import UUID

LEGACY_HOST_SHA256 = "4de1f985ac72ac74e910e0deffd406e5145cf21cce150df702febb15ca9c150c"
LEGACY_SOURCE = "c05bb0a528527ed1544c88fb0b1570c64b32084d"
LEGACY_PRODUCT = "{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}"
LEGACY_COMPONENT = "{A10A61A1-B511-4A07-9D37-C592515D217E}"
LEGACY_IMAGE = r"C:\Program Files\Endpoint Platform\Agent\endpoint-agent-service.exe"
SERVICE_SID = "S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691"

# Evidence requirements for the future native adapter. They are not runtime
# switches or permission grants. Effective rights must account for inherit-only
# ACEs; genuine81 product directories have inherited DACLs and ordinary Users RX.
REQUIRED_NATIVE_CHECKS = frozenset({
    "actual-service-token", "enabled-service-sid", "same-logon-context",
    "minimal-token-query", "held-process-handles", "creation-times-rechecked",
    "canonical-scm-imagepath", "nonreparse-image-and-ancestors",
    "stable-open-file-identity", "stable-open-file-sha256", "trusted-owner",
    "nonnull-readable-dacl", "no-untrusted-effective-image-write",
    "no-untrusted-effective-ancestor-delete-child", "no-untrusted-write-dac-owner",
    "installed-machine-product", "local-product-scoped-component",
    "independent-msi-extraction", "compiled-source-version-corroboration",
})


class NotReady(ValueError):
    """A fixture prerequisite is absent, inconsistent or unverified."""


@dataclass(frozen=True)
class Release:
    version: str
    source_revision: str
    artifact_sha256: str
    tree_sha256: str
    payload_floor: str
    registry_floor: str
    kind: str


@dataclass(frozen=True)
class LegacyAuthority:
    """Read-only native adapter observations; never accepted from user JSON."""
    host_sha256: str
    host_size: int
    source_revision: str
    compiled_version: str
    product_code: str
    component_guid: str
    image_path: str
    component_path: str
    service_name: str
    account: str
    service_sid: str
    service_type: str
    start_type: str
    state: str
    scm_pid: int
    rechecked_scm_pid: int
    runtime_parent_pid: int
    chain: tuple[tuple[int, int, int, str], ...]
    rechecked_chain: tuple[tuple[int, int, int, str], ...]
    checks: frozenset[str]
    explicit: str | None


def validate_legacy_authority(value: LegacyAuthority) -> None:
    """Validate the measured81 preparation contract; never resolve runtime argv."""
    expected = {
        "host_sha256": LEGACY_HOST_SHA256, "host_size": 10284332,
        "source_revision": LEGACY_SOURCE, "compiled_version": "3.2.81",
        "product_code": LEGACY_PRODUCT, "component_guid": LEGACY_COMPONENT,
        "image_path": LEGACY_IMAGE, "component_path": LEGACY_IMAGE,
        "service_name": "EndpointAgent", "account": "S-1-5-19", "service_sid": SERVICE_SID,
        "service_type": "own-process", "start_type": "automatic", "state": "running",
    }
    if any(getattr(value, key) != wanted for key, wanted in expected.items()):
        raise NotReady("immutable81 native identity differs")
    if value.explicit not in {None, "3.2.81"} or value.checks != REQUIRED_NATIVE_CHECKS:
        raise NotReady("native authority evidence incomplete or conflicting")
    chain = value.chain
    if (len(chain) != 2 or chain != value.rechecked_chain
        or value.scm_pid <= 0 or value.scm_pid != value.rechecked_scm_pid
        or value.runtime_parent_pid != value.scm_pid or chain[0][0] != value.scm_pid
        or chain[0][1] != chain[1][0] or chain[0][0] == chain[1][0]
        or any(pid <= 0 or created <= 0 or image != LEGACY_IMAGE for pid, _, created, image in chain)
        or chain[0][2] <= chain[1][2]):
        raise NotReady("native service ancestry changed or unsupported")


@dataclass(frozen=True)
class SeedOwnership:
    product_code: str
    upgrade_code: str
    component_guids: frozenset[str]
    foundation_product_codes: frozenset[str]
    foundation_upgrade_codes: frozenset[str]
    foundation_component_guids: frozenset[str]
    payload_paths: tuple[str, ...]
    service_names: tuple[str, ...]
    removal_roots: tuple[str, ...]
    transaction_checks: frozenset[str]


SEED_TRANSACTION_CHECKS = frozenset({"shared-protected-exclusion", "durable-restore-before-stop",
    "scm-stop-and-wait", "msi-owned-selector-publication", "scm-restart-unchanged-host",
    "full-seed-payload-identity", "preserved-foundation-and-machine-identity",
    "unknown-files-fail-closed", "retained-external-evidence"})


def validate_seed_ownership(value: SeedOwnership) -> None:
    """Validate compiled native MSI observations, not an MSI authoring shortcut."""
    all_guids = (value.product_code, value.upgrade_code, *value.component_guids,
        *value.foundation_product_codes, *value.foundation_upgrade_codes, *value.foundation_component_guids)
    if any(not isinstance(item, str) or not re.fullmatch(
        r"\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}", item) for item in all_guids):
        raise NotReady("seed MSI identities are not canonical native GUIDs")
    if (not value.component_guids or LEGACY_PRODUCT not in value.foundation_product_codes
        or not value.foundation_upgrade_codes or not value.foundation_component_guids
        or value.product_code in value.foundation_product_codes
        or value.upgrade_code in value.foundation_upgrade_codes
        or value.component_guids & value.foundation_component_guids
        or value.service_names or value.removal_roots != ("versions/3.2.86",)
        or value.transaction_checks != SEED_TRANSACTION_CHECKS):
        raise NotReady("seed MSI ownership or transaction is not isolated")
    if not value.payload_paths or "versions/3.2.86/pc_agent.exe" not in value.payload_paths:
        raise NotReady("seed MSI core is missing")
    for path in value.payload_paths:
        if (not isinstance(path, str) or not path.startswith(("versions/3.2.86/", "fixture-state/3.2.86/"))
            or "\\" in path or ":" in path or any(part in {"", ".", ".."} for part in path.split("/"))):
            raise NotReady("seed MSI owns forbidden foundation or global state")


@dataclass(frozen=True)
class State:
    """Expected sequence shape, additional byte/security checks stay native."""
    foundation: str
    current: str
    previous: str | None
    origin: str
    initial_feature: bool
    seed_installed: bool = False


@dataclass(frozen=True)
class Step:
    action: str
    version: str
    before: State
    after: State
    releases: tuple[Release, ...]
    frozen_source: str
    rollback_from: str | None = None


def plan(case: str, *, frozen_source: str | None, releases: tuple[Release, ...]) -> tuple[Step, ...]:
    """Require immutable inputs; do not build, register, change floors or deploy."""
    if not isinstance(frozen_source, str) or not re.fullmatch(r"[0-9a-f]{40}", frozen_source):
        raise NotReady("canonical source is not frozen")
    expected = {f"3.2.{n}" for n in range(82, 88)}
    if len(releases) != 6 or {release.version for release in releases} != expected:
        raise NotReady("immutable82-87 inputs missing or duplicated")
    for field in ("source_revision", "artifact_sha256"):
        if len({getattr(item, field) for item in releases}) != len(releases):
            raise NotReady("fixture identities must be independently frozen")
    for item in releases:
        floor = "3.2.82" if item.version in {"3.2.82", "3.2.84", "3.2.85"} else "3.2.81"
        if (item.payload_floor != floor or item.registry_floor != floor
            or item.kind != ("msi-seed" if item.version == "3.2.86" else "zip")
            or not re.fullmatch(r"[0-9a-f]{40}", item.source_revision)
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (item.artifact_sha256, item.tree_sha256))):
            raise NotReady("fixture payload/source/floor identity differs")
        if item.version == "3.2.82" and item.source_revision != frozen_source:
            raise NotReady("canonical82 source differs from the frozen revision")
    if case == "A":
        states = (
            State("absent", "absent", None, "absent", False),
            State("3.2.82", "3.2.82", None, "msi", True),
            State("3.2.82", "3.2.84", "3.2.82", "zip", True),
            State("3.2.82", "3.2.85", "3.2.84", "zip", True),
            State("3.2.82", "3.2.85", "3.2.84", "zip", False),
            State("3.2.82", "3.2.82", "3.2.85", "zip", False),
            State("3.2.82", "3.2.82", "3.2.85", "msi", True),
        )
        actions = (("install-canonical-setup", "3.2.82"), ("targeted-ota", "3.2.84"),
            ("targeted-ota", "3.2.85"), ("retire-initial-feature", "3.2.82"),
            ("authenticated-rollback", "3.2.82"), ("same-canonical-setup", "3.2.82"))
        trigger = "3.2.85"
    elif case == "B":
        baseline = State("3.2.81", "3.2.81", None, "msi", True)
        states = (baseline, baseline,
            State("3.2.81", "3.2.86", "3.2.81", "msi", True, True),
            State("3.2.81", "3.2.87", "3.2.86", "zip", True, True),
            State("3.2.81", "3.2.83", "3.2.87", "zip", True, True),
            State("3.2.81", "3.2.83", "3.2.87", "zip", True),
            State("3.2.82", "3.2.83", "3.2.87", "zip", True))
        actions = (("verify-immutable-foundation", "3.2.81"), ("install-supplemental-msi", "3.2.86"),
            ("targeted-ota", "3.2.87"), ("authenticated-rollback", "3.2.83"),
            ("uninstall-supplemental-msi", "3.2.86"), ("upgrade-canonical-setup", "3.2.82"))
        trigger = "3.2.87"
    else:
        raise NotReady("unknown fixture case")
    return tuple(Step(action, version, states[index], states[index+1], releases, frozen_source,
        trigger if action == "authenticated-rollback" else None)
        for index, (action, version) in enumerate(actions))


class NativePreparation(Protocol):
    """Post-freeze backend contract; no implementation is shipped in canonical82.

require_native_readiness must verify dedicated machine/device, frozen sources,
    signed canonical package identities, full payload/source/tree/floor identity,
    live product/component/feature and retained package identities, effective ACL,
    active-update exclusion, delivered terminal proofs, original enrollment/CA/
    origin hashes and protected external evidence before AND after each action.

    It must revalidate the same immutable setup/cache/foundation bytes, all current
    and previous payload/receipt bytes, and preserve identity at every step.
    Retirement uses canonical Task7 owner/fence and Windows Installer exclusively.
    Seed86 must have disjoint Product/Upgrade/component ownership, only its core
    and fixture evidence, no services/foundation/cache/credentials/global cleanup;
    selector publication belongs to its reviewed durable MSI transaction and SCM.
    Authority81 is queried under the actual unchanged service token before hello.
    Target/rollback actions use canonical authenticated APIs and terminal rollout
    identities. All partial/ambiguous results stop, retain evidence, and require
    native recovery review; never raw cleanup or hand-authored state.
    """
    def require_native_readiness(self, *, step: Step, machine_id: str, device_id: str, phase: str) -> None: ...
    def inspect(self) -> State: ...
    def execute(self, step: Step, *, rollback_trigger: str | None) -> None: ...
    def terminal_rollout(self, version: str) -> str | None: ...


def prepare(steps: tuple[Step, ...], *, adapter: NativePreparation | None,
            machine_id: str, device_id: str) -> None:
    """One supervised sequence. No resumptive cleanup of an ambiguous fixture."""
    if adapter is None:
        raise NotReady("reviewed post-freeze native adapter/artifacts are required")
    if not machine_id or not device_id or not steps:
        raise NotReady("dedicated fixture identity is required")
    case = "A" if steps[0].action == "install-canonical-setup" else "B"
    if steps != plan(case, frozen_source=steps[0].frozen_source, releases=steps[0].releases):
        raise NotReady("fixture sequence was altered")
    for step in steps:
        adapter.require_native_readiness(step=step, machine_id=machine_id, device_id=device_id, phase="before")
        if adapter.inspect() != step.before:
            raise NotReady("native predecessor does not match; retain evidence")
        trigger = None
        if step.rollback_from:
            trigger = adapter.terminal_rollout(step.rollback_from)
            try:
                if not isinstance(trigger, str) or str(UUID(trigger)) != trigger:
                    raise ValueError
            except ValueError:
                raise NotReady("real terminal rollout trigger is required") from None
        adapter.execute(step, rollback_trigger=trigger)
        adapter.require_native_readiness(step=step, machine_id=machine_id, device_id=device_id, phase="after")
        if adapter.inspect() != step.after:
            raise NotReady("native outcome differs; retain evidence without cleanup")
