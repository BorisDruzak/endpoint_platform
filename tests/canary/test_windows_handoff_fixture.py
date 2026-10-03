"""Pre-freeze fixture contracts only; native adapters and artifacts are deferred."""
from dataclasses import replace
from pathlib import Path

import pytest

from tools.canary import prepare_windows_handoff_fixture as fixture


def releases():
    return tuple(fixture.Release(version=f"3.2.{n}", source_revision=f"{n:040x}",
        artifact_sha256=f"{n:064x}", tree_sha256=f"{n+100:064x}",
        payload_floor="3.2.82" if n in {82, 84, 85} else "3.2.81",
        registry_floor="3.2.82" if n in {82, 84, 85} else "3.2.81",
        kind="msi-seed" if n == 86 else "zip") for n in range(82, 88))


def authority():
    return fixture.LegacyAuthority(
        host_sha256=fixture.LEGACY_HOST_SHA256, host_size=10284332,
        source_revision=fixture.LEGACY_SOURCE, compiled_version="3.2.81",
        product_code=fixture.LEGACY_PRODUCT, component_guid=fixture.LEGACY_COMPONENT,
        image_path=fixture.LEGACY_IMAGE, component_path=fixture.LEGACY_IMAGE,
        service_name="EndpointAgent", account="S-1-5-19", service_sid=fixture.SERVICE_SID,
        service_type="own-process", start_type="automatic", state="running",
        scm_pid=20, rechecked_scm_pid=20, runtime_parent_pid=20,
        chain=((20, 10, 200, fixture.LEGACY_IMAGE), (10, 4, 100, fixture.LEGACY_IMAGE)),
        rechecked_chain=((20, 10, 200, fixture.LEGACY_IMAGE), (10, 4, 100, fixture.LEGACY_IMAGE)),
        checks=frozenset(fixture.REQUIRED_NATIVE_CHECKS), explicit=None,
    )


def test_pre_freeze_plan_retains_exact_a_b_routes_and_native_gates():
    a = fixture.plan("A", frozen_source=f"{82:040x}", releases=releases())
    b = fixture.plan("B", frozen_source=f"{82:040x}", releases=releases())
    assert [(s.action, s.version) for s in a] == [
        ("install-canonical-setup", "3.2.82"), ("targeted-ota", "3.2.84"),
        ("targeted-ota", "3.2.85"), ("retire-initial-feature", "3.2.82"),
        ("authenticated-rollback", "3.2.82"), ("same-canonical-setup", "3.2.82")]
    assert [(s.action, s.version) for s in b] == [
        ("verify-immutable-foundation", "3.2.81"), ("install-supplemental-msi", "3.2.86"),
        ("targeted-ota", "3.2.87"), ("authenticated-rollback", "3.2.83"),
        ("uninstall-supplemental-msi", "3.2.86"), ("upgrade-canonical-setup", "3.2.82")]
    with pytest.raises(fixture.NotReady, match="native"):
        fixture.prepare(a, adapter=None, machine_id="vm-test", device_id="device-test")


@pytest.mark.parametrize("field,value", [
    ("payload_floor", None), ("registry_floor", None), ("registry_floor", "3.2.80"),
    ("source_revision", "unfrozen"), ("artifact_sha256", "unknown"),
    ("tree_sha256", "unknown"), ("kind", "production-msi"),
])
def test_immutable_fixture_registration_contract_rejects_missing_or_relabelled_identity(field, value):
    items = list(releases())
    items[1] = replace(items[1], **{field: value})
    with pytest.raises(fixture.NotReady):
        fixture.plan("B", frozen_source=f"{82:040x}", releases=tuple(items))


def test_plan_refuses_before_freeze_and_reused_artifact_or_source_identity():
    with pytest.raises(fixture.NotReady):
        fixture.plan("A", frozen_source=None, releases=releases())
    for key in ("source_revision", "artifact_sha256", "version"):
        items = list(releases())
        items[1] = replace(items[1], **{key: getattr(items[0], key)})
        with pytest.raises(fixture.NotReady):
            fixture.plan("A", frozen_source=f"{82:040x}", releases=tuple(items))


def test_native_authority_contract_accepts_measured_onefile_chain_only_as_preparation_input():
    assert fixture.validate_legacy_authority(authority()) is None
    assert fixture.validate_legacy_authority(replace(authority(), explicit="3.2.81")) is None


@pytest.mark.parametrize("field,value", [
    ("host_sha256", "0" * 64), ("host_size", 0), ("compiled_version", "0.0.0"),
    ("source_revision", "a" * 40), ("product_code", "other"),
    ("component_guid", "other"), ("component_path", "C:/elsewhere/host.exe"),
    ("image_path", "C:/elsewhere/host.exe"), ("service_name", "manual"),
    ("account", "S-1-5-18"), ("service_sid", "S-1-5-19"),
    ("service_type", "shared-process"), ("start_type", "manual"),
    ("state", "stopped"), ("rechecked_scm_pid", 99), ("runtime_parent_pid", 99),
    ("chain", ()), ("rechecked_chain", ()), ("explicit", ""),
    ("explicit", "malformed"), ("explicit", "3.2.82"),
])
def test_authority_contract_rejects_unknown_image_manual_ancestry_and_missing_evidence(field, value):
    with pytest.raises(fixture.NotReady):
        fixture.validate_legacy_authority(replace(authority(), **{field: value}))


@pytest.mark.parametrize("missing", sorted(fixture.REQUIRED_NATIVE_CHECKS))
def test_every_native_check_is_required_before_fixture_start(missing):
    with pytest.raises(fixture.NotReady):
        fixture.validate_legacy_authority(replace(authority(), checks=authority().checks - {missing}))


def test_pid_reuse_and_shell_intermediary_are_rejected():
    observed = authority()
    for chain in (
        ((20, 10, 999, fixture.LEGACY_IMAGE), observed.chain[1]),
        ((20, 10, 200, "C:/Windows/System32/cmd.exe"), observed.chain[1]),
        ((20, 999, 200, fixture.LEGACY_IMAGE), observed.chain[1]),
    ):
        with pytest.raises(fixture.NotReady):
            fixture.validate_legacy_authority(replace(observed, chain=chain))


def test_production_package_does_not_import_preparation_or_legacy_fixture_authority():
    for source in Path("pc_agent").rglob("*.py"):
        if "tests" not in source.parts:
            text = source.read_text(encoding="utf-8")
            assert "prepare_windows_handoff_fixture" not in text
            assert "resolve_fixture_launcher_authority" not in text


class Boundary:
    """Actions change only model state; production adapter is intentionally absent."""
    def __init__(self, steps):
        self.steps, self.position, self.calls = steps, 0, []
        self.wrong = None

    def inspect(self):
        previous = self.steps[self.position - 1] if self.position else None
        if self.position and self.wrong:
            return replace(previous.after, **{self.wrong: "wrong"})
        return previous.after if previous else self.steps[0].before

    def execute(self, step, *, rollback_trigger):
        self.calls.append((step.action, rollback_trigger))
        self.position += 1

    def terminal_rollout(self, version):
        return "11111111-1111-4111-8111-111111111111" if version in {"3.2.85", "3.2.87"} else None

    def require_native_readiness(self, **_):
        pass


@pytest.mark.parametrize("case", ["A", "B"])
def test_sequence_uses_real_rollback_trigger_and_checks_each_predecessor(case):
    steps = fixture.plan(case, frozen_source=f"{82:040x}", releases=releases())
    boundary = Boundary(steps)
    fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == 6
    rollback = next(call for call in boundary.calls if call[0] == "authenticated-rollback")
    assert rollback[1] == "11111111-1111-4111-8111-111111111111"


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("field", ["foundation", "current", "previous", "origin", "initial_feature", "seed_installed"])
def test_partial_or_ambiguous_native_result_stops_without_cleanup(case, field):
    steps = fixture.plan(case, frozen_source=f"{82:040x}", releases=releases())
    boundary = Boundary(steps)
    boundary.wrong = field
    with pytest.raises(fixture.NotReady):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == 1


def seed():
    return fixture.SeedOwnership(
        product_code="{11111111-1111-4111-8111-111111111111}",
        upgrade_code="{22222222-2222-4222-8222-222222222222}",
        component_guids=frozenset({"{33333333-3333-4333-8333-333333333333}"}),
        foundation_product_codes=frozenset({fixture.LEGACY_PRODUCT}),
        foundation_upgrade_codes=frozenset({"{44444444-4444-4444-8444-444444444444}"}),
        foundation_component_guids=frozenset({fixture.LEGACY_COMPONENT}),
        payload_paths=("versions/3.2.86/pc_agent.exe", "fixture-state/3.2.86/receipt.json"),
        service_names=(), removal_roots=("versions/3.2.86",),
        transaction_checks=fixture.SEED_TRANSACTION_CHECKS)


def test_seed_contract_keeps_independent_native_owner():
    assert fixture.validate_seed_ownership(seed()) is None


@pytest.mark.parametrize("field,value", [
    ("product_code", fixture.LEGACY_PRODUCT), ("upgrade_code", "{44444444-4444-4444-8444-444444444444}"),
    ("component_guids", frozenset({fixture.LEGACY_COMPONENT})),
    ("service_names", ("EndpointAgent",)), ("removal_roots", (".",)),
    ("transaction_checks", frozenset()),
])
def test_seed_rejects_shared_foundation_ownership_and_global_cleanup(field, value):
    with pytest.raises(fixture.NotReady):
        fixture.validate_seed_ownership(replace(seed(), **{field: value}))


@pytest.mark.parametrize("path", ["endpoint-agent-service.exe", "installer-state/foundation.json",
    "installer-cache/package.msi", "versions/3.2.83/pc_agent.exe", "data/credential.json",
    "versions/3.2.86/../../current.json", "versions\\3.2.86\\pc_agent.exe"])
def test_seed_payload_cannot_overwrite_fixed_host_or_identity(path):
    with pytest.raises(fixture.NotReady):
        fixture.validate_seed_ownership(replace(seed(), payload_paths=(*seed().payload_paths, path)))


def test_plan_binds_canonical_release_to_exact_frozen_source():
    with pytest.raises(fixture.NotReady):
        fixture.plan("A", frozen_source="f" * 40, releases=releases())


def test_missing_terminal_trigger_cannot_be_fabricated_by_orchestrator():
    steps = fixture.plan("B", frozen_source=f"{82:040x}", releases=releases())
    boundary = Boundary(steps)
    boundary.terminal_rollout = lambda _: None
    with pytest.raises(fixture.NotReady, match="terminal rollout"):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == 3
