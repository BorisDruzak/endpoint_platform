"""Source-only direct-B contracts; native adapters and artifacts stay deferred."""
from dataclasses import replace
from pathlib import Path

import pytest

from tools.canary import prepare_windows_handoff_fixture as fixture


FROZEN_SOURCE = "54759e0287f35ab4c553d89c10f10d83816618ff"


def releases(case):
    versions = (82, 84, 85) if case == "A" else (82, 83)
    return tuple(fixture.Release(version=f"3.2.{n}", source_revision=FROZEN_SOURCE if n == 82 else f"{n:040x}",
        artifact_sha256=f"{n:064x}", tree_sha256=f"{n+100:064x}",
        payload_floor="3.2.82" if n in {82, 84, 85} else "3.2.81",
        registry_floor="3.2.82" if n in {82, 84, 85} else "3.2.81",
        kind="zip") for n in versions)


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


def test_case_specific_inputs_retain_a_and_direct_b_routes_without_seed():
    a = fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"))
    b = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"))
    assert [(s.action, s.version) for s in a] == [
        ("install-canonical-setup", "3.2.82"), ("targeted-ota", "3.2.84"),
        ("targeted-ota", "3.2.85"), ("retire-initial-feature", "3.2.82"),
        ("authenticated-rollback", "3.2.82"), ("same-canonical-setup", "3.2.82")]
    assert [(s.action, s.version) for s in b] == [
        ("verify-immutable-foundation", "3.2.81"), ("targeted-ota", "3.2.83"),
        ("upgrade-canonical-setup", "3.2.82")]
    assert b[0].before == b[0].after == fixture.State("3.2.81", "3.2.81", None, "msi", True)
    assert b[1].after == b[2].before == fixture.State("3.2.81", "3.2.83", "3.2.81", "zip", True)
    assert b[2].after == fixture.State("3.2.82", "3.2.83", "3.2.81", "zip", True)
    assert all(step.rollback_from is None and not step.after.seed_installed for step in b)
    for steps in (a, b):
        with pytest.raises(fixture.NotReady, match="native"):
            fixture.prepare(steps, adapter=None, machine_id="vm-test", device_id="device-test")


@pytest.mark.parametrize("previous", [None, "3.2.81"])
def test_b_preserves_permitted_initial_previous_through_verification(previous):
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous=previous)
    assert steps[0].before == steps[0].after == steps[1].before == fixture.State(
        "3.2.81", "3.2.81", previous, "msi", True)
    assert steps[1].after == steps[2].before == fixture.State("3.2.81", "3.2.83", "3.2.81", "zip", True)
    assert steps[2].after == fixture.State("3.2.82", "3.2.83", "3.2.81", "zip", True)
    boundary = Boundary(steps)
    fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == [("verify-immutable-foundation", None), ("targeted-ota", None),
        ("upgrade-canonical-setup", None)]
    assert boundary.readiness == [dict(step=step, machine_id="vm-test", device_id="device-test", phase=phase)
        for step in steps for phase in ("before", "after")]


@pytest.mark.parametrize("previous", ["3.2.79", "3.2.82", "3.2.83", "unknown", "", " 3.2.81",
    "3.2.81\n", "03.2.81", 81, False, [], {}, ("3.2.81",)])
def test_b_cannot_declare_arbitrary_or_malformed_initial_history(previous):
    with pytest.raises(fixture.NotReady):
        fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous=previous)


def test_initial_previous_parameter_does_not_generalize_a_start():
    original = fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"))
    assert fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"), initial_previous=None) == original
    with pytest.raises(fixture.NotReady):
        fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"), initial_previous="3.2.81")


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("reason", ["source differs", "hash differs", "ownership unavailable", "presence differs"])
def test_same81_model_cannot_override_native_previous_proof_failure(phase, reason):
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous="3.2.81")
    boundary = Boundary(steps)
    def require(**request):
        if request["phase"] == phase:
            raise fixture.NotReady(reason)
    boundary.require_native_readiness = require
    with pytest.raises(fixture.NotReady, match=reason):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == (0 if phase == "before" else 1)


@pytest.mark.parametrize("declared,actual", [(None, "3.2.81"), ("3.2.81", None), ("3.2.81", "3.2.79")])
def test_initial_history_must_match_actual_inspected_predecessor(declared, actual):
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous=declared)
    boundary = Boundary(steps)
    boundary.inspect = lambda: replace(steps[0].before, previous=actual)
    with pytest.raises(fixture.NotReady, match="predecessor"):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == []
    assert len(boundary.readiness) == 1


@pytest.mark.parametrize("field,value", [("previous", None), ("previous", "3.2.79"),
    ("foundation", "3.2.82"), ("current", "3.2.83"), ("origin", "zip"), ("seed_installed", True)])
def test_same81_sequence_reconstruction_rejects_changed_initial_state(field, value):
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous="3.2.81")
    changed = (replace(steps[0], before=replace(steps[0].before, **{field: value})), *steps[1:])
    boundary = Boundary(steps)
    with pytest.raises(fixture.NotReady):
        fixture.prepare(changed, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == boundary.readiness == []


@pytest.mark.parametrize("alteration", ["action", "rollback", "discard_previous"])
def test_same81_shape_does_not_authorize_a_changed_verification_step(alteration):
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"), initial_previous="3.2.81")
    first = {"action": replace(steps[0], action="targeted-ota"),
        "rollback": replace(steps[0], rollback_from="3.2.85"),
        "discard_previous": replace(steps[0], after=replace(steps[0].after, previous=None))}[alteration]
    boundary = Boundary(steps)
    with pytest.raises(fixture.NotReady, match="sequence"):
        fixture.prepare((first, *steps[1:]), adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == boundary.readiness == []


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("field,value", [
    ("payload_floor", None), ("registry_floor", None), ("registry_floor", "3.2.80"),
    ("source_revision", "unfrozen"), ("artifact_sha256", "unknown"),
    ("tree_sha256", "unknown"), ("kind", "production-msi"), ("kind", "msi-seed"),
    ("source_revision", None), ("artifact_sha256", None), ("tree_sha256", None),
])
def test_immutable_fixture_registration_contract_rejects_missing_or_relabelled_identity(case, field, value):
    items = list(releases(case))
    items[1] = replace(items[1], **{field: value})
    with pytest.raises(fixture.NotReady):
        fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=tuple(items))


@pytest.mark.parametrize("case", ["A", "B"])
def test_plan_refuses_before_freeze_and_reused_artifact_or_source_identity(case):
    with pytest.raises(fixture.NotReady):
        fixture.plan(case, frozen_source=None, releases=releases(case))
    for key in ("source_revision", "artifact_sha256", "version"):
        items = list(releases(case))
        items[1] = replace(items[1], **{key: getattr(items[0], key)})
        with pytest.raises(fixture.NotReady):
            fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=tuple(items))


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("extra", ["3.2.81", "3.2.84", "3.2.86", "3.2.87", "3.2.99"])
def test_extra_unknown_or_duplicate_release_input_is_not_ignored(case, extra):
    items = (*releases(case), replace(releases(case)[0], version=extra))
    with pytest.raises(fixture.NotReady):
        fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=items)


@pytest.mark.parametrize("case", ["A", "B"])
def test_missing_release_and_wrong_canonical_floor_are_rejected(case):
    items = releases(case)
    with pytest.raises(fixture.NotReady):
        fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=items[:-1])
    with pytest.raises(fixture.NotReady):
        fixture.plan(case, frozen_source=FROZEN_SOURCE,
            releases=(replace(items[0], payload_floor="3.2.81", registry_floor="3.2.81"), *items[1:]))


@pytest.mark.parametrize("case", ["A", "B"])
def test_same_count_unknown_version_or_coherent_wrong_fixture_floor_is_rejected(case):
    items = releases(case)
    wrong_floor = "3.2.81" if case == "A" else "3.2.82"
    for substitute in (replace(items[1], version="3.2.87"),
        replace(items[1], payload_floor=wrong_floor, registry_floor=wrong_floor)):
        with pytest.raises(fixture.NotReady):
            fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=(items[0], substitute, *items[2:]))


def test_different_valid_frozen_hash_does_not_rebind_canonical82():
    items = releases("B")
    with pytest.raises(fixture.NotReady):
        fixture.plan("B", frozen_source="a" * 40,
            releases=(replace(items[0], source_revision="a" * 40), items[1]))


def test_unknown_case_cannot_choose_a_default_release_set():
    with pytest.raises(fixture.NotReady):
        fixture.plan("unknown", frozen_source=FROZEN_SOURCE, releases=releases("B"))


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
        self.readiness = []

    def inspect(self):
        previous = self.steps[self.position - 1] if self.position else None
        if self.position and self.wrong:
            return replace(previous.after, **{self.wrong: "wrong"})
        return previous.after if previous else self.steps[0].before

    def execute(self, step, *, rollback_trigger):
        self.calls.append((step.action, rollback_trigger))
        self.position += 1

    def terminal_rollout(self, version):
        return "11111111-1111-4111-8111-111111111111" if version == "3.2.85" else None

    def require_native_readiness(self, **evidence_request):
        self.readiness.append(evidence_request)


def test_a_sequence_keeps_its_real85_rollback_trigger():
    steps = fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"))
    boundary = Boundary(steps)
    fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == 6
    rollback = next(call for call in boundary.calls if call[0] == "authenticated-rollback")
    assert rollback[1] == "11111111-1111-4111-8111-111111111111"


def test_b_sequence_never_requests_a_rollback_or_seed_action():
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"))
    boundary = Boundary(steps)
    boundary.terminal_rollout = lambda _: pytest.fail("B has no rollback trigger")
    fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == [("verify-immutable-foundation", None), ("targeted-ota", None),
        ("upgrade-canonical-setup", None)]


@pytest.mark.parametrize("case", ["A", "B"])
def test_each_action_requires_native_readiness_before_and_after(case):
    steps = fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=releases(case))
    boundary = Boundary(steps)
    fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.readiness == [dict(step=step, machine_id="vm-test", device_id="device-test", phase=phase)
        for step in steps for phase in ("before", "after")]


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_failed_readiness_stops_before_next_action_without_cleanup(case, phase):
    steps = fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=releases(case))
    boundary = Boundary(steps)
    def require(**request):
        if request["phase"] == phase:
            raise fixture.NotReady("native evidence unavailable")
    boundary.require_native_readiness = require
    with pytest.raises(fixture.NotReady, match="native evidence"):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == (0 if phase == "before" else 1)


def test_b_rechecks_previous81_retention_before_setup_and_stops_on_failure():
    steps = fixture.plan("B", frozen_source=FROZEN_SOURCE, releases=releases("B"))
    boundary = Boundary(steps)
    def require(**request):
        if request["step"].action == "upgrade-canonical-setup" and request["phase"] == "before":
            assert boundary.inspect().previous == "3.2.81"
            raise fixture.NotReady("native previous81 retention unavailable")
    boundary.require_native_readiness = require
    with pytest.raises(fixture.NotReady, match="previous81 retention"):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == [("verify-immutable-foundation", None), ("targeted-ota", None)]


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("alteration", ["skip", "reorder", "previous", "trigger"])
def test_altered_sequences_reject_before_native_actions(case, alteration):
    steps = fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=releases(case))
    changed = {"skip": steps[:-1], "reorder": tuple(reversed(steps)),
        "previous": (replace(steps[0], after=replace(steps[0].after, previous="3.2.87")), *steps[1:]),
        "trigger": (replace(steps[0], rollback_from="3.2.87"), *steps[1:])}[alteration]
    boundary = Boundary(steps)
    with pytest.raises(fixture.NotReady, match="sequence"):
        fixture.prepare(changed, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert boundary.calls == boundary.readiness == []


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("field", ["foundation", "current", "previous", "origin", "initial_feature", "seed_installed"])
def test_partial_or_ambiguous_native_result_stops_without_cleanup(case, field):
    steps = fixture.plan(case, frozen_source=FROZEN_SOURCE, releases=releases(case))
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
        fixture.plan("A", frozen_source="f" * 40, releases=releases("A"))


@pytest.mark.parametrize("trigger", [None, "", "not-a-uuid", "11111111111141118111111111111111"])
def test_missing_or_malformed_a_terminal_trigger_cannot_be_fabricated(trigger):
    steps = fixture.plan("A", frozen_source=FROZEN_SOURCE, releases=releases("A"))
    boundary = Boundary(steps)
    boundary.terminal_rollout = lambda _: trigger
    with pytest.raises(fixture.NotReady, match="terminal rollout"):
        fixture.prepare(steps, adapter=boundary, machine_id="vm-test", device_id="device-test")
    assert len(boundary.calls) == 4
