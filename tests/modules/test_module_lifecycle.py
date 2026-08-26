import pytest

from endpoint_server.modules.lifecycle import ModuleLifecycleError, transition_module_version


def test_module_lifecycle_allows_only_valid_forward_transitions() -> None:
    assert transition_module_version("draft", "validated") == "validated"
    assert transition_module_version("validated", "lab_accepted") == "lab_accepted"
    assert transition_module_version("lab_accepted", "published") == "published"
    assert transition_module_version("published", "deprecated") == "deprecated"


@pytest.mark.parametrize(
    ("current", "target"),
    [("draft", "published"), ("validation_failed", "published"), ("revoked", "published"), ("deprecated", "validated")],
)
def test_module_lifecycle_rejects_bypasses_and_reactivation(current: str, target: str) -> None:
    with pytest.raises(ModuleLifecycleError):
        transition_module_version(current, target)
