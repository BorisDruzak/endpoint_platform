import pytest

from endpoint_server.modules.service import ModuleServiceError, create_draft_version


def test_module_service_requires_validated_recipe_before_draft_creation() -> None:
    with pytest.raises(ModuleServiceError, match="recipe"):
        create_draft_version(None)
