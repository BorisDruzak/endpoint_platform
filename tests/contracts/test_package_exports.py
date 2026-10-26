"""Package model exports retain their identities when loading offline helpers."""
import importlib

import pytest

import endpoint_contracts


def test_package_model_exports_are_the_original_defining_objects():
    modules = [importlib.import_module('endpoint_contracts.' + name) for name in (
        'commands', 'activity', 'context', 'enrollment', 'gateway_ws',
        'security_events', 'power_events', 'sensor_health', 'endpoint_policy', 'identity',
        'network_primitives', 'read_only_primitives', 'capabilities', 'modules',
        'operations', 'telemetry', 'updates',
    )]
    for name in endpoint_contracts.__all__:
        value = getattr(endpoint_contracts, name)
        originals = [getattr(module, name) for module in modules if hasattr(module, name)]
        assert originals and all(value is original for original in originals)
        assert name in dir(endpoint_contracts)


def test_unknown_package_attribute_still_raises_attribute_error():
    with pytest.raises(AttributeError):
        getattr(endpoint_contracts, 'not_a_contract_export')
