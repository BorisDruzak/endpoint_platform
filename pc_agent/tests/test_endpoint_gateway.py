"""Endpoint Gateway transport safety boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent import endpoint_gateway


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status
        self.raise_for_status_called = False

    def raise_for_status(self) -> None:
        self.raise_for_status_called = True


def test_gateway_rejects_unauthorized_device_credential_without_retrying_it() -> None:
    response = _Response(401)

    with pytest.raises(endpoint_gateway.GatewayCredentialRejected):
        endpoint_gateway.require_gateway_response(response)

    assert response.raise_for_status_called is False


def test_gateway_uses_only_the_configured_tls_origin() -> None:
    assert endpoint_gateway._ORIGIN == "https://endpoint.sosnadmin.local"


def test_gateway_reads_semantic_release_version_from_strict_alt_selector(
    tmp_path: Path,
) -> None:
    selector = tmp_path / "current.json"
    selector.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.77-rc.1",
            }
        ),
        encoding="utf-8",
    )

    assert endpoint_gateway.read_gateway_current_version(selector) == "3.1.77-rc.1"
