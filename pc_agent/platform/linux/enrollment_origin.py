"""Configured enrollment origin shared without importing the Core runtime."""
import os
from collections.abc import Mapping

PRODUCTION_ENDPOINT_ORIGIN = 'https://endpoint.sosnadmin.local'
STAGING_ENDPOINT_ORIGIN = 'https://endpoint-staging.sosnadmin.local'


def configured_endpoint_origin(environment: Mapping[str, str] | None = None) -> str:
    values = os.environ if environment is None else environment
    deployment = values.get('ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT', 'production').strip().lower()
    if deployment == 'production':
        return PRODUCTION_ENDPOINT_ORIGIN
    if deployment != 'staging':
        raise ValueError('ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT must be production or staging')
    if values.get('CANARY_ENVIRONMENT', '').strip().lower() != 'staging':
        raise ValueError('staging agent requires CANARY_ENVIRONMENT=staging')
    if values.get('CANARY_APPROVED', '').strip().lower() != 'true':
        raise ValueError('staging agent requires CANARY_APPROVED=true')
    return STAGING_ENDPOINT_ORIGIN
