"""Disabled by default OIDC deployment settings; secrets remain server side."""
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
from endpoint_server.identity.helpdesk_client import https_origin


@dataclass(frozen=True, slots=True)
class OIDCSettings:
    enabled: bool = False
    issuer: str = ''
    employee_client_id: str = ''
    employee_client_secret: str = field(default='', repr=False)
    admin_client_id: str = ''
    admin_client_secret: str = field(default='', repr=False)
    admin_required_acr: str = ''
    helpdesk_base_url: str = ''
    helpdesk_credential: str = field(default='', repr=False)
    encryption_key: bytes = field(default=b'', repr=False)
    ca_file: str | None = None
    breakglass_usernames: tuple[str,...] = ()
    breakglass_until: datetime | None = None

    def __post_init__(self):
        if self.breakglass_usernames:
            if (self.breakglass_until is None or self.breakglass_until.tzinfo is None
                or self.breakglass_until > datetime.now(UTC)+timedelta(hours=24)
                or any(not name or name!=name.strip() for name in self.breakglass_usernames)):
                raise ValueError('Breakglass requires explicit usernames and UTC expiry within24 hours')
        if not self.enabled:
            return
        https_origin(self.issuer)
        if self.issuer.endswith('/'):
            raise ValueError('OIDC issuer must be exact without trailing slash')
        if not self.employee_client_id or not self.admin_client_id or self.employee_client_id == self.admin_client_id:
            raise ValueError('Distinct employee and admin OIDC clients required')
        if not self.employee_client_secret or not self.admin_client_secret or not self.admin_required_acr:
            raise ValueError('Confidential OIDC clients and explicit MFA acr required')
        from endpoint_server.identity.helpdesk_client import HelpdeskIdentityClient
        HelpdeskIdentityClient(self.helpdesk_base_url, self.helpdesk_credential,ca_file=self.ca_file)
        Fernet(self.encryption_key)

    @classmethod
    def from_environment(cls, values):
        emergency = tuple(name.strip() for name in values.get('OIDC_BREAKGLASS_USERNAMES','').split(',') if name.strip())
        until = datetime.fromisoformat(values['OIDC_BREAKGLASS_UNTIL']) if values.get('OIDC_BREAKGLASS_UNTIL') else None
        enabled = values.get('ENDPOINT_SSO_ENABLED','').lower() in {'true','1'}
        if not enabled:
            if values.get('ENDPOINT_SSO_ENABLED','').lower() not in {'','false','0'}:
                raise ValueError('ENDPOINT_SSO_ENABLED must be boolean')
            return cls(breakglass_usernames=emergency,breakglass_until=until)
        from pathlib import Path
        from endpoint_server.config import load_secret_file
        def secret(name):
            return load_secret_file(Path(values[name])).strip()
        return cls(enabled=True, issuer=values['OIDC_ISSUER'], employee_client_id=values['OIDC_EMPLOYEE_CLIENT_ID'],
            employee_client_secret=secret('OIDC_EMPLOYEE_CLIENT_SECRET_FILE').decode('utf-8'),
            admin_client_id=values['OIDC_ADMIN_CLIENT_ID'], admin_client_secret=secret('OIDC_ADMIN_CLIENT_SECRET_FILE').decode('utf-8'),
            admin_required_acr=values['OIDC_ADMIN_REQUIRED_ACR'], helpdesk_base_url=values['HELPDESK_IDENTITY_BASE_URL'],
            helpdesk_credential=secret('HELPDESK_IDENTITY_CREDENTIAL_FILE').decode('ascii'),
            encryption_key=secret('OIDC_ENCRYPTION_KEY_FILE'),ca_file=values.get('ENDPOINT_SSO_CA_FILE') or None,
            breakglass_usernames=emergency,breakglass_until=until)
