"""WorkTime browser contract, separate from service, admin and DLP APIs."""


def json_response(description, schema):
    return {'description': description, 'content': {'application/json': {'schema': schema}}}


def worktime_openapi():
    errors = {str(code): {'description': text} for code, text in [
        (400, 'Invalid flow'), (401, 'Invalid authority'), (403, 'Permission or CSRF denied'), (404, 'Handoff disabled'),
        (429, 'Rate limited'), (503, 'Authority unavailable')]}
    nullable_uuid = {'type': ['string', 'null'], 'format': 'uuid'}
    grant = {'type': 'object', 'required': ['role', 'department_id'],
             'properties': {'role': {'type': 'string'}, 'department_id': nullable_uuid}}
    properties = {
        'person_id': {'type': 'string', 'format': 'uuid'}, 'department_id': nullable_uuid,
        'csrf_token': {'type': 'string'}, 'grants': {'type': 'array', 'items': grant},
        'privileged_assurance': {'type': 'boolean'}, 'auth_source': {'enum': ['helpdesk', 'oidc']}}
    session = {'type': 'object', 'required': list(properties), 'properties': properties}
    opaque = {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{43}$'}
    form = {'type': 'object', 'additionalProperties': False, 'required': ['code', 'state'],
            'properties': {'code': opaque, 'state': opaque}}
    security = [{'WorktimeCookie': []}, {'EmployeeCookie': []}]
    paths = {
        '/auth/worktime/helpdesk/login': {'get': {
            'description': 'Five-minute state/browser/PKCE flow; fixed Helpdesk origin. No person or return URL parameters.',
            'responses': {'303': {'description': 'Fixed Helpdesk authorization redirect'}, **errors}}},
        '/auth/worktime/helpdesk/callback': {'post': {
            'description': 'Exact Helpdesk Origin and flow cookie required. Bounded form POST; codes never enter URLs.',
            'requestBody': {'required': True, 'content': {'application/x-www-form-urlencoded': {'schema': form}}},
            'responses': {'303': {'description': 'Own cabinet or fixed login error'}, **errors}}},
        '/api/employee/worktime/login-options': {'get': {'responses': {'200': json_response(
            'No-store feature discovery', {'type': 'object', 'required': ['helpdesk_login_enabled'],
            'properties': {'helpdesk_login_enabled': {'type': 'boolean'}}})}}},
        '/api/employee/worktime/session': {
            'get': {'security': security,
                'description': 'Present WorkTime cookie takes priority, is introspected live and never falls back when invalid. Helpdesk grants empty and assurance false.',
                'responses': {'200': json_response('No-store selected session', session), **errors}},
            'delete': {'security': security,
                'description': 'Revoke only selected local session with its own CSRF; Helpdesk/provider sessions remain separate.',
                'parameters': [{'in': 'header', 'name': 'X-CSRF-Token', 'required': True, 'schema': {'type': 'string'}}],
                'responses': {'204': {'description': 'Selected session revoked'}, **errors}}}}
    schemes = {key: {'type': 'apiKey', 'in': 'cookie', 'name': name} for key, name in [
        ('WorktimeCookie', 'endpoint_worktime_session'), ('EmployeeCookie', 'endpoint_employee_session')]}
    return {'openapi': '3.1.0', 'info': {'title': 'Endpoint WorkTime browser authentication', 'version': 'v1'},
            'paths': paths, 'components': {'securitySchemes': schemes}}
