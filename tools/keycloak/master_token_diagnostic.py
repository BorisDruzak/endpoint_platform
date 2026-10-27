"""Inert-by-default, one-login private master-token diagnostic; never recovery.

Native execution requires explicit --run-once --candidate, reviewed root-private
source/authorization seals and an unused v10 runtime. No prepare/restore, browser,
LDAP/identity API, retention/scope change, purge or promotion operation exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import stat
import sys
import time
import types

EXECUTOR_ROOT = Path('/root/keycloak-identity-recovery-20261027-executor-v10')
BACKEND_SHA256 = '5b46db376f6d83af5c94deed439459be055885fd034bcfadee307f8f4ade44f3'
HELPER_SHA256 = '7df5688f2c4de83cec4047c1788e56a8ccf1b84bd7297102545bea7bfa0a1cd8'
ORIGINAL_ROOT = Path('/var/backups/keycloak-recovery/keycloak_recovery_20261027_55f72537')
BOOTSTRAP_ENV = Path('/run/keycloak-provision-20261027/provision.env')
PREPARE_ROOT = Path('/root/keycloak-fresh-prepare-after-master-probe1-v1')
FORENSIC_DATABASES = {'keycloak_recovery_20261027_55f72537':20856,
                      'keycloak_recovery_20261027_2190f3d5':22159,
                      'keycloak_recovery_20261027_82e14168':23462}
TOKEN_SHAPE_FIELDS = frozenset({'bounded_compact_token','claims_object','iat_positive_integer',
    'exp_after_iat','expected_master_issuer','expected_admin_cli','canonical_sid',
    'remaining_lifetime_at_least_45_seconds','signature_verified'})
CLEANUP_FIELDS = frozenset({'cleanup_required','owned_candidate_stopped','canonical_reference_unchanged',
    'private_sockets_absent','candidate_database_connections_absent','after_forensic_snapshot_captured',
    'historical_forensics_unchanged','preserved_source_files_unchanged'})
INVENTORY_FIELDS = frozenset({'fresh_session_verified','flags_verified','realms_verified',
    'strict_cutoff_order_verified','revocation_not_lowered','offline_inventory_bounded'})
PROBE_CODES = frozenset({'ProbeArgumentsInvalid','ProbeExplicitCandidateRequired','ProbeUnexpectedFailure',
    'ProbeSourceSealInvalid','ProbeSourcePinMismatch','ProbeExecutorPathInvalid','ProbeNativeHostRequired',
    'ProbeAuthorizationInvalid','ProbePreservationInvalid','ProbeCandidateNotPristine','ProbeV10ProfileRequired',
    'ProbeBootstrapMissing','ProbeBootstrapMalformed','ProbeBootstrapDuplicate','ProbeInputBoundExceeded',
    'ProbePrivateFileInvalid','ProbePrivateFileUnavailable','ProbeLoginAlreadyConsumed','ProbeLoginScopeInvalid',
    'ProbeAttemptAlreadyConsumed',
    'ProbeRealmGetAlreadyConsumed','ProbeRealmGetScopeInvalid','ProbeInventoryAlreadyConsumed',
    'ProbeShapeInvalid','ProbeInventoryShapeInvalid','ProbeCleanupShapeInvalid','ProbeInterrupted','ProbeLockUnavailable',
    'ProbeJournalUnavailable','ProbeCleanupUnconfirmed','ProbeMasterLoginResponseInvalid'})


class ProbeRefused(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ProbeRefused(code)


def _unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'ProbeAuthorizationInvalid')
    return result


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_unique)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProbeRefused('ProbeAuthorizationInvalid') from None


def _physical(path):
    require(path.is_absolute(), 'ProbePrivateFileInvalid')
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022,
                'ProbePrivateFileInvalid')


def _read_private(path, maximum):
    """Read one verified fd, never follow a link or trust a pathname reread."""
    try:
        _physical(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                    stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum,
                    'ProbePrivateFileInvalid')
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            require(len(data) <= maximum and
                    (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) ==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'ProbeInputBoundExceeded')
            return data
    except OSError:
        raise ProbeRefused('ProbePrivateFileUnavailable') from None


def select_bootstrap(lines):
    """Select only one field; never decode or retain unrelated secret values."""
    result = None
    total = 0
    for line in lines:
        require(type(line) is bytes, 'ProbeBootstrapMalformed')
        total += len(line)
        require(total <= 65536 and len(line) <= 4096, 'ProbeInputBoundExceeded')
        if not line.startswith(b'SSO_BOOTSTRAP_PASSWORD='):
            continue
        require(result is None, 'ProbeBootstrapDuplicate')
        value = line[len(b'SSO_BOOTSTRAP_PASSWORD='):].rstrip(b'\r\n')
        require(1 <= len(value) <= 512 and all(33 <= char <= 126 for char in value),
                'ProbeBootstrapMalformed')
        result = value.decode('ascii')
    require(result is not None, 'ProbeBootstrapMissing')
    return result


def _bootstrap_only():
    # Root-only checked fd; no read_private_environment() dict or LDAP/client
    # values are loaded. Unrelated lines are discarded as bounded raw bytes.
    try:
        _physical(BOOTSTRAP_ENV)
        fd = os.open(BOOTSTRAP_ENV, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, 'ProbePrivateFileInvalid')
            value = select_bootstrap(stream)
            after = os.fstat(stream.fileno())
            require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns) ==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'ProbePrivateFileInvalid')
            return value
    except OSError:
        raise ProbeRefused('ProbePrivateFileUnavailable') from None


def _load_reviewed():
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ProbeNativeHostRequired')
    require(Path(__file__) == EXECUTOR_ROOT / 'master_token_diagnostic.py', 'ProbeExecutorPathInvalid')
    _physical(EXECUTOR_ROOT)
    require(stat.S_IMODE(EXECUTOR_ROOT.lstat().st_mode) == 0o700, 'ProbeExecutorPathInvalid')
    seal = _json(_read_private(EXECUTOR_ROOT / 'master-token-source-closure.json', 4096))
    require(type(seal) is dict and set(seal) == {'schema','probe_sha256','backend_sha256','helper_sha256'} and
            seal['schema'] == 'keycloak_master_token_source_closure_v1' and
            seal['backend_sha256'] == BACKEND_SHA256 and seal['helper_sha256'] == HELPER_SHA256 and
            type(seal['probe_sha256']) is str and re.fullmatch('[0-9a-f]{64}',seal['probe_sha256']),
            'ProbeSourceSealInvalid')
    modules = {}
    for key, name, expected in [('probe','master_token_diagnostic.py',seal['probe_sha256']),
                               ('backend','recover_pilot_identity.py',BACKEND_SHA256),
                               ('pilot','pilot_acceptance.py',HELPER_SHA256)]:
        path = EXECUTOR_ROOT / name
        data = _read_private(path,1024*1024)
        require(hashlib.sha256(data).hexdigest() == expected,'ProbeSourcePinMismatch')
        if key != 'probe':
            module = types.ModuleType('reviewed_master_diagnostic_'+key)
            module.__file__ = str(path)
            exec(compile(data,str(path),'exec'),module.__dict__)
            modules[key] = module
    backend,pilot = modules['backend'],modules['pilot']
    require(backend.EXECUTOR_ROOT == EXECUTOR_ROOT and backend.PILOT_HELPER_SHA256 == HELPER_SHA256,
            'ProbeSourcePinMismatch')
    backend._run_private(['true'],maximum_output=0)
    pilot.BASE = 'http://127.0.0.1:8089'
    return backend,pilot,seal


def single_login_client(backend,pilot,runtime):
    class OneMasterLogin(pilot.LocalAdminClient):
        def __init__(self):
            super().__init__(request_budget=1)
            self.consumed = False

        def request(self,method,path,*,payload=None,form=None,authenticated=True):
            require(not self.consumed,'ProbeLoginAlreadyConsumed')
            require(method == 'POST' and path == '/realms/master/protocol/openid-connect/token' and
                    payload is None and authenticated is False and type(form) is dict and
                    set(form) == {'grant_type','client_id','username','password'} and
                    form['grant_type'] == 'password' and form['client_id'] == 'admin-cli' and
                    form['username'] == 'sso-bootstrap' and type(form['password']) is str and
                    pilot.BASE == 'http://127.0.0.1:8089','ProbeLoginScopeInvalid')
            self.consumed = True  # Consume before proof/network; never replay.
            runtime.proof()
            return super().request(method,path,payload=payload,form=form,authenticated=authenticated)
    return OneMasterLogin()


def reduce_inventory(backend,value,client):
    """The existing purge preconditions, with no mutation and no value export."""
    backend.require(type(value) is dict and value.get('fresh_master_session_count') == 1 and
                    value.get('unexpected_offline_flags') == 0,'FreshMasterSessionOrFlagNotVerified')
    backend.require(value.get('realms') == ['master','sosnadmin'],'UnexpectedRestoredRealms')
    cutoff,old = client.admin_iat,value.get('maximum_restored_token_iat')
    backend.require(type(cutoff) is int and type(old) is int and 0 <= old < cutoff,
                    'FreshAdminMustPostdateRestoredTokens')
    before = value.get('realm_not_before')
    backend.require(type(before) is dict and set(before) == {'master','sosnadmin'} and
                    all(type(x) is int and 0 <= x <= cutoff for x in before.values()),
                    'ExistingRealmRevocationWouldBeLowered')
    sessions = value.get('offline_sessions')
    backend.require(type(sessions) is list and len(sessions) <= 100,'OfflineSessionBoundExceeded')
    seen = set()
    for item in sessions:
        backend.require(type(item) is dict and set(item) == {'realm','id'} and
                        item['realm'] in {'master','sosnadmin'} and type(item['id']) is str,
                        'OfflineSessionIdentityInvalid')
        canonical = item['id']
        backend.require(backend.is_canonical_session_id(canonical) and (item['realm'],canonical) not in seen,
                        'OfflineSessionIdentityInvalid')
        seen.add((item['realm'],canonical))
    return dict.fromkeys(INVENTORY_FIELDS,True)


def execute_probe(operations):
    """One fixed sequence. Every exit attempts cleanup before any result receipt."""
    phase,token,session,primary = 'Preflight','',None,None
    shape,inventory = {},{}
    cleanup = dict.fromkeys(CLEANUP_FIELDS,False)
    cleanup_code = None
    try:
        operations.preflight()
        phase = 'RuntimeStart'; operations.start()
        phase = 'MasterLogin'; token = operations.login_once()
        phase = 'TokenShape'; proposed_shape = operations.shape(token)
        require(type(proposed_shape) is dict and set(proposed_shape) == TOKEN_SHAPE_FIELDS and
                all(type(x) is bool for x in proposed_shape.values()),'ProbeShapeInvalid')
        shape = proposed_shape
        phase = 'TokenConstructor'; session = operations.construct_client(token)
        phase = 'TokenLifetime'; operations.lifetime(session)
        phase = 'RealmGet'; operations.realms_once(session)
        phase = 'SessionInventory'; proposed_inventory = operations.inventory_once(session)
        require(type(proposed_inventory) is dict and set(proposed_inventory) == INVENTORY_FIELDS and
                all(type(x) is bool and x for x in proposed_inventory.values()),'ProbeInventoryShapeInvalid')
        inventory = proposed_inventory
    except BaseException as error:
        primary = operations.safe_code(error)
        if primary in {'PrivateBuildCleanupHold','PrivateRuntimeCleanupHold'}:
            cleanup_code = primary  # A later stop cannot erase prior group uncertainty.
    finally:
        token = ''
        try:
            if session is not None:
                session.token,session.session_id = '',''
            operations.clear_sensitive()
        except BaseException as error:
            cleanup_code = operations.safe_code(error)
        try:
            proposed_cleanup = operations.cleanup()
            require(type(proposed_cleanup) is dict and set(proposed_cleanup) == CLEANUP_FIELDS and
                    all(type(x) is bool for x in proposed_cleanup.values()),'ProbeCleanupShapeInvalid')
            cleanup = proposed_cleanup
            if cleanup['cleanup_required'] and not all(cleanup.values()):
                cleanup_code = cleanup_code or 'ProbeCleanupUnconfirmed'
        except BaseException as error:
            cleanup_code = operations.safe_code(error)
    result = {'schema':'keycloak_master_token_diagnostic_v1',
        'status':'CleanupUnconfirmedHold' if cleanup_code else
                 'MasterTokenDiagnosticFailedHold' if primary else 'MasterTokenDiagnosticCompleteHold',
        'phase':phase,'refusal_code':primary,'cleanup_code':cleanup_code,'token_shape':shape,
        'inventory_checks':inventory,'cleanup':cleanup,'semantic_reviewed':False,'switch_ready':False,
        'purge_performed':False,'browser_used':False,'identity_api_used':False,'ad_changed':False,
        'receipt_failure':False}
    try:
        operations.record(result)
    except BaseException:
        result['receipt_failure'] = True
        if cleanup_code is None:
            result['status'] = 'ProbeReceiptFailedHold'
    return result


class NativeProbe:
    def __init__(self,candidate,backend,pilot,source_seal=None):
        self.candidate,self.backend,self.pilot = candidate,backend,pilot
        self.runtime,self.receipts,self.login_client = None,None,None
        self.login_used,self.get_used,self.inventory_used = False,False,False
        self.failed_baselines = {}
        self.preserved_files = {}
        if source_seal is not None:
            self.preserved_files.update({EXECUTOR_ROOT/'master_token_diagnostic.py':source_seal['probe_sha256'],
                EXECUTOR_ROOT/'recover_pilot_identity.py':BACKEND_SHA256,
                EXECUTOR_ROOT/'pilot_acceptance.py':HELPER_SHA256})
        self.source_seal = source_seal

    def safe_code(self,error):
        if type(error) is ProbeRefused and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in PROBE_CODES:
            return error.args[0]
        if type(error) in {self.backend.RecoveryRefused,self.backend.RecoveryCleanupFailure}:
            code = self.backend._safe_error_metadata(error)['refusal_code']
            if code in self.backend.SAFE_REFUSAL_CODES:
                return code
        if type(error) is self.pilot.AcceptanceError and len(error.args) == 1 and type(error.args[0]) is str:
            if re.fullmatch('LocalAdminHTTP[1-5][0-9]{2}',error.args[0]):
                return error.args[0].replace('LocalAdminHTTP','CandidateHTTP')
            if error.args[0] == 'AdminAuthenticationFailed':
                return 'ProbeMasterLoginResponseInvalid'
        return 'ProbeUnexpectedFailure'

    def _validate_authorization(self,authorization):
        names = {'original_snapshot','original_context','original_identity','prepare_preservation_before',
                 'prepare_preservation_after','sealed_run7_source'}
        require(type(authorization) is dict and set(authorization) ==
                {'schema','candidate_database','candidate_oid','preserved_artifacts'} and
                authorization['schema'] == 'keycloak_master_token_probe_authorization_v1' and
                authorization['candidate_database'] == self.candidate and
                type(authorization['candidate_oid']) is int and authorization['candidate_oid'] > 0 and
                authorization['candidate_oid'] not in {16385,19553,20856,22159,23462} and
                type(authorization['preserved_artifacts']) is dict and
                set(authorization['preserved_artifacts']) == names,'ProbeAuthorizationInvalid')

    def _consume_once(self):
        # Fixed root-private O_EXCL fence, under the shared recovery lock, before
        # any runtime constructor, journal, copy/build/start or login. A failed
        # prestart attempt consumes this invocation even if v10 was never created.
        path = EXECUTOR_ROOT/'master-token-probe-consumed.json'
        require(not path.exists() and not path.is_symlink(),'ProbeAttemptAlreadyConsumed')
        self.backend._write_private(path,{'schema':'keycloak_master_token_probe_consumed_v1',
            'attempt_consumed':True,'switch_ready':False})

    def _preservation(self,authorization):
        b = self.backend
        self._validate_authorization(authorization)
        artifacts = {}
        for name,item in authorization['preserved_artifacts'].items():
            require(type(item) is dict and set(item) == {'path','sha256'} and
                    type(item['path']) is str and b.is_hash(item['sha256']),'ProbePreservationInvalid')
            declared = PurePosixPath(item['path'])
            path = Path(item['path'])
            require(declared.is_absolute() and '..' not in declared.parts and '\\' not in item['path'] and
                    (declared.is_relative_to(PurePosixPath('/var/backups/keycloak-recovery')) or
                     declared.is_relative_to(PurePosixPath('/root/keycloak-identity-recovery-20261027-executor-v8')) or
                     declared.is_relative_to(PurePosixPath(PREPARE_ROOT.as_posix()))),
                    'ProbePreservationInvalid')
            data = _read_private(path,16*1024*1024)
            require(hashlib.sha256(data).hexdigest() == item['sha256'],'ProbePreservationInvalid')
            self.preserved_files[path] = item['sha256']
            if name == 'original_snapshot':
                artifacts[name] = _json(data)
                b._validate_snapshot(artifacts[name])
                require(artifacts[name]['database_oid'] == 20856,'ProbePreservationInvalid')
            if name in {'original_snapshot','original_context','original_identity'}:
                expected_file = {'original_snapshot':'candidate-restored.json',
                    'original_context':'context.json','original_identity':'identity-before.json'}[name]
                require(path == ORIGINAL_ROOT / expected_file,'ProbePreservationInvalid')
            if name == 'original_context':
                context = _json(data)
                require(context.get('candidate_oid') == 20856 and
                        context.get('backup_dump_sha256') == b.DUMP_SHA256,'ProbePreservationInvalid')
            if name.startswith('prepare_preservation_'):
                which = name.removeprefix('prepare_preservation_')
                require(path == PREPARE_ROOT/'attempt'/('preservation-'+which+'.json'),
                        'ProbePreservationInvalid')
                row = _json(data)
                expected_keys = {'schema','not_original_restore_baseline','capture'} | (
                    {'actual_generated_candidate_name'} if which == 'before' else set())
                require(type(row) is dict and set(row) == expected_keys and
                    row['schema'] == 'failed_candidate_forensic_preservation_v1' and
                    row['not_original_restore_baseline'] is True and type(row['capture']) is dict and
                    (which != 'before' or row['actual_generated_candidate_name'] == self.candidate),
                    'ProbePreservationInvalid')
                failed = row['capture'].get('failed_databases')
                require(type(failed) is dict and set(failed) == set(FORENSIC_DATABASES),
                        'ProbePreservationInvalid')
                for database,oid in FORENSIC_DATABASES.items():
                    entry = failed[database]
                    require(type(entry) is dict and set(entry) == {'snapshot','identity'} and
                        type(entry['identity']) is dict and entry['identity'].get('candidate_oid') == oid,
                        'ProbePreservationInvalid')
                    b._validate_snapshot(entry['snapshot'])
                    require(entry['snapshot']['database_oid'] == oid and entry['snapshot'].get('database') == database,
                            'ProbePreservationInvalid')
                artifacts[name] = failed
        require(artifacts['prepare_preservation_before'] == artifacts['prepare_preservation_after'],
                'ProbePreservationInvalid')
        self.failed_baselines = {name:row['snapshot'] for name,row in artifacts['prepare_preservation_after'].items()}
        for snapshot in self.failed_baselines.values():
            require(b.compare_snapshots(artifacts['original_snapshot'],snapshot) != [],'ProbePreservationInvalid')
        return artifacts['original_snapshot']

    def _capture_failed(self):
        return {name:self.backend.collect_inventory(name) for name in FORENSIC_DATABASES}

    def _verify_failed(self,actual):
        require(type(actual) is dict and set(actual) == set(FORENSIC_DATABASES) and
                set(self.failed_baselines) == set(FORENSIC_DATABASES),'ProbePreservationInvalid')
        for name,oid in FORENSIC_DATABASES.items():
            require(actual[name].get('database') == name and actual[name].get('database_oid') == oid and
                    self.backend.compare_snapshots(self.failed_baselines[name],actual[name]) == [],
                    'ProbePreservationInvalid')

    def _verify_preserved_files(self):
        require(bool(self.preserved_files),'ProbePreservationInvalid')
        for path,expected in self.preserved_files.items():
            require(hashlib.sha256(_read_private(path,16*1024*1024)).hexdigest() == expected,
                    'ProbePreservationInvalid')
        return True

    def preflight(self):
        b = self.backend
        b._names(self.candidate)
        require(b.runtime_recipe(self.candidate,browser_tls=True)['directory'] ==
                '/var/lib/keycloak-recovery-v10/'+self.candidate,'ProbeV10ProfileRequired')
        authorization_path = EXECUTOR_ROOT/'master-token-probe-authorization.json'
        authorization_data = _read_private(authorization_path,16384)
        authorization = _json(authorization_data)
        self.preserved_files[authorization_path] = hashlib.sha256(authorization_data).hexdigest()
        closure_path = EXECUTOR_ROOT/'master-token-source-closure.json'
        closure_data = _read_private(closure_path,4096)
        require(_json(closure_data) == self.source_seal,'ProbeSourceSealInvalid')
        self.preserved_files[closure_path] = hashlib.sha256(closure_data).hexdigest()
        self._validate_authorization(authorization)
        self._consume_once()
        original = self._preservation(authorization)
        # UNCHANGED constructor/pristine guards include original UUID/OTP SQL
        # comparison. These are not IdP/LDAP/user API lookups.
        self.runtime = b.PrivateCandidateRuntime(self.candidate)
        require(self.runtime.candidate_oid == authorization['candidate_oid'],'ProbeAuthorizationInvalid')
        self.runtime.verify_pristine_attempt()
        require(b.compare_snapshots(original,self.runtime.baseline) == [],'ProbeCandidateNotPristine')
        nonce = secrets.token_hex(8)
        require(re.fullmatch('[0-9a-f]{16}',nonce),'ProbeJournalUnavailable')
        self.receipts = b._create_owned_directory(self.runtime.evidence_root.parent /
            (self.candidate+'-master-token-probe-'+nonce),group=0,mode=0o700)
        self.runtime.receipts = self.receipts
        before = b.collect_inventory(self.candidate)
        require(before['database_oid'] == self.runtime.candidate_oid and
                b.compare_snapshots(self.runtime.baseline,before) == [],'ProbeCandidateNotPristine')
        b._write_private(self.receipts/'probe-before-full101.json',before)
        historical = self._capture_failed()
        b._write_private(self.receipts/'probe-historical-before-full101.json',historical)
        self._verify_failed(historical)
        b._write_private(self.receipts/'probe-begin.json',{'source_closure_verified':True,
            'fresh_prepared_candidate_verified':True,'old_forensics_preserved':True,'switch_ready':False})

    def start(self):
        self.runtime.copy_and_configure()
        self.runtime.start()

    def login_once(self):
        require(not self.login_used,'ProbeLoginAlreadyConsumed')
        self.login_used = True
        password = _bootstrap_only()
        try:
            self.login_client = single_login_client(self.backend,self.pilot,self.runtime)
            self.login_client.login(password)
            token = self.login_client.token
            self.login_client.token = ''
            return token
        finally:
            password = ''

    def shape(self,token):
        result = self.backend.candidate_token_shape_metadata(token,now=int(time.time()))
        require(type(result) is dict and set(result) == TOKEN_SHAPE_FIELDS and
                all(type(x) is bool for x in result.values()),'ProbeShapeInvalid')
        self.backend._write_private(self.receipts/'probe-token-shape.json',result)
        return result

    def construct_client(self,token):
        client = self.backend.CandidateSessionClient(token,runtime_verifier=self.runtime.proof)
        require(client.not_before_payloads == {} and client.session_delete_paths == set() and
                client.logout_paths == set(),'ProbeRealmGetScopeInvalid')
        send = client._send
        consumed = False
        def one_get(request):
            nonlocal consumed
            require(not consumed,'ProbeRealmGetAlreadyConsumed')
            require(request.get_method() == 'GET' and
                    request.full_url == 'http://127.0.0.1:8089/admin/realms' and request.data is None,
                    'ProbeRealmGetScopeInvalid')
            consumed = True
            return send(request)
        client.transport = one_get
        return client

    def lifetime(self,client,*,now=None):
        now = int(time.time()) if now is None else now
        self.backend.require(type(client.expires_at) is int and type(now) is int and
            client.expires_at-now >= 45,'FreshMasterTokenLifetimeTooShort')

    def realms_once(self,client):
        require(not self.get_used,'ProbeRealmGetAlreadyConsumed')
        self.get_used = True
        value = client.request('GET','/admin/realms')
        self.backend.require(type(value) is list and len(value) == 2 and
            all(type(item) is dict and type(item.get('realm')) is str for item in value) and
            sorted(item['realm'] for item in value) == ['master','sosnadmin'],'FreshMasterTokenNotVerified')

    def inventory_once(self,client):
        require(not self.inventory_used,'ProbeInventoryAlreadyConsumed')
        self.inventory_used = True
        self.runtime.proof()
        value = self.backend.collect_session_inventory(self.candidate,client.session_id)
        return reduce_inventory(self.backend,value,client)

    def clear_sensitive(self):
        if self.login_client is not None:
            self.login_client.token = ''

    def cleanup(self):
        result = dict.fromkeys(CLEANUP_FIELDS,False)
        if self.runtime is None:
            return result
        result['cleanup_required'] = True
        b,r = self.backend,self.runtime
        # Independent checks continue even after stop/one proof fails. Never
        # signal a PID not owned by the reused runtime's process-group guards.
        checks = [
            ('owned_candidate_stopped',lambda: r.stop().get('owned_candidate_stopped') is True and
                not b._private_candidate_processes(self.candidate)),
            ('canonical_reference_unchanged',lambda: r.verify_canonical_reference() is None),
            ('private_sockets_absent',lambda: all(not b._run_private(
                ['ss','-Hltn','sport','=',':'+str(port)],maximum_output=65536).strip()
                for port in (8089,8449,9009))),
            ('candidate_database_connections_absent',lambda: _json(b._run_private(b._psql_argv('postgres'),
                input_bytes=("BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; "
                    "SELECT to_json((SELECT oid::bigint FROM pg_database WHERE datname='"+self.candidate+
                    "')="+str(r.candidate_oid)+" AND NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname='"+
                    self.candidate+"')); COMMIT;").encode(),maximum_output=1024)) is True),
        ]
        for name,check in checks:
            try:
                result[name] = check() is True
            except BaseException:
                result[name] = False
        try:
            historical = self._capture_failed()
            b._write_private(self.receipts/'probe-historical-after-full101.json',historical)
            self._verify_failed(historical)
            result['historical_forensics_unchanged'] = True
        except BaseException:
            pass
        try:
            result['preserved_source_files_unchanged'] = self._verify_preserved_files()
        except BaseException:
            pass
        try:
            after = b.collect_inventory(self.candidate)
            b.require(after['database_oid'] == r.candidate_oid,'CandidateOidChanged')
            b._write_private(self.receipts/'probe-after-full101.json',after)
            result['after_forensic_snapshot_captured'] = True
        except BaseException:
            pass
        return result

    def record(self,result):
        if self.receipts is not None:
            self.backend._write_private(self.receipts/'master-token-probe-result.json',result)


def run_native(candidate):
    """Explicit native entry; no restore, mutation retry, purge or promotion."""
    backend,pilot,seal = _load_reviewed()
    backend._names(candidate)
    import fcntl
    handlers,fd = {},None
    previous_umask = os.umask(0o077)
    def interrupted(signum,frame):
        for number in handlers:
            signal.signal(number,signal.SIG_IGN)
        raise ProbeRefused('ProbeInterrupted')
    try:
        path = Path('/run/keycloak-identity-recovery.lock')
        _physical(path.parent)
        fd = os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600,'ProbeLockUnavailable')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for name in ('SIGTERM','SIGHUP','SIGINT'):
            number = getattr(signal,name)
            handlers[number] = signal.signal(number,interrupted)
        return execute_probe(NativeProbe(candidate,backend,pilot,source_seal=seal))
    finally:
        for number,handler in handlers.items():
            signal.signal(number,handler)
        if fd is not None:
            os.close(fd)
        os.umask(previous_umask)


class _Parser(argparse.ArgumentParser):
    def error(self,message):
        raise ProbeRefused('ProbeArgumentsInvalid')


def main(argv=None):
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument('--run-once',action='store_true')
        parser.add_argument('--candidate')
        args = parser.parse_args(argv)
        if not args.run_once:
            require(args.candidate is None,'ProbeArgumentsInvalid')
            print(json.dumps({'status':'PlanOnly','native_actions_performed':False,'switch_ready':False}))
            return 0
        require(type(args.candidate) is str and bool(args.candidate),'ProbeExplicitCandidateRequired')
        result = run_native(args.candidate)
        print(json.dumps(result,sort_keys=True))
        return 0 if result['status'] == 'MasterTokenDiagnosticCompleteHold' else 2
    except BaseException as error:
        if type(error) is SystemExit and error.code == 0:
            return 0
        code = (error.args[0] if type(error) is ProbeRefused and len(error.args) == 1 and
                type(error.args[0]) is str and error.args[0] in PROBE_CODES else 'ProbeUnexpectedFailure')
        print(json.dumps({'status':'MasterTokenDiagnosticFailedHold','refusal_code':code,'switch_ready':False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
