"""Pinned historical instance references and fail-closed native identity classification."""
from datetime import datetime,timezone
import re
from .codec import canonical,digest,instant,parse_json,require,sha256
from .history import read_file,MANIFEST_SHA,_relative

ABSENCE_NAME='fresh-current-quiescence-001-accepted-observation.json'
ABSENCE_SHA='1f377d2375f805cc8f62bf216c83a455c9fd3559b7e9ceaf8bbd848d1a506758'
NATIVE_NAME='native-inspect-diagnostic-observation.json'
NATIVE_SHA='06a935ded177e049c5bf41fe8a169928735413a266ea09554776dec03b607614'
STATES={'ORIGINAL_PROCESS_ACTIVE','PID_REUSED','PROCESS_ABSENT','IDENTITY_UNKNOWN'}
SAMPLE_KEYS={'status','pid','birth_filetime','image','image_sha256','parent_pid','session_id',
             'handle_count','wait_result','native_error','cim_count','cim_birth_filetime',
             'cim_image_equal','cim_session_equal'}

def filetime(value):
    delta=instant(value)-datetime(1601,1,1,tzinfo=timezone.utc)
    fraction=re.search(r'\.(\d+)',value)
    require(fraction is None or len(fraction[1])<=7,'exact native time precision')
    tail=int(fraction[1][6]) if fraction is not None and len(fraction[1])==7 else 0
    return (delta.days*86400+delta.seconds)*10**7+delta.microseconds*10+tail

def reference_registry(prefix):
    raw=read_file(prefix.root/'source-closure-manifest.json')
    require(sha256(raw)==MANIFEST_SHA,'identity reference source closure')
    manifest=parse_json(raw)
    witness_raw=read_file(prefix.root/'zero-owner-recovery-records'/ABSENCE_NAME)
    require(sha256(witness_raw)==ABSENCE_SHA,'immutable accepted absence witness')
    witness=parse_json(witness_raw)
    value=witness['observation']
    require(value['run_id']==prefix.plan['run_id'] and value['scan_complete'] is True
            and value['scan_error_type'] is None,'accepted absence witness binding')
    slots=value['known']+value['pair']
    require(len(value['known'])==14 and len(value['pair'])==2
            and all(r['present'] is False and r['error_type'] is None for r in slots)
            and len({r['pid'] for r in slots})==16,'exact historical absent slots')
    refs=[{'pid':r['pid'],'absence_filetime':filetime(value['utc']),'original_birth_filetime':None} for r in slots]
    spec=next(v for v in manifest['prerequisites'] if v['relative_path'].endswith(NATIVE_NAME)
              and v['sha256']==NATIVE_SHA)
    native_raw=read_file(prefix.root.parent/_relative(spec['relative_path']))
    require(sha256(native_raw)==NATIVE_SHA,'saved native original identity')
    native=parse_json(native_raw)
    identity=native['diagnostic']['frames'][0]['identity']
    require(identity['pid']==refs[14]['pid'] and identity['parent']==refs[15]['pid']
            and identity['status']=='FULL' and identity['error_class'] is None
            and all(identity[k] is True for k in ('image_matches_powershell','owner_matches_diagnostic_sid',
                'repeat_cim_equal','retained_native_equal','retained_not_exited'))
            and identity['native_birth_utc']==identity['cim_birth_utc'],'saved pair0 native binding')
    refs[14]['original_birth_filetime']=filetime(identity['native_birth_utc'])
    return {'schema':'task13_original_process_references_v1','original':prefix.binding,
            'vm_uuid':prefix.plan['vm_uuid'],'run_id':prefix.plan['run_id'],
            'absence_witness_sha256':ABSENCE_SHA,'native_identity_sha256':NATIVE_SHA,'refs':refs}

def classify_identity(reference,row):
    """Never trust a guest state label. Any incomplete or racing evidence is UNKNOWN."""
    try:
        require(set(reference)=={'pid','absence_filetime','original_birth_filetime'}
                and type(reference['pid']) is int and reference['pid']>0
                and type(reference['absence_filetime']) is int and reference['absence_filetime']>0,
                'reference identity')
        original=reference['original_birth_filetime']
        require(original is None or type(original) is int and original>0,'saved original birth')
        require(set(row)=={'pid','first','second','retained_first_not_exited','error_type'}
                and row['pid']==reference['pid'] and type(row['pid']) is int and row['error_type'] is None,
                'identity row')
        first,second=row['first'],row['second']
        for sample in (first,second):
            require(type(sample) is dict and set(sample)==SAMPLE_KEYS and sample['pid']==reference['pid']
                    and type(sample['pid']) is int,'native sample schema')
        if first['status']==second['status']=='ABSENT':
            for sample in (first,second):
                require(sample['native_error']==87 and type(sample['native_error']) is int
                        and sample['cim_count']==0 and type(sample['cim_count']) is int
                        and all(sample[k] is None for k in SAMPLE_KEYS-{'status','pid','native_error','cim_count'}),
                        'native consistent absence')
            require(row['retained_first_not_exited'] is None,'absent handle')
            return 'PROCESS_ABSENT'
        for sample in (first,second):
            require(sample['status']=='PRESENT' and sample['native_error']==0
                    and sample['cim_count']==1 and sample['wait_result']==258
                    and type(sample['birth_filetime']) is int and sample['birth_filetime']>0
                    # CIM_DATETIME stores microseconds. Native equality below
                    # retains all 100 ns ticks; only the CIM projection truncates.
                    and sample['cim_birth_filetime']==sample['birth_filetime']//10*10
                    and type(sample['cim_birth_filetime']) is int
                    and sample['cim_image_equal'] is True and sample['cim_session_equal'] is True,
                    'native/CIM identity agreement')
            require(type(sample['image']) is str and 1<=len(sample['image'])<=32768
                    and sha256(sample['image'].encode())==sample['image_sha256'],'native image binding')
            require(all(type(sample[k]) is int and 0<=sample[k]<2**32 for k in
                        ('parent_pid','session_id','handle_count','wait_result','native_error','cim_count')),
                    'native numeric identity fields')
        require(row['retained_first_not_exited'] is True
                and all(first[k]==second[k] for k in ('pid','birth_filetime','image','image_sha256','parent_pid','session_id')),
                'retained identity changed or exited')
        if original is not None and first['birth_filetime']==original:return 'ORIGINAL_PROCESS_ACTIVE'
        if first['birth_filetime']>reference['absence_filetime']:return 'PID_REUSED'
    except (ValueError,KeyError,TypeError,AttributeError):
        pass
    return 'IDENTITY_UNKNOWN'

def identity_states(prefix,value):
    registry=reference_registry(prefix)
    keys={'schema','status','run_id','vm_uuid','registry_sha256','utc','rows','parent_observations'}
    if value.get('schema')=='task13_native_process_identity_v2':
        require(set(value)==keys|{'diagnostics','caller_context'},'complete identity diagnostics')
        validate_diagnostics(value)
    else:require(set(value)==keys and value.get('schema')=='task13_native_process_identity_v1','identity schema')
    require(value['status']=='READ_ONLY_PROCESS_IDENTITY_OBSERVATION'
            and value['run_id']==registry['run_id'] and value['vm_uuid']==registry['vm_uuid']
            and value['registry_sha256']==digest(registry) and type(value['rows']) is list
            and len(value['rows'])==16,'original instance registry and observation binding')
    parents=value['parent_observations']
    require(type(parents) is list and len(parents)<=16,'bounded parent metadata')
    for parent in parents:
        require(type(parent) is dict and set(parent)=={'pid','status','image','birth_filetime','session_id','error_type'}
                and type(parent['pid']) is int and 0<=parent['pid']<2**32
                and parent['status'] in ('UNKNOWN','ABSENT','CIM_METADATA')
                and (parent['error_type'] is None or type(parent['error_type']) is str and len(parent['error_type'])<=128),
                'read-only parent metadata schema')
    return {ref['pid']:classify_identity(ref,row) for ref,row in zip(registry['refs'],value['rows'])}

def validate_diagnostics(value):
    """Bound metadata independently; no field participates in instance admission."""
    rows=value['diagnostics'];context=value['caller_context']
    require(type(rows) is list and len(rows)==len(value['rows'])==16
            and len(canonical(rows))<=32768 and len(canonical(context))<=8192,'bounded identity diagnostics')
    require(type(context) is dict and set(context)=={'pid','user_sid','authentication_type','impersonation_level',
            'is_admin','ps_version','clr_version','is_64bit','requested_process_access','privileges'}
            and type(context['pid']) is int and 0<context['pid']<2**32
            and context['requested_process_access']==0x101000
            and type(context['is_admin']) is bool and type(context['is_64bit']) is bool
            and type(context['privileges']) is list and len(context['privileges'])<=128
            and all(type(v) is str and len(v)<=512 for v in context['privileges'])
            and all(type(context[k]) is str and len(context[k])<=256 for k in
                ('user_sid','authentication_type','impersonation_level','ps_version','clr_version')),'bounded caller context')
    for row,identity in zip(rows,value['rows']):
        require(type(row) is dict and set(row)=={'pid','failure','elapsed_ms'} and row['pid']==identity['pid']
                and type(row['elapsed_ms']) is int and 0<=row['elapsed_ms']<=30000,'diagnostic row binding')
        failure=row['failure']
        if failure is None:continue
        require(type(failure) is dict and set(failure)=={'sample','stage','native_error','elapsed_ms','partial',
                'first_wait','second_wait','error_record'} and failure['sample'] in ('first','second')
                and type(failure['stage']) is str and len(failure['stage'])<=128
                and type(failure['elapsed_ms']) is int and 0<=failure['elapsed_ms']<=30000
                and (failure['native_error'] is None or type(failure['native_error']) is int and 0<=failure['native_error']<2**32)
                and (failure['partial'] is None or type(failure['partial']) is dict and set(failure['partial'])==SAMPLE_KEYS)
                and all(failure[k] is None or type(failure[k]) is int and 0<=failure[k]<2**32
                    for k in ('first_wait','second_wait')),'bounded failure metadata')
        error=failure['error_record']
        require(type(error) is dict and set(error)=={'error_record_type','fully_qualified_error_id',
                'fully_qualified_error_id_sha256','message_id','category','reason','line','exceptions'}
                and type(error['exceptions']) is list and 1<=len(error['exceptions'])<=4
                and type(error['line']) is int and error['line']>=0
                and all(error[k] is None or type(error[k]) is str and len(error[k])<=256 for k in
                    ('error_record_type','fully_qualified_error_id','fully_qualified_error_id_sha256','message_id','category','reason')),
                'bounded ErrorRecord')
        for exception in error['exceptions']:
            require(type(exception) is dict and set(exception)=={'type','hresult','native_error_code'}
                    and type(exception['type']) is str and len(exception['type'])<=256
                    and type(exception['hresult']) is int and -2**31<=exception['hresult']<2**31
                    and (exception['native_error_code'] is None or type(exception['native_error_code']) is int
                        and -2**31<=exception['native_error_code']<2**32),'bounded exception chain')
