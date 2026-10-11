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
    require(set(value)=={'schema','status','run_id','vm_uuid','registry_sha256','utc','rows','parent_observations'}
            and value['schema']=='task13_native_process_identity_v1'
            and value['status']=='READ_ONLY_PROCESS_IDENTITY_OBSERVATION'
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
