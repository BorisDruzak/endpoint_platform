"""Explicit synthetic complete comparator journal; never operational evidence."""
from tools.canary.task13_continuation.codec import canonical

FACTS = 'PAYLOAD DEVICE_NETWORK SELECTORS PRIVATE_STATE UPDATE_HISTORY MSI_PRODUCT_CACHE MSI_COMPONENTS_FEATURES MSI_TABLES MSI_COMPONENT_STATES ANCESTOR_ACLS SERVICES_ANCESTRY TRUST_SCM SETUP_TRUST CLOCK_CAPACITY INSTALL_TREE STAGING_TREE CACHE_FINAL HELPER_INPUTS NATIVE_QUERIES MAPPING'.split()
NATIVE = 'NewObject ProductState ProductInfo Features FeatureState ComponentPath MsiQueryComponentStateW MsiGetComponentPathW scexe GetAuthenticodeSignature GetCimInstance GetAccessRules GetOwner'.split()

def complete_rows():
    rows=[]
    def mark(p,s,c=None): rows.append((p,s,c))
    mark('ENTER','WRAPPER');mark('RETURN','WATCHDOG_ARMED')
    mark('ENTER','STDIN.READ',dict(requested=3,position=0,call=0))
    mark('RETURN','STDIN.READ',dict(requested=3,returned=3,position=3,call=0))
    mark('ENTER','PAYLOAD.GZIP_READ');mark('RETURN','PAYLOAD.GZIP_READ')
    mark('ENTER','SCRIPTBLOCK.INVOKE')
    for fact in FACTS:
        mark('ENTER','FACTS.'+fact)
        if fact=='MSI_TABLES':
            mark('ENTER','MSI_TABLES.SUMMARY')
            mark('ENTER','MSI_TABLES.OPEN_DATABASE',dict(mode=0));mark('RETURN','MSI_TABLES.OPEN_DATABASE',dict(ms=1))
            for table in ('Component','Feature','FeatureComponents','ServiceInstall','ServiceControl'):
                stage='MSI_TABLES.'+table
                mark('ENTER',stage+'.SUMMARY',dict(table_seconds=20,chunk_seconds=5,max_rows=6000,max_fields=64))
                for operation in ('OPEN','EXECUTE'):
                    mark('ENTER',stage+'.'+operation);mark('RETURN',stage+'.'+operation,dict(ms=1))
                mark('ENTER',stage+'.ROWS',dict(completed_rows=0,completed_fields=0,max_chunk_rows=128))
                mark('RETURN',stage+'.ROWS',dict(completed_rows=1,completed_fields=1,chunk_ms=1))
                mark('ENTER',stage+'.SORT',dict(rows=1));mark('RETURN',stage+'.SORT',dict(ms=1))
                mark('ENTER',stage+'.CLOSE');mark('RETURN',stage+'.CLOSE')
                mark('RETURN',stage+'.SUMMARY',dict(views=1,executes=1,rows=1,fields=1,fetches=2,field_count_calls=1,chunks=1,duplicates=0,fetch_ticks=1,field_count_ticks=1,field_ticks=1,frequency=1000,ms=1))
            mark('RETURN','MSI_TABLES.SUMMARY',dict(tables=5,views=5,executes=5,rows=5,fields=5,fetches=10,field_count_calls=5,duplicates=0,ms=1))
        mark('RETURN','FACTS.'+fact)
    for name in NATIVE:
        mark('RETURN','PROFILE.NATIVE.'+name,dict(started=1,returned=1,ticks=1,max_ticks=1,frequency=1000))
    mark('RETURN','SCRIPTBLOCK.INVOKE');mark('RETURN','WRAPPER')
    return rows

def journal_bytes(identity,utc='2026-10-11T00:00:00Z',rows=None):
    return b''.join(canonical(dict(identity,seq=n,ms=n,utc=utc,phase=p,stage=s,counts=c))+b'\n'
                    for n,(p,s,c) in enumerate(complete_rows() if rows is None else rows,1))
