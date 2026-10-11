"""Complete chronological protected workload journal validation."""
from .codec import parse_json, require, integer, instant, digest
from collections import Counter

FACTS = 'PAYLOAD DEVICE_NETWORK SELECTORS PRIVATE_STATE UPDATE_HISTORY MSI_PRODUCT_CACHE MSI_COMPONENTS_FEATURES MSI_TABLES MSI_COMPONENT_STATES ANCESTOR_ACLS SERVICES_ANCESTRY TRUST_SCM SETUP_TRUST CLOCK_CAPACITY INSTALL_TREE STAGING_TREE CACHE_FINAL HELPER_INPUTS NATIVE_QUERIES MAPPING'.split()
NATIVE = set('NewObject ProductState ProductInfo Features FeatureState ComponentPath MsiQueryComponentStateW MsiGetComponentPathW scexe GetAuthenticodeSignature GetCimInstance GetAccessRules GetOwner'.split())
NATIVE_ALLOWED = NATIVE | set('AllocHGlobal CloseHandle Dispose FreeHGlobal GetTokenInformation GetValue GetValueKind GetValueNames OpenBaseKey OpenProcess OpenProcessToken OpenSubKey ReadInt32 ReadIntPtr Translate'.split())
TABLES = ('Component','Feature','FeatureComponents','ServiceInstall','ServiceControl')

def validate_journal(raw, identity, expected_stdin_bytes=None):
    require(type(raw) is bytes and 0 < len(raw) <= 33554432 and raw.endswith(b"\n"), "complete bounded journal")
    rows = [parse_json(line) for line in raw.splitlines()]
    require(len(rows) >= 5, "journal missing phases")
    last_ms, last_utc = 0, None
    required = [("ENTER", "WRAPPER"), ("RETURN", "WATCHDOG_ARMED"),
                ("ENTER", "SCRIPTBLOCK.INVOKE"), ("RETURN", "SCRIPTBLOCK.INVOKE"),
                ("RETURN", "WRAPPER")]
    cursor = 0
    stack,facts,natives,tables = [],[],set(),{}
    stdin_position,stdin_call,gzip_reads = 0,0,0
    events=Counter();table_order=[];row_totals={}
    for seq, row in enumerate(rows, 1):
        require(set(row) == {"utc", "ms", "run", "pid", "birth", "phase", "stage", "seq", "counts"},
                "journal exact schema")
        require(all(row[k] == v and type(row[k]) is type(v) for k, v in identity.items()), "journal identity")
        require(type(row["seq"]) is int and row["seq"] == seq, "journal sequence")
        ms, utc = integer(row["ms"], 0, 120000), instant(row["utc"])
        require(ms >= last_ms and (last_utc is None or utc >= last_utc), "journal rollback")
        require(abs((utc-instant(rows[0]['utc'])).total_seconds()*1000-(ms-rows[0]['ms']))<=5000,'journal UTC/elapsed divergence')
        require(row["phase"] in ("ENTER", "RETURN") and type(row["stage"]) is str, "journal incomplete operation")
        stage,phase,counts=row['stage'],row['phase'],row['counts']
        if stage.startswith("PROFILE."):
            counts = row["counts"]
            name=stage.removeprefix('PROFILE.NATIVE.')
            require(phase=='RETURN' and name in NATIVE_ALLOWED and type(counts) is dict
                    and set(counts)=={'started','returned','ticks','max_ticks','frequency'},'native summary schema')
            require(integer(counts['started'],1)==integer(counts['returned'],1),'unreturned native operation')
            frequency=integer(counts['frequency'],1)
            require(integer(counts['max_ticks'])<=integer(counts['ticks'])<=frequency*120,'native timing bounds')
            natives.add(name)
        elif stage=='WATCHDOG_ARMED':
            require(phase=='RETURN' and seq==2 and stack and stack[-1]['stage']=='WRAPPER','watchdog arm order')
        else:
            allowed = stage in ('WRAPPER','SCRIPTBLOCK.INVOKE','STDIN.READ','PAYLOAD.GZIP_READ') or stage in {'FACTS.'+s for s in FACTS} or stage in ('MSI_TABLES.SUMMARY','MSI_TABLES.OPEN_DATABASE') or any(stage==f'MSI_TABLES.{t}.{s}' for t in TABLES for s in ('SUMMARY','OPEN','EXECUTE','ROWS','SORT','CLOSE'))
            require(allowed,'unknown journal stage')
            if phase=='ENTER':
                events[stage]+=1
                if stage in ('STDIN.READ','PAYLOAD.GZIP_READ'): require(stack[-1]['stage']=='WRAPPER','payload phase outside wrapper')
                if stage.startswith('FACTS.'): require(stack[-1]['stage']=='SCRIPTBLOCK.INVOKE','Facts phase outside invocation')
                if stage.startswith('MSI_TABLES.') and stage.endswith('.SUMMARY') and stage!='MSI_TABLES.SUMMARY':
                    require(counts=={'table_seconds':20,'chunk_seconds':5,'max_rows':6000,'max_fields':64},'fixed MSI bounds')
                    table_order.append(stage.split('.')[1])
                stack.append(row)
                if stage.startswith('FACTS.'): facts.append(stage.removeprefix('FACTS.'))
            else:
                require(stack and stack[-1]['stage']==stage,'unpaired journal phase')
                entered=stack.pop()
                if stage=='STDIN.READ':
                    a,b=entered['counts'],counts
                    require(type(a) is dict and type(b) is dict and set(a)=={'requested','position','call'}
                            and set(b)=={'requested','returned','position','call'},'stdin count schema')
                    requested=integer(a['requested'],1,65536);returned=integer(b['returned'],1,requested)
                    require(integer(a['position'])==stdin_position and integer(a['call'])==stdin_call
                            and integer(b['call'])==stdin_call and integer(b['requested'])==requested
                            and integer(b['position'])==stdin_position+returned,'stdin count continuity')
                    stdin_position+=returned;stdin_call+=1
                if stage=='PAYLOAD.GZIP_READ': gzip_reads+=1
                if stage.startswith('MSI_TABLES.') and stage.endswith('.ROWS'):
                    table=stage.split('.')[1];a,b=entered['counts'],counts
                    require(type(a) is dict and type(b) is dict and set(a)=={'completed_rows','completed_fields','max_chunk_rows'}
                            and set(b)=={'completed_rows','completed_fields','chunk_ms'},'MSI chunk count schema')
                    before_rows,before_fields=row_totals.get(table,(0,0))
                    require(integer(a['completed_rows'])==before_rows and integer(a['completed_fields'])==before_fields
                            and integer(a['max_chunk_rows'])==128 and integer(b['chunk_ms'],0,5000)<5000
                            and 0<=integer(b['completed_rows'])-before_rows<=128
                            and before_fields<=integer(b['completed_fields'])<=b['completed_rows']*64,'MSI chunk continuity/bound')
                    row_totals[table]=(b['completed_rows'],b['completed_fields'])
                if stage.startswith('MSI_TABLES.') and stage.endswith('.SUMMARY'):
                    require(type(counts) is dict,'MSI summary counts')
                    if stage!='MSI_TABLES.SUMMARY':
                        table=stage.split('.')[1]
                        require(table not in tables,'duplicate MSI table')
                        require(integer(counts['views'])==1 and integer(counts['executes'])==1
                                and integer(counts['duplicates'])==0 and integer(counts['rows'],0,6000)==integer(counts['field_count_calls'])
                                and integer(counts['fetches'])==counts['rows']+1
                                and counts['rows']<=integer(counts['fields'])<=counts['rows']*64
                                and integer(counts['chunks'],1)>=1 and integer(counts['ms'],0,20000)<20000,'complete MSI table counts')
                        frequency=integer(counts['frequency'],1)
                        for key in ('fetch_ticks','field_count_ticks','field_ticks'): require(integer(counts[key])<=frequency*20,'MSI timing bounds')
                        tables[table]=counts
                        require(row_totals.get(table)==(counts['rows'],counts['fields']),'MSI chunk/summary mismatch')
                    else:
                        require(set(tables)==set(TABLES) and integer(counts['tables'])==5,'all MSI tables required')
                        for key in ('views','executes','rows','fields','fetches','field_count_calls','duplicates'):
                            require(integer(counts[key])==sum(t[key] for t in tables.values()),'MSI totals mismatch')
        if cursor < len(required) and (row["phase"], row["stage"]) == required[cursor]:
            cursor += 1
        last_ms, last_utc = ms, utc
    require(cursor == len(required) and (rows[-1]["phase"], rows[-1]["stage"]) == required[-1], "journal no complete finish")
    require(not stack and facts==FACTS and NATIVE<=natives and set(tables)==set(TABLES)
            and stdin_call>0 and gzip_reads>0,'missing source-specific comparator phases')
    require(table_order==list(TABLES) and events['MSI_TABLES.OPEN_DATABASE']==1 and events['MSI_TABLES.SUMMARY']==1
            and events['WRAPPER']==1 and events['SCRIPTBLOCK.INVOKE']==1,'mandatory phase counts/order')
    for table in TABLES:
        require(all(events[f'MSI_TABLES.{table}.{stage}']==1 for stage in ('SUMMARY','OPEN','EXECUTE','SORT','CLOSE'))
                and events[f'MSI_TABLES.{table}.ROWS']>=1,'missing native table operation')
    if expected_stdin_bytes is not None: require(stdin_position==integer(expected_stdin_bytes,1),'wire/stdin byte count')
    return {"rows": len(rows), "duration_ms": last_ms, "identity": identity, "rows_sha256": digest({"rows": rows})}
