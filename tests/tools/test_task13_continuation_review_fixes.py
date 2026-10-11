import copy
from uuid import uuid4
import pytest
from tools.canary.task13_continuation.journal import validate_journal
from tests.tools.task13_journal_fixture import complete_rows,journal_bytes

pytestmark=pytest.mark.no_db

@pytest.mark.parametrize('fault',['wrapper_only','no_facts','no_native','unmatched_read','read_position','native_ticks','table_summary','gzip_return','facts_order','table_open','row_chunk_time'])
def test_incomplete_journal_cannot_support_pass(fault):
    identity=dict(run=str(uuid4()),pid=12,birth=123)
    rows=copy.deepcopy(complete_rows())
    if fault=='wrapper_only': rows=[row for row in rows if row[1] in ('WRAPPER','WATCHDOG_ARMED','SCRIPTBLOCK.INVOKE')]
    elif fault=='no_facts': rows=[row for row in rows if not row[1].startswith('FACTS.')]
    elif fault=='no_native': rows=[row for row in rows if not row[1].startswith('PROFILE.')]
    elif fault=='unmatched_read': rows.insert(-1,('ENTER','STDIN.READ',dict(requested=3,position=3,call=1)))
    elif fault=='read_position': next(row[2] for row in rows if row[:2]==('RETURN','STDIN.READ'))['position']=2
    elif fault=='native_ticks': next(row[2] for row in rows if row[1].startswith('PROFILE.'))['ticks']=-1
    elif fault=='table_summary': next(row[2] for row in rows if row[:2]==('RETURN','MSI_TABLES.SUMMARY'))['tables']=4
    elif fault=='gzip_return': rows=[row for row in rows if row[:2]!=('RETURN','PAYLOAD.GZIP_READ')]
    elif fault=='table_open': rows=[row for row in rows if row[1]!='MSI_TABLES.Component.OPEN']
    elif fault=='row_chunk_time': next(row[2] for row in rows if row[:2]==('RETURN','MSI_TABLES.Component.ROWS'))['chunk_ms']=6000
    else:
        a=next(i for i,r in enumerate(rows) if r[:2]==('ENTER','FACTS.PAYLOAD'))
        b=next(i for i,r in enumerate(rows) if r[:2]==('ENTER','FACTS.DEVICE_NETWORK'))
        rows[a],rows[b]=rows[b],rows[a]
    with pytest.raises(ValueError): validate_journal(journal_bytes(identity,rows=rows),identity)

def test_complete_explicit_synthetic_journal_contract():
    identity=dict(run=str(uuid4()),pid=12,birth=123)
    validate_journal(journal_bytes(identity),identity,expected_stdin_bytes=3)
