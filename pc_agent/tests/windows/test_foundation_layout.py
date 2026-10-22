"""Schema two authenticates every shared dependency without changing v1."""
import hashlib
from types import SimpleNamespace

import pytest


def records(module):
    return [{'path': path, 'file': ids[0], 'component': ids[1],
             'size': 3, 'sha256': hashlib.sha256(b'exe').hexdigest()}
            for path, ids in module.FOUNDATION_EXECUTABLES.items()]


def test_schema_two_accepts_complete_shared_inventory_and_v1_rejects_it():
    from pc_agent.platform.windows import msi_inventory as module
    from pc_agent.platform.windows.foundation_layout import shared_binding
    rows = records(module)
    path = '_foundation-runtime/python312.dll'
    file, component = shared_binding(path)
    rows.append(dict(path=path, file=file, component=component, size=3,
                     sha256=hashlib.sha256(b'dll').hexdigest()))
    assert module._foundation_records(rows, schema=2) == tuple(rows)
    with pytest.raises(module.ProvenanceConflict):
        module._foundation_records(rows)
    with pytest.raises(module.ProvenanceConflict):
        module._foundation_records(records(module), schema=2)


@pytest.mark.parametrize('defect', ['missing', 'escape', 'case_alias', 'wrong_binding'])
def test_schema_two_rejects_incomplete_or_ambiguous_inventory(defect):
    from pc_agent.platform.windows import msi_inventory as module
    from pc_agent.platform.windows.foundation_layout import shared_binding
    rows = records(module)
    path = '_foundation-runtime/python312.dll'
    file, component = shared_binding(path)
    row = dict(path=path, file=file, component=component, size=3, sha256='a' * 64)
    rows.append(row)
    if defect == 'missing':
        rows.pop(0)
    elif defect == 'escape':
        row['path'] = '_foundation-runtime/../outside.dll'
    elif defect == 'case_alias':
        rows.append({**row, 'path': path.upper()})
    else:
        row['component'] = 'foreign'
    with pytest.raises(module.ProvenanceConflict):
        module._foundation_records(rows, schema=2)


def test_shared_namespace_extra_file_is_rejected_before_byte_read(tmp_path, monkeypatch):
    from pc_agent.platform.windows import msi_inventory as module
    from pc_agent.platform.windows.foundation_layout import shared_binding
    from pc_agent.platform.windows import update_transaction
    rows = records(module)
    shared = tmp_path / '_foundation-runtime'
    shared.mkdir()
    (shared / 'python312.dll').write_bytes(b'dll')
    path = '_foundation-runtime/python312.dll'
    file, component = shared_binding(path)
    rows.append(dict(path=path, file=file, component=component, size=3,
                     sha256=hashlib.sha256(b'dll').hexdigest()))
    for row in rows[:8]:
        (tmp_path / row['path']).write_bytes(b'exe')
    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda *_: None)
    expected = SimpleNamespace(foundation_files=tuple(rows), foundation_schema=2)
    with module.verified_foundation_bytes(expected, tmp_path):
        pass
    (shared / 'foreign.dll').write_bytes(b'injected')
    with pytest.raises(module.ProvenanceConflict):
        with module.verified_foundation_bytes(expected, tmp_path):
            pytest.fail('extra shared dependency admitted')


def test_all_explicit_shared_byte_proofs_remain_pinned_across_metadata_checkpoints(tmp_path, monkeypatch):
    from pc_agent.platform.windows import msi_inventory as module, durable_state, update_transaction
    from pc_agent.platform.windows.foundation_layout import shared_binding
    rows = records(module)
    for index in range(40):
        path = '_foundation-runtime/dependency-%s.dll' % index
        file, component = shared_binding(path)
        rows.append(dict(path=path, file=file, component=component, size=3,
                         sha256=hashlib.sha256(b'exe').hexdigest()))
    for row in rows:
        path = tmp_path / row['path']
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b'exe')
    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda *_: None)
    original = durable_state._verify_copy_bytes
    reads = []
    def verify(*args):
        reads.append(1)
        return original(*args)
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', verify)
    expected = SimpleNamespace(foundation_files=tuple(rows), foundation_schema=2)
    with module.package_read_scope(), module.immutable_foundation_reads(expected, tmp_path):
        for _ in range(2):
            with module.verified_foundation_bytes(expected, tmp_path):
                pass
            module._PHASE_READS.get().invalidate()
        assert len(module._PHASE_READS.get().pins) == len(rows)
        import os
        if os.name == 'nt':
            with pytest.raises(PermissionError):
                (tmp_path / rows[-1]['path']).write_bytes(b'blocked while pinned')
    assert len(reads) == len(rows)
    (tmp_path / rows[-1]['path']).write_bytes(b'all pins closed')
