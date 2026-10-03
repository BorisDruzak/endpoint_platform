from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
import pytest
from pc_agent.platform.windows import durable_state as durable


def test_lost_owner_blocks_next_document_preserves_fence_and_resets_context(tmp_path):
    fence=tmp_path/'transaction.json'; fence.write_bytes(b'active fence')
    alive=True
    def checkpoint():
        if not alive: raise ValueError('OWNER_AUTH_FAILED')
    with pytest.raises(ValueError,match='OWNER_AUTH_FAILED'):
        with durable.installer_mutation_checkpoints(checkpoint):
            durable.write_json_atomic(tmp_path/'first.json',{'prepared':True},trusted_root=tmp_path,max_bytes=100)
            alive=False
            durable.write_json_atomic(tmp_path/'second.json',{'committed':True},trusted_root=tmp_path,max_bytes=100)
    assert fence.read_bytes()==b'active fence'
    assert (tmp_path/'first.json').exists()
    assert not (tmp_path/'second.json').exists()
    assert not list(tmp_path.glob('*.tmp'))
    durable.write_json_atomic(tmp_path/'ordinary.json',{},trusted_root=tmp_path,max_bytes=100)


def test_checkpoint_is_context_and_thread_local(tmp_path):
    def denied(): raise ValueError('OWNER_AUTH_FAILED')
    def write(name): durable.write_bytes_atomic(tmp_path/name,b'ok',trusted_root=tmp_path,max_bytes=10)
    with durable.installer_mutation_checkpoints(denied):
        with pytest.raises(ValueError): write('denied')
        Context().run(write,'fresh-context')
        with ThreadPoolExecutor(max_workers=1) as pool: pool.submit(write,'fresh-thread').result()
    assert (tmp_path/'fresh-context').read_bytes()==b'ok'
    assert (tmp_path/'fresh-thread').read_bytes()==b'ok'


@pytest.mark.parametrize('operation',['unlink','prepared','copy','existing-copy','barrier'])
def test_checkpoint_covers_every_installer_durability_boundary(tmp_path,operation):
    import hashlib
    source=tmp_path/'source'; source.write_bytes(b'evidence')
    destination=tmp_path/'destination'
    if operation=='existing-copy': destination.write_bytes(b'evidence')
    def denied(): raise ValueError('OWNER_AUTH_FAILED')
    with durable.installer_mutation_checkpoints(denied), pytest.raises(ValueError,match='OWNER_AUTH_FAILED'):
        if operation=='unlink': durable.durable_unlink(source,trusted_root=tmp_path)
        elif operation=='prepared': durable.publish_prepared(source,destination,expected_bytes=b'evidence',trusted_root=tmp_path,max_bytes=100)
        elif operation=='barrier': durable.flush_directory(tmp_path)
        else: durable.durable_copy_file(source,destination,source_root=tmp_path,trusted_root=tmp_path,
            max_bytes=100,expected_size=8,expected_sha256=hashlib.sha256(b'evidence').hexdigest(),
            protect=lambda _:None,validate=lambda _:None)
    assert source.read_bytes()==b'evidence'
    assert destination.exists()==(operation=='existing-copy')
