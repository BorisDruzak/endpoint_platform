"""Only exact reviewed legacy registrations may enter native major upgrade."""
from types import SimpleNamespace
import pytest
from pc_agent.platform.windows.msi_inventory import ProvenanceConflict

OLD='{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}'
PACKAGE='{11111111-1111-4111-8111-111111111111}'
RELEASE={'schema_version':'endpoint_windows_release_v1','version':'3.2.81',
 'source_revision':'c05bb0a528527ed1544c88fb0b1570c64b32084d',
 'package_sha256':'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5',
 'initial_runtime_tree_sha256':'a4db007c0e313f6d5b34633aeaad10a2a47f01aeed6444b97021b3e222a580e2',
 'product_code':OLD}


def test_unknown_or_missing_owner_binary_is_not_legacy_admission():
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    assert legacy.canonical_release({**RELEASE,'package_sha256':'0'*64}) is None
    assert legacy.canonical_release(RELEASE)==RELEASE


@pytest.mark.parametrize('field',['version','source_revision','product_code','initial_runtime_tree_sha256','schema_version','extra'])
def test_known_hash_does_not_admit_a_different_contract(field):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    with pytest.raises(ProvenanceConflict):legacy.canonical_release({**RELEASE,field:'wrong'})


@pytest.mark.parametrize('defect',['none','advertised','user','transforms','patch','package','related-empty','related-foreign'])
def test_registered_target_is_exact_machine_unmodified_package(defect):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    package=SimpleNamespace(sha256=RELEASE['package_sha256'],version='3.2.81',product_code=OLD,package_code=PACKAGE)
    class Native:
        def product(self,code):return 1 if defect=='advertised' else 5
        def property(self,code,name):
            return {'AssignmentType':'0' if defect=='user' else '1','PackageCode':OLD if defect=='package' else PACKAGE,'VersionString':'3.2.81'}[name]
        def product_metadata(self,code,name):return 'unreviewed' if defect=='transforms' else ''
        def has_patches(self,code):return defect=='patch'
        def related_products(self,code):return () if defect=='related-empty' else (OLD,PACKAGE) if defect=='related-foreign' else (OLD,)
    if defect=='none':legacy.verify_registration(package,RELEASE,native=Native())
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_registration(package,RELEASE,native=Native())


@pytest.mark.parametrize('defect',[None,'absent','extra','path','source','unknown-hash','registered-cache','foundation'])
def test_legacy_foundation_inspection_requires_original_receipt_native_owner_and_cache(tmp_path,monkeypatch,defect):
    import json
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy,installation_provenance as provenance,msi_inventory
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    cache=paths.updates_root.parent/'installer-cache';cache.mkdir(parents=True)
    record={'schema_version':'endpoint_windows_installer_provenance_v1',
        'release_manifest_schema_version':RELEASE['schema_version'],
        **{key:value for key,value in RELEASE.items() if key!='schema_version'},
        'cache_file':f"msi-{RELEASE['package_sha256']}/EndpointAgent.msi"}
    if defect=='extra':record['approved']=True
    if defect=='path':record['cache_file']='../foreign.msi'
    if defect=='source':record['source_revision']='0'*40
    if defect=='unknown-hash':record['package_sha256']='0'*64
    if defect!='absent':(cache/'installer-provenance.json').write_text(json.dumps(record))
    monkeypatch.setattr(provenance,'_assert_security',lambda *_:None)
    package=SimpleNamespace(sha256=RELEASE['package_sha256'],version=RELEASE['version'],product_code=OLD,package_code=PACKAGE)
    calls=[]
    def read(path,digest):
        assert path==cache/record['cache_file'] and digest==RELEASE['package_sha256']
        calls.append('immutable-media');return package
    def foundation(actual,install_root,*,native):
        assert actual==package and install_root==paths.install_root
        if defect=='foundation':raise ProvenanceConflict()
        calls.append('native-foundation')
    def cached(path,actual,*,native):
        assert path==cache/record['cache_file'] and actual==package
        if defect=='registered-cache':raise ProvenanceConflict()
        calls.append('registered-cache')
    monkeypatch.setattr(msi_inventory,'read_package',read)
    monkeypatch.setattr(msi_inventory,'verify_foundation',foundation)
    monkeypatch.setattr(msi_inventory,'verify_registered_cache',cached)
    class Native:
        def product(self,code):return 5
        def property(self,code,name):return {'AssignmentType':'1','PackageCode':PACKAGE,'VersionString':RELEASE['version']}[name]
        def product_metadata(self,*_):return ''
        def has_patches(self,*_):return False
        def related_products(self,*_):return (OLD,)
    if defect in {None,'absent'}:
        assert legacy.inspect_foundation(paths,native=Native())==(RELEASE if defect is None else None)
        assert calls==(['immutable-media','native-foundation','registered-cache'] if defect is None else [])
    else:
        with pytest.raises(ProvenanceConflict):legacy.inspect_foundation(paths,native=Native())
        if defect in {'extra','path','source','unknown-hash'}:assert not calls


@pytest.mark.parametrize('detected,valid',[(OLD,True),(OLD+';',True),('',False),(None,False),(OLD+';;',False),(OLD+';'+PACKAGE,False),(OLD+';'+OLD,False)])
def test_actual_native_upgrade_targets_cannot_be_widened(detected,valid):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    if valid:legacy.verify_detected_targets(OLD,detected)
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_detected_targets(OLD,detected)


@pytest.mark.parametrize('defect',[None,'no-legacy','unselected','package','source','duplicate','downgrade'])
def test_prepared_predecessor_comes_only_from_bound_verified_history(tmp_path,monkeypatch,defect):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy,installation_provenance as provenance,msi_inventory,runtime_identity,installer_fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    selected='a'*64;previous='b'*64
    request={'transaction_id':'11111111-1111-4111-8111-111111111111','selected':selected,'previous':previous}
    new=SimpleNamespace(package=SimpleNamespace(version='3.2.79' if defect=='downgrade' else '3.2.96',product_code=PACKAGE))
    plan={'archives':[previous,selected] if defect=='duplicate' else [previous if defect=='unselected' else selected]}
    if defect=='unselected':request['previous']=None
    monkeypatch.setattr(provenance,'_expected_request',lambda actual:new if actual==request else pytest.fail('request replaced'))
    monkeypatch.setattr(provenance,'_read_plan',lambda root,actual,expected:plan if actual==request and expected is new else pytest.fail('plan binding lost'))
    monkeypatch.setattr(installer_fence,'assert_state_security',lambda *_:None)
    record={'package':{'sha256':'0'*64 if defect=='no-legacy' else RELEASE['package_sha256'],
        'version':RELEASE['version'],'product_code':OLD,'package_code':PACKAGE}}
    retained=SimpleNamespace(archive=tmp_path/'retained',record=record,
        identity=SimpleNamespace(version=RELEASE['version'],source_revision='0'*40 if defect=='source' else RELEASE['source_revision']))
    verified=[]
    def archive(actual,identifier):verified.append(identifier);return retained
    monkeypatch.setattr(runtime_identity,'verify_retained_archive',archive)
    old=SimpleNamespace(sha256=RELEASE['package_sha256'],version=RELEASE['version'],
        product_code=PACKAGE if defect=='package' else OLD,package_code=PACKAGE)
    monkeypatch.setattr(msi_inventory,'read_package',lambda path,digest:old)
    if defect in {None,'no-legacy'}:
        result=legacy.prepared_predecessor(paths,request)
        assert (result is None)==(defect=='no-legacy')
        if result is not None:
            assert result.release==RELEASE and result.package is old and result.media==retained.archive/'package.msi'
        assert verified==[selected]
    else:
        with pytest.raises(ProvenanceConflict):legacy.prepared_predecessor(paths,request)


@pytest.mark.parametrize('state,recovery,detected,valid',[
 (5,False,OLD,True),(5,True,OLD,True),(5,False,'',False),(5,False,OLD+';'+PACKAGE,False),
 (-1,False,'',False),(-1,True,'',True),(-1,True,OLD,False),(1,True,OLD,False)])
def test_native_preflight_binds_actual_targets_and_bounded_recovery(monkeypatch,state,recovery,detected,valid):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy,installation_provenance as provenance,msi_inventory
    old=SimpleNamespace(product_code=OLD,package_code=PACKAGE,version=RELEASE['version'],sha256=RELEASE['package_sha256'])
    new_code='{33333333-3333-4333-8333-333333333333}'
    new=SimpleNamespace(product_code=new_code,package_code=PACKAGE,version='3.2.96')
    role=SimpleNamespace(package=old,media='old-original.msi',release=RELEASE)
    request={'package_path':'new-original.msi'}
    paths=SimpleNamespace(install_root='fixed-install-root')
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:role)
    monkeypatch.setattr(provenance,'_expected_request',lambda *_:SimpleNamespace(package=new))
    comparisons=[]
    monkeypatch.setattr(msi_inventory,'verify_registered_cache',lambda path,package,**_:comparisons.append(package.product_code))
    monkeypatch.setattr(msi_inventory,'verify_foundation',lambda *_args,**_kwargs:None)
    class Native:
        def product(self,code):return state if code==OLD else (5 if state==-1 else -1)
        def property(self,code,name):return {'PackageCode':PACKAGE,'VersionString':RELEASE['version'] if code==OLD else '3.2.96','AssignmentType':'1'}[name]
        def product_metadata(self,*_):return ''
        def has_patches(self,*_):return False
        def related_products(self,*_):return (new_code,) if state==-1 else (OLD,)
    if valid:
        legacy.verify_native_preflight(paths,request,detected,recovery=recovery,native=Native())
        assert comparisons==[new_code if state==-1 else OLD]
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_native_preflight(paths,request,detected,recovery=recovery,native=Native())


@pytest.mark.parametrize('detected,valid',[('',True),(None,False),(OLD,False)])
def test_no_legacy_history_cannot_authorize_an_old_native_target(monkeypatch,detected,valid):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:None)
    if valid:legacy.verify_native_preflight(None,{},detected)
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_native_preflight(None,{},detected)


@pytest.mark.parametrize('survives',[False,True])
def test_completion_requires_explicit_replaced_product_verification(monkeypatch,survives):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy,installation_provenance as provenance,msi_inventory
    role=SimpleNamespace(package='exact-old-inventory')
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:role)
    monkeypatch.setattr(provenance,'_expected_request',lambda *_:SimpleNamespace(package='exact-new-inventory'))
    checked=[]
    def replaced(old,new,root):
        checked.append((old,new,root))
        if survives:raise ProvenanceConflict()
    monkeypatch.setattr(msi_inventory,'verify_replaced_product',replaced)
    paths=SimpleNamespace(install_root='original-install-root')
    if survives:
        with pytest.raises(ProvenanceConflict):legacy.verify_completed_replacement(paths,{})
    else:legacy.verify_completed_replacement(paths,{})
    assert checked==[('exact-old-inventory','exact-new-inventory','original-install-root')]


@pytest.mark.parametrize('foundation,prepared,valid',[
 (RELEASE,RELEASE,True),(RELEASE,None,False),(None,RELEASE,False),(None,None,True),
 (RELEASE,{**RELEASE,'product_code':PACKAGE},False)])
def test_preparation_requires_the_observed_foundation_in_bound_history(monkeypatch,foundation,prepared,valid):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:None if prepared is None else SimpleNamespace(release=prepared))
    if valid:legacy.verify_prepared_foundation(None,{},foundation)
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_prepared_foundation(None,{},foundation)


@pytest.mark.parametrize('defect',[None,'missing-component','foreign-path','absent-feature','partial-runtime'])
def test_old5_recovery_rechecks_native_foundation_components_and_paths(tmp_path,monkeypatch,defect):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy,installation_provenance as provenance,msi_inventory as msi
    old=msi.PackageInventory(RELEASE['package_sha256'],OLD,PACKAGE,RELEASE['version'],
        {msi.FOUNDATION_FEATURE:1,msi.RUNTIME_FEATURE:1},
        {'svc':msi.Component('svc',PACKAGE,'INSTALLFOLDER','host',(msi.FOUNDATION_FEATURE,))},
        (msi.InstalledFile('host','svc','service-host.exe',10),))
    new=SimpleNamespace(product_code='{33333333-3333-4333-8333-333333333333}',version='3.2.96')
    paths=SimpleNamespace(install_root=tmp_path/'Agent')
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:SimpleNamespace(package=old,media='original.msi',release=RELEASE))
    monkeypatch.setattr(provenance,'_expected_request',lambda *_:SimpleNamespace(package=new))
    compared=[]
    monkeypatch.setattr(msi,'verify_registered_cache',lambda *_args,**_kw:compared.append(True))
    class Native:
        def product(self,code):return 5 if code==OLD else -1
        def property(self,code,name):return {'AssignmentType':'1','PackageCode':PACKAGE,'VersionString':RELEASE['version']}[name]
        def product_metadata(self,*_):return ''
        def has_patches(self,*_):return False
        def related_products(self,*_):return (OLD,)
        def feature(self,code,name):
            if name==msi.FOUNDATION_FEATURE:return 2 if defect=='absent-feature' else 3
            return 2 if defect=='partial-runtime' else 3
        def component(self,code,identifier):
            if defect=='missing-component':return -1,''
            return 3,str((tmp_path/'foreign' if defect=='foreign-path' else paths.install_root)/'service-host.exe')
    if defect in {None,'partial-runtime'}:
        legacy.verify_native_preflight(paths,{},OLD,recovery=True,native=Native())
        assert compared==[True]
    else:
        with pytest.raises(ProvenanceConflict):legacy.verify_native_preflight(paths,{},OLD,recovery=True,native=Native())
        assert compared==[]
