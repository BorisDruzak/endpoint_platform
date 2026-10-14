"""Read-only native registration queries used before exact legacy replacement."""
import pytest
from pc_agent.platform.windows.msi_inventory import NativeMsi,ProvenanceConflict

PRODUCT='{11111111-1111-4111-8111-111111111111}'
OTHER='{22222222-2222-4222-8222-222222222222}'


def native(method):
    value=NativeMsi.__new__(NativeMsi)
    value._api=lambda name,*_args:method
    return value


@pytest.mark.parametrize('items',[[],[PRODUCT],[OTHER,PRODUCT]])
def test_related_products_are_exact_bounded_native_results(items):
    seen=[]
    def query(upgrade,reserved,index,buffer):
        seen.append(index)
        assert reserved==0
        if index==len(items):return 259
        buffer.value=items[index]
        return 0
    assert native(query).related_products(PRODUCT)==tuple(sorted(items))
    assert seen==list(range(len(items)+1))


@pytest.mark.parametrize('defect',['error','guid','duplicate','overflow'])
def test_related_products_reject_unavailable_or_ambiguous_inventory(defect):
    def query(upgrade,reserved,index,buffer):
        if defect=='error':return 1605
        if defect=='guid':buffer.value='untrusted';return 0
        if defect=='duplicate':buffer.value=PRODUCT;return 0 if index<2 else 259
        buffer.value='{'+f'{index:08X}'+'-1111-4111-8111-111111111111}'
        return 0
    with pytest.raises(ProvenanceConflict):native(query).related_products(PRODUCT)


def test_empty_registered_transforms_are_observable_but_required_properties_stay_strict():
    def query(code,name,buffer,length):return 0
    value=native(query)
    assert value.product_metadata(PRODUCT,'Transforms')==''
    with pytest.raises(ProvenanceConflict):value.property(PRODUCT,'VersionString')


def test_unavailable_registered_metadata_is_not_empty_success():
    with pytest.raises(ProvenanceConflict):
        native(lambda *_args:1608).product_metadata(PRODUCT,'Transforms')


@pytest.mark.parametrize('code,expected',[(259,False),(0,True),(234,True)])
def test_any_registered_patch_is_reported_without_exposing_transform_paths(code,expected):
    assert native(lambda *_args:code).has_patches(PRODUCT) is expected


def test_unavailable_patch_inventory_is_rejected():
    with pytest.raises(ProvenanceConflict):native(lambda *_args:1605).has_patches(PRODUCT)
