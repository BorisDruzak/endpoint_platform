"""Shared resources may survive replacement; the old native owner may not."""
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import msi_inventory as inventory


@pytest.mark.parametrize('defect',['none','old-product','old-feature','old-component','old-path','new-invalid'])
def test_replacement_requires_old_registration_absence_and_complete_new_owner(monkeypatch,defect,tmp_path):
    old=SimpleNamespace(product_code='old',features={'foundation':1,'runtime':1},
        components={'shared':SimpleNamespace(guid='shared'),'initial':SimpleNamespace(guid='old-initial')})
    new=SimpleNamespace(product_code='new')
    native=SimpleNamespace(product=lambda code:5 if defect=='old-product' else -1,
        feature=lambda product,feature:3 if defect=='old-feature' else -1,
        component=lambda product,guid:((3,None) if defect=='old-component' else
            (-1,'unexplained path') if defect=='old-path' else (-1,None)))
    verified=[]
    def verify(package,root,*,native):
        assert package is new and root==tmp_path
        if defect=='new-invalid':raise ValueError('PROVENANCE_CONFLICT')
        verified.append(package)
    monkeypatch.setattr(inventory,'verify_installed',verify)
    if defect=='none':
        inventory.verify_replaced_product(old,new,tmp_path,native=native)
        assert verified==[new]
    else:
        with pytest.raises(ValueError):inventory.verify_replaced_product(old,new,tmp_path,native=native)
