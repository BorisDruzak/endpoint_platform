"""Disk budgets count new allocations on the volume receiving them."""
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("payload,expected", [(1, 67108865), (100, 67108964), (536870912, 603979776)])
def test_download_budget_uses_ceiling_and_bounded_floor(payload, expected):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    assert disk.download_required_bytes(payload) == expected


def test_apply_budget_counts_only_pinned_copy_and_new_expansion():
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    assert disk.apply_required_bytes(100, 200) == 67109164
    assert disk.apply_required_bytes(100, 671088541) == 738197506


@pytest.mark.parametrize("free,insufficient", [(67109163, True), (67109164, False), (67109165, False)])
def test_capacity_boundary_at_exact_apply_budget(tmp_path, monkeypatch, free, insufficient):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda _: SimpleNamespace(free=free))
    if insufficient:
        with pytest.raises(disk.DiskInsufficient, match="^DISK_INSUFFICIENT$"):
            disk.require_disk_space(tmp_path / "not-created" / "candidate", 67109164)
    else:
        disk.require_disk_space(tmp_path / "not-created" / "candidate", 67109164)


def test_capacity_uses_each_target_volume_not_source_volume(tmp_path, monkeypatch):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    first, second = tmp_path / "data", tmp_path / "install"
    first.mkdir(); second.mkdir()
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda path: SimpleNamespace(free=100 if Path(path) == first else 99))
    disk.require_disk_space(first / "download.zip", 100)
    with pytest.raises(disk.DiskInsufficient):
        disk.require_disk_space(second / "candidate", 100)


@pytest.mark.parametrize("size", [-1, True, 1.1, 512 * 1024 * 1024 + 1])
def test_download_budget_rejects_unbounded_or_invalid_sizes(size):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    with pytest.raises(ValueError):
        disk.download_required_bytes(size)


@pytest.mark.parametrize("size", [-1, True, 2 * 1024 * 1024 * 1024 + 1])
def test_expanded_budget_rejects_unvalidated_sizes(size):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    with pytest.raises(ValueError):
        disk.apply_required_bytes(100, size)


def test_same_volume_allocations_are_combined_before_capacity_check(tmp_path, monkeypatch):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    monkeypatch.setattr(disk, "allocation_volume", lambda _: tmp_path, raising=False)
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda _: SimpleNamespace(free=67109163))
    with pytest.raises(disk.DiskInsufficient):
        disk.require_allocation_space([(tmp_path / "one", 100), (tmp_path / "two", 200)])


def test_separate_volumes_do_not_charge_each_others_allocations(tmp_path, monkeypatch):
    disk = importlib.import_module("pc_agent.platform.windows.disk_readiness")
    first, second = tmp_path / "one", tmp_path / "two"
    first.mkdir(); second.mkdir()
    monkeypatch.setattr(disk, "allocation_volume", lambda path: path, raising=False)
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda path: SimpleNamespace(free=67108964 if Path(path) == first else 67109064))
    disk.require_allocation_space([(first, 100), (second, 200)])
