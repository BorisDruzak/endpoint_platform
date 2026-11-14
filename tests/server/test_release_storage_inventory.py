from pathlib import Path
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tools.release import inventory_storage


@pytest.mark.asyncio
async def test_inventory_keeps_registered_and_unclassified_artifacts(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "registered.zip").write_bytes(b"registered")
    (root / "unclassified.exe").write_bytes(b"unclassified")
    (root / "subdirectory").mkdir()
    (root / "subdirectory" / "nested").write_bytes(b"nested")

    engine = create_async_engine("sqlite+aiosqlite://")
    try:
        async with engine.begin() as connection:
            for definition in (
                "update_builds (artifact_identifier TEXT)",
                "setup_update_releases (artifact_name TEXT)",
                "windows_setup_releases (artifact_identifier TEXT)",
                "browser_sensor_releases (artifact_identifier TEXT, update_manifest_identifier TEXT, metadata_identifier TEXT)",
            ):
                await connection.execute(text(f"CREATE TABLE {definition}"))
            await connection.execute(text("INSERT INTO update_builds VALUES ('registered.zip')"))
            await connection.execute(text("INSERT INTO setup_update_releases VALUES ('missing.exe')"))
            await connection.execute(text("INSERT INTO windows_setup_releases VALUES ('subdirectory')"))
            await connection.execute(text(
                "INSERT INTO browser_sensor_releases VALUES ('sensor.crx', 'update.xml', 'metadata.json')"
            ))
        async with async_sessionmaker(engine)() as session:
            result = await inventory_storage.read_artifact_inventory(session, root)
    finally:
        await engine.dispose()
    assert result["registered_files"] == [{"name": "registered.zip", "bytes": 10}]
    assert result["unclassified_files"] == [{"name": "unclassified.exe", "bytes": 12}]
    assert result["missing_registered_names"] == ["metadata.json", "missing.exe", "sensor.crx", "update.xml"]
    assert result["registered_nonregular_entries"] == ["subdirectory"]
    assert result["other_entries"] == ["subdirectory"]
    assert (root / "registered.zip").read_bytes() == b"registered"
    assert (root / "unclassified.exe").read_bytes() == b"unclassified"
    assert (root / "subdirectory" / "nested").read_bytes() == b"nested"


def test_artifact_scan_rejects_an_incomplete_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_storage, "MAX_ENTRIES", 1)
    for name in ("a", "b"):
        (tmp_path / name).touch()
    with pytest.raises(ValueError, match="inventory limit"):
        inventory_storage.scan_artifacts(Path(tmp_path))
