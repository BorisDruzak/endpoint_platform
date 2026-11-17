"""Report files and catalog references in server artifact storage."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import stat

from sqlalchemy import select, union_all

from endpoint_server.browser_sensor.models import BrowserSensorRelease
from endpoint_server.db.models import UpdateBuild, WindowsSetupRelease
from endpoint_server.db.session import create_session_provider
from endpoint_server.setup_updates.models import SetupRelease


MAX_ENTRIES = 20_000


def scan_artifacts(root: Path) -> tuple[dict[str, int], list[str]]:
    details = root.lstat()
    if not stat.S_ISDIR(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
        raise ValueError("artifact root must be a physical directory")
    files = {}
    other = []
    with os.scandir(root) as entries:
        for number, entry in enumerate(entries, start=1):
            if number > MAX_ENTRIES:
                raise ValueError("artifact directory exceeds inventory limit")
            details = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400:
                files[entry.name] = details.st_size
            else:
                other.append(entry.name)
    return files, sorted(other)


async def read_artifact_inventory(session, root: Path) -> dict[str, object]:
    columns = (
        UpdateBuild.artifact_identifier,
        SetupRelease.artifact_name,
        WindowsSetupRelease.artifact_identifier,
        BrowserSensorRelease.artifact_identifier,
        BrowserSensorRelease.update_manifest_identifier,
        BrowserSensorRelease.metadata_identifier,
    )
    rows = (await session.execute(
        union_all(*(select(column) for column in columns)).limit(MAX_ENTRIES + 1)
    )).all()
    if len(rows) > MAX_ENTRIES:
        raise ValueError("release catalog exceeds inventory limit")
    names = {name for (name,) in rows}
    files, other = await asyncio.to_thread(scan_artifacts, root)
    space = shutil.disk_usage(root)
    return {
        "registered_files": [{"name": name, "bytes": files[name]} for name in sorted(names & files.keys())],
        "unclassified_files": [{"name": name, "bytes": files[name]} for name in sorted(files.keys() - names)],
        "missing_registered_names": sorted(names - files.keys() - set(other)),
        "registered_nonregular_entries": sorted(names & set(other)),
        "other_entries": other,
        "volume_free_bytes": space.free,
        "volume_total_bytes": space.total,
    }


async def _run(root: Path, database_url: str) -> dict[str, object]:
    provider = create_session_provider(database_url)
    try:
        async with asyncio.timeout(20), provider() as session:
            return await read_artifact_inventory(session, root)
    finally:
        await provider.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, default=os.environ.get("ARTIFACT_ROOT"))
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL")
    if not args.artifact_root or not database_url:
        parser.error("ARTIFACT_ROOT and DATABASE_URL are required")
    try:
        inventory = asyncio.run(_run(Path(args.artifact_root), database_url))
    except Exception:
        raise SystemExit("release storage inventory failed") from None
    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
