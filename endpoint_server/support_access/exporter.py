"""Unprivileged expiring lease snapshot publisher; never controls sshd."""
import argparse
import asyncio
from dataclasses import asdict
from datetime import UTC,datetime,timedelta
import json
import os
from pathlib import Path
import tempfile

from endpoint_server.config import Settings
from endpoint_server.db.session import create_session_provider
from .service import get_broker_leases


async def export_once(provider,path:Path,*,settings:Settings,now=None):
    now=now or datetime.now(UTC)
    async with provider() as session:
        leases=await get_broker_leases(session,now,settings=settings)
    payload={'schema_version':1,'generated_at':now.isoformat(),'valid_until':(now+timedelta(seconds=60)).isoformat(),'leases':[{**asdict(row),'device_id':str(row.device_id),'expires_at':row.expires_at.isoformat()} for row in leases]}
    # RuntimeDirectory is provisioned by systemd; do not create arbitrary parents.
    fd,temporary=tempfile.mkstemp(prefix='.leases-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as stream:
            json.dump(payload,stream,separators=(',',':'))
            stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,0o640)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


async def run(path):
    settings=Settings.from_environment()
    provider=create_session_provider(settings.database_url)
    try:
        while True:
            try:
                await asyncio.wait_for(export_once(provider,path,settings=settings),timeout=4)
            except Exception:
                # Keep last-good bytes; the broker rejects them after 60 seconds.
                pass
            await asyncio.sleep(5)
    finally:
        await provider.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('/run/endpoint-support/leases.json'))
    args=parser.parse_args()
    asyncio.run(run(args.output))


if __name__=='__main__':
    main()
