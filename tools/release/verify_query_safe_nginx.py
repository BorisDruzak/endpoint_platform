#!/usr/bin/env python3
"""Isolated nginx callback-failure check using synthetic sentinels only.

Starts its own loopback process and ephemeral port; never touches live nginx,
application services, private logs, TLS files, or real authorization callbacks.
"""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from apply_query_safe_nginx import PROFILES, validate_asset


def verify(asset,site,*,nginx='nginx'):
    payload=Path(asset).read_bytes()
    validate_asset(payload,site)
    text=payload.decode('utf-8')
    format_name=PROFILES[site][1]
    format_directive=re.search(r'log_format '+format_name+r' escape=json\s+.*?;',text,re.S).group()
    callbacks=('/api/web/session/oidc/callback',) if site=='helpdesk' else ('/auth/admin/callback','/auth/employee/callback')
    sentinels=('callback-code-sentinel','callback-state-sentinel','callback-referer-sentinel')
    with tempfile.TemporaryDirectory(prefix='nginx-callback-hygiene-') as directory:
        root=Path(directory)
        with socket.socket() as available, socket.socket() as unavailable:
            available.bind(('127.0.0.1',0))
            port=available.getsockname()[1]
            unavailable.bind(('127.0.0.1',0))
            dead_port=unavailable.getsockname()[1]
            locations=[]
            for callback in callbacks:
                location=re.search(r'location = '+re.escape(callback)+r'\s*\{.*?\}',text,re.S).group()
                locations.append(re.sub(r'proxy_pass http://127\.0\.0\.1:\d+;',
                    f'proxy_pass http://127.0.0.1:{dead_port};',location))
            config=root/'nginx.conf'
            config.write_text('daemon off;\nmaster_process off;\npid '+str(root/'nginx.pid')+';\n'
                'error_log '+str(root/'error.log')+' error;\nevents {}\nhttp {\n'+format_directive+'\n'
                'access_log '+str(root/'access.log')+' '+format_name+';\n'
                'server { listen 127.0.0.1:'+str(port)+';\nlocation = /ready { return 204; }\n'
                +'\n'.join(locations)+'\n}\n}\n',encoding='utf-8')
            available.close()
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with (root/'process.log').open('wb') as output:
                process=subprocess.Popen([nginx,'-p',str(root)+'/', '-c',str(config)],
                    stdin=subprocess.DEVNULL,stdout=output,stderr=output)
                try:
                    for _ in range(100):
                        try:
                            with opener.open(f'http://127.0.0.1:{port}/ready',timeout=.2) as response:
                                if response.status==204:
                                    break
                        except (OSError,urllib.error.URLError):
                            if process.poll() is not None:
                                raise RuntimeError('Isolated nginx did not start') from None
                            time.sleep(.05)
                    else:
                        raise RuntimeError('Isolated nginx readiness timed out')
                    for callback in callbacks:
                        request=urllib.request.Request(f'http://127.0.0.1:{port}{callback}?code={sentinels[0]}&state={sentinels[1]}',
                            headers={'Referer':'https://sso.example.test/?value='+sentinels[2]})
                        try:
                            opener.open(request,timeout=3).close()
                        except urllib.error.HTTPError as error:
                            if error.code!=502:
                                raise RuntimeError('Unexpected isolated callback outcome') from None
                            error.read()
                        else:
                            raise RuntimeError('Expected isolated upstream failure')
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
        content='\n'.join(path.read_text(encoding='utf-8',errors='replace') for path in root.glob('*.log'))
        count=sum(content.count(value) for value in sentinels)
        if count:
            raise RuntimeError(f'Synthetic sentinel persisted; occurrence_count={count}')
        records=[json.loads(line) for line in (root/'access.log').read_text().splitlines()]
        for callback in callbacks:
            matches=[row for row in records if row.get('path')==callback and row.get('status')==502]
            if len(matches)!=1 or matches[0]['method']!='GET' or matches[0]['request_time']<0:
                raise RuntimeError('Missing safe callback outcome/metrics')
        return {'site':site,'failed_callbacks':len(callbacks),'sentinel_occurrences':0,
            'path_status_metrics_preserved':True,'live_services_touched':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asset',type=Path,required=True)
    parser.add_argument('--site',choices=tuple(PROFILES),required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.asset,args.site),sort_keys=True))


if __name__=='__main__':
    main()
