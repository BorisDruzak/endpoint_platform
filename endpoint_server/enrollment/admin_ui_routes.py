"""Small browser surface for administrator-managed Windows enrollment."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from endpoint_server.auth.admin_sessions import (
    ADMIN_SESSION_COOKIE,
    AdminPrincipal,
    require_admin,
)
from endpoint_server.auth.csrf import csrf_token_for_session


router = APIRouter(tags=["admin-enrollment-ui"])


def _page(csrf_token: str) -> str:
    """Return a dependency-free UI that only calls the protected API contract."""
    csrf = json.dumps(csrf_token)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Endpoint Admin / Enrollment</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px}}fieldset,section{{margin:1rem 0;padding:1rem}}input,select,button{{margin:.25rem;padding:.4rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #bbb;padding:.4rem;text-align:left}}#error{{color:#a00}}</style>
</head><body><h1>Endpoint Admin / Enrollment</h1>
<p id="summary">Loading Windows campaign configuration…</p><p id="error" role="alert"></p>
<section><h2>Create Windows campaign</h2><form id="campaign-form">
<label>Label <input name="label" required maxlength="256"></label>
<label>Mode <select name="mode"><option value="auto">AUTO</option><option value="manual">MANUAL</option></select></label>
<label>Policy ID <input name="policy_id" value="windows-office-v1" required></label>
<label>Allowed releases <input name="releases" placeholder="3.2.44" required></label>
<label>Allowed CIDRs <input name="cidrs" placeholder="192.168.100.0/24" required></label>
<label>Expires <input name="expires_at" type="datetime-local" required></label>
<label>Max uses <input name="max_uses" type="number" min="1" value="100" required></label>
<button type="submit">Create campaign</button></form></section>
<section><h2>Windows campaigns</h2><table><thead><tr><th>Label</th><th>Mode</th><th>Releases</th><th>CIDRs</th><th>Uses</th><th>Expires</th></tr></thead><tbody id="campaigns"></tbody></table></section>
<section><h2>New agents</h2><table><thead><tr><th>Hostname</th><th>Platform</th><th>Manufacturer / model</th><th>Serial</th><th>MAC</th><th>Source IP</th><th>Release</th><th>Reason</th><th>Created</th><th>Actions</th></tr></thead><tbody id="requests"></tbody></table></section>
<script>
const csrf = {csrf};
const headers = {{'Content-Type':'application/json','X-CSRF-Token':csrf}};
const error = document.getElementById('error');
const cell = (row, value) => {{ const td=document.createElement('td'); td.textContent=value ?? ''; row.append(td); }};
async function api(path, options={{}}) {{ const response=await fetch(path,{{credentials:'same-origin',...options,headers:{{...headers,...(options.headers||{{}})}}}}); if (!response.ok) throw new Error(await response.text()); return response.status===204 ? null : response.json(); }}
function campaignRow(c) {{ const row=document.createElement('tr'); const p=c.policy||{{}}; cell(row,c.label||c.id); cell(row,p.enrollment_mode||'invalid'); cell(row,(p.allowed_installer_releases||[]).join(', ')); cell(row,(c.allowed_cidrs||[]).join(', ')); cell(row,`${{c.use_count}} / ${{c.max_uses}}`); cell(row,c.expires_at); return row; }}
function requestRow(r) {{ const row=document.createElement('tr'); cell(row,r.hostname); cell(row,r.platform); cell(row,[r.manufacturer,r.model].filter(Boolean).join(' / ')); cell(row,r.serial); cell(row,(r.macs||[]).join(', ')); cell(row,r.source_address); cell(row,r.installer_release_id); cell(row,r.reason||r.status); cell(row,r.created_at); const td=document.createElement('td'); for (const [label, path, body] of [['Approve',`/api/admin/enrollment/requests/${{r.id}}/approve`,null],['Deny',`/api/admin/enrollment/requests/${{r.id}}/deny`,{{reason:'OPERATOR_DENIED'}}]]) {{ const button=document.createElement('button'); button.type='button'; button.textContent=label; button.onclick=async()=>{{ try {{ await api(path,{{method:'POST',body:body?JSON.stringify(body):undefined}}); await load(); }} catch(e) {{ error.textContent='Enrollment action failed.'; }} }}; td.append(button); }} row.append(td); return row; }}
async function load() {{ try {{ error.textContent=''; const [summary,campaigns,requests]=await Promise.all([api('/api/admin/enrollment/windows-summary'),api('/api/admin/enrollment/campaigns'),api('/api/admin/enrollment/requests')]); document.getElementById('summary').textContent=summary.status==='single_active_campaign' ? `Windows enrollment: ${{summary.enrollment_mode.toUpperCase()}} via campaign “${{summary.label||summary.campaign_id}}”` : `Windows enrollment: ${{summary.status}}`; const campaignBody=document.getElementById('campaigns'); campaignBody.replaceChildren(...campaigns.campaigns.filter(c=>c.target_platform==='windows').map(campaignRow)); const requestBody=document.getElementById('requests'); requestBody.replaceChildren(...requests.requests.filter(r=>['waiting_approval','review_required'].includes(r.status)).map(requestRow)); }} catch(e) {{ error.textContent='Unable to load Enrollment administration.'; }} }}
document.getElementById('campaign-form').onsubmit=async event=>{{ event.preventDefault(); const form=new FormData(event.currentTarget); const list=name=>form.get(name).split(',').map(value=>value.trim()).filter(Boolean); const local=form.get('expires_at'); const body={{expires_at:new Date(local).toISOString(),max_uses:Number(form.get('max_uses')),allowed_cidrs:list('cidrs'),target_platform:'windows',label:form.get('label'),policy:{{policy_id:form.get('policy_id'),enrollment_mode:form.get('mode'),allowed_installer_releases:list('releases')}}}}; try {{ await api('/api/admin/enrollment/campaigns',{{method:'POST',body:JSON.stringify(body)}}); event.currentTarget.reset(); await load(); }} catch(e) {{ error.textContent='Campaign was not created.'; }} }};
load();
</script></body></html>"""


@router.get("/admin/enrollment", response_class=HTMLResponse)
async def enrollment_admin_page(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> HTMLResponse:
    """Serve the authenticated page; mutation still passes existing CSRF checks."""
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    return HTMLResponse(
        _page(csrf_token_for_session(session_token, request.app.state.settings.session_secret)),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
