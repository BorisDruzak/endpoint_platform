import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { request } from './api'

type Campaign = {
  id: string; label: string | null; site: string | null; target_platform: string
  expires_at: string; max_uses: number; use_count: number; allowed_cidrs: string[]
  policy: { policy_id?: string; enrollment_mode?: string; allowed_installer_releases?: string[] }
  revoked_at: string | null; disabled_at: string | null
}
type EnrollmentRequest = {
  id: string; status: string; reason: string | null; platform: string; hostname: string
  manufacturer: string | null; model: string | null; serial: string | null; macs: string[]
  source_address: string; installer_release_id: string; selected_campaign_id: string | null
  device_id?: string | null; created_at: string; expires_at: string; decided_at?: string | null
}
type RequestPage = { data: EnrollmentRequest[]; total: number; limit: number; offset: number }
type SetupRelease = {
  id: string; version: string; agent_version: string; filename: string; setup_sha256: string
  msi_sha256: string; source_commit: string; msi_source_commit: string
  authenticode_status: string; authenticode_publisher: string | null
  msi_authenticode_status: string; msi_authenticode_publisher: string | null
  download_url: string; created_at: string; retired_at: string | null
}

const dateText = (value: string | null) => value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
const requestLabels: Record<string, string> = {
  created: 'Создан', validating: 'Проверяется', auto_approved: 'Одобрен автоматически', approved: 'Одобрен вручную',
  waiting_approval: 'Ожидает подтверждения', review_required: 'Требует проверки',
  claim_issued: 'Claim сформирован', enrolling: 'Регистрируется', device_registered: 'Устройство зарегистрировано',
  waiting_wss: 'Ожидает WSS', completed: 'Завершён', denied: 'Отклонён', expired: 'Истёк', failed: 'Ошибка',
}
const lifecycle = [
  'Запуск установщика', 'Проверка текущего состояния', 'Установка MSI', 'Запрос регистрации',
  'Правило AUTO или решение оператора', 'Provisioning', 'Запуск службы EndpointAgent',
  'Подключение Gateway WSS', 'Сбор Device Context', 'Готово',
]

const requestQueues = [
  { id: 'pending', title: 'Ожидают подтверждения' },
  { id: 'review', title: 'Требуют проверки' },
  { id: 'active', title: 'В процессе' },
  { id: 'denied', title: 'Отклонены' },
  { id: 'completed', title: 'Завершены' },
  { id: 'failed', title: 'Ошибки и истёкшие' },
  { id: 'other', title: 'Другие состояния' },
] as const

const enrollmentStages = [
  { label: 'Создан', statuses: ['created'] },
  { label: 'Проверен', statuses: ['validating'] },
  { label: 'Одобрен или ожидает решения', statuses: ['auto_approved', 'approved', 'waiting_approval', 'review_required'] },
  { label: 'Разрешение сформировано', statuses: ['claim_issued'] },
  { label: 'Регистрация устройства', statuses: ['enrolling', 'device_registered'] },
  { label: 'Ожидание подключения WSS', statuses: ['waiting_wss'] },
  { label: 'Завершено', statuses: ['completed'] },
] as const

function RequestQueue({ title, page, busy, onOpen, onDecide, onMove }: {
  title: string; page: RequestPage; busy: boolean
  onOpen: (item: EnrollmentRequest) => void
  onDecide: (item: EnrollmentRequest, decision: 'approve' | 'deny') => void
  onMove: (offset: number) => void
}) {
  const { data: rows, total, limit, offset } = page
  return <section className="panel">
    <div className="table-top"><h2>{title}</h2><span>{total} заявок</span></div>
    {rows.length ? <div className="table-scroll"><table>
      <thead><tr><th>Устройство</th><th>Состояние</th><th>Адрес</th><th>Установщик</th><th>Создан</th><th>Действия</th></tr></thead>
      <tbody>{rows.map(item => <tr key={item.id}>
        <td><strong>{item.hostname}</strong><small>{item.manufacturer} {item.model}</small></td>
        <td>{requestLabels[item.status] ?? item.status}</td>
        <td>{item.source_address}</td><td>{item.installer_release_id}</td><td>{dateText(item.created_at)}</td>
        <td><button onClick={() => onOpen(item)}>Подробнее</button>{['waiting_approval', 'review_required'].includes(item.status) && <><button disabled={busy} onClick={() => onDecide(item, 'approve')}>Одобрить</button><button disabled={busy} onClick={() => onDecide(item, 'deny')}>Отклонить</button></>}</td>
      </tr>)}</tbody>
    </table></div> : <p className="muted">Заявок нет.</p>}
    <div className="pagination"><button disabled={offset === 0} onClick={() => onMove(Math.max(0, offset - limit))}>Назад</button><span>{total ? `${offset + 1}–${Math.min(offset + limit, total)}` : '0'} из {total}</span><button disabled={offset + limit >= total} onClick={() => onMove(offset + limit)}>Далее</button></div>
  </section>
}

export function EnrollmentPage() {
  const [searchParams] = useSearchParams()
  const [tab, setTab] = useState('installer')
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [queuePages, setQueuePages] = useState<Record<string, RequestPage>>({})
  const [queueOffsets, setQueueOffsets] = useState<Record<string, number>>({})
  const [queuesLoaded, setQueuesLoaded] = useState(false)
  const [queueError, setQueueError] = useState('')
  const [releases, setReleases] = useState<SetupRelease[]>([])
  const [summary, setSummary] = useState<{ status: string; enrollment_mode: string | null; label: string | null } | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [revision, setRevision] = useState(0)
  const [selected, setSelected] = useState<EnrollmentRequest | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Campaign | null>(null)
  const [label, setLabel] = useState('')
  const [site, setSite] = useState('')
  const [mode, setMode] = useState('manual')
  const [policyId, setPolicyId] = useState('windows-office-v1')
  const [networks, setNetworks] = useState('')
  const [allowedVersions, setAllowedVersions] = useState<string[]>([])
  const [expires, setExpires] = useState('')
  const [maxUses, setMaxUses] = useState(100)

  useEffect(() => {
    let active = true
    Promise.all([
      request<{ campaigns: Campaign[] }>('/api/admin/enrollment/campaigns'),
      request<{ status: string; enrollment_mode: string | null; label: string | null }>('/api/admin/enrollment/windows-summary'),
      request<{ data: SetupRelease[] }>('/api/admin/console/installer/releases'),
    ]).then(([campaignList, currentSummary, releaseList]) => {
      if (!active) return
      setCampaigns(campaignList.campaigns)
      setSummary(currentSummary)
      setReleases(releaseList.data)
      setError('')
      setLoaded(true)
    }).catch(reason => { if (active) { setError(reason.message); setLoaded(true) } })
    return () => { active = false }
  }, [revision])
  useEffect(() => {
    if (tab !== 'requests') return
    let active = true
    setQueuesLoaded(false)
    setQueueError('')
    Promise.all(requestQueues.map(async queue => {
      const offset = queueOffsets[queue.id] ?? 0
      const page = await request<RequestPage>(`/api/admin/console/enrollment/requests?queue=${queue.id}&limit=50&offset=${offset}`)
      return [queue.id, page] as const
    })).then(entries => {
      if (!active) return
      setQueuePages(Object.fromEntries(entries))
      setQueuesLoaded(true)
    }).catch(reason => {
      if (!active) return
      setQueueError(reason instanceof Error ? reason.message : 'Очереди регистрации загрузить не удалось')
      setQueuesLoaded(true)
    })
    return () => { active = false }
  }, [tab, revision, queueOffsets])
  useEffect(() => {
    const open = searchParams.get('open')
    if (!open) return
    let active = true
    setTab('requests')
    request<{ data: EnrollmentRequest }>(`/api/admin/console/enrollment/requests/${open}`)
      .then(value => { if (active) setSelected(value.data) })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Запрос не удалось открыть') })
    return () => { active = false }
  }, [searchParams])

  function startCreate() {
    setEditing(null); setLabel(''); setSite(''); setMode('manual'); setPolicyId('windows-office-v1')
    setNetworks(''); setAllowedVersions([]); setExpires(''); setMaxUses(100); setFormOpen(true)
  }
  function startEdit(campaign: Campaign) {
    setEditing(campaign); setLabel(campaign.label ?? ''); setSite(campaign.site ?? '')
    setMode(campaign.policy.enrollment_mode ?? 'manual'); setPolicyId(campaign.policy.policy_id ?? 'windows-office-v1')
    setNetworks(campaign.allowed_cidrs.join(', ')); setAllowedVersions(campaign.policy.allowed_installer_releases ?? [])
    setExpires(new Date(campaign.expires_at).toISOString().slice(0, 16)); setMaxUses(campaign.max_uses); setFormOpen(true)
  }
  async function saveCampaign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const body = {
        label, site: site || null, target_platform: 'windows', expires_at: new Date(expires).toISOString(),
        max_uses: maxUses, allowed_cidrs: networks.split(',').map(value => value.trim()).filter(Boolean),
        policy: { policy_id: policyId, enrollment_mode: mode, allowed_installer_releases: allowedVersions },
      }
      if (editing) {
        const { target_platform: _, ...changes } = body
        void _
        await request(`/api/admin/enrollment/campaigns/${editing.id}`, { method: 'PATCH', body: JSON.stringify(changes) })
      }
      else await request('/api/admin/console/campaigns', { method: 'POST', body: JSON.stringify(body) })
      setFormOpen(false); setRevision(value => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Кампанию сохранить не удалось') }
    finally { setBusy(false) }
  }
  async function revokeCampaign(campaign: Campaign) {
    if (!window.confirm(`Отозвать кампанию «${campaign.label ?? campaign.id}»?`)) return
    setBusy(true); setError('')
    try { await request(`/api/admin/enrollment/campaigns/${campaign.id}/revoke`, { method: 'POST' }); setRevision(value => value + 1) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Кампанию отозвать не удалось') }
    finally { setBusy(false) }
  }
  async function decide(item: EnrollmentRequest, decision: 'approve' | 'deny') {
    const action = decision === 'approve' ? 'Одобрить' : 'Отклонить'
    if (!window.confirm(`${action} регистрацию ${item.hostname}?`)) return
    setBusy(true); setError('')
    try {
      await request(`/api/admin/enrollment/requests/${item.id}/${decision}`, {
        method: 'POST', ...(decision === 'deny' ? { body: JSON.stringify({ reason: 'OPERATOR_DENIED' }) } : {}),
      })
      setRevision(value => value + 1); setSelected(null)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Решение не сохранено') }
    finally { setBusy(false) }
  }
  async function openRequest(item: EnrollmentRequest) {
    setError('')
    try {
      const detail = await request<{ data: EnrollmentRequest }>(`/api/admin/console/enrollment/requests/${item.id}`)
      setSelected(detail.data)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Запрос не удалось открыть') }
  }
  const latest = releases.find(item => !item.retired_at)
  const knownVersions = [...new Set(releases.filter(item => !item.retired_at && item.authenticode_status === 'valid' && item.msi_authenticode_status === 'valid').map(item => item.version))]
  if (editing) for (const version of editing.policy.allowed_installer_releases ?? []) if (!knownVersions.includes(version)) knownVersions.push(version)
  const selectedStageIndex = selected ? enrollmentStages.findIndex(stage => (stage.statuses as readonly string[]).includes(selected.status)) : -1
  return <>
    <div className="page-heading"><div><p className="eyebrow">РАЗВЁРТЫВАНИЕ</p><h1>Установка и регистрация</h1><p className="muted">Установщик Windows, кампании и запросы устройств</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <nav className="tabs" aria-label="Разделы установки"><button className={tab === 'installer' ? 'selected' : ''} onClick={() => setTab('installer')}>Установщик</button><button className={tab === 'campaigns' ? 'selected' : ''} onClick={() => setTab('campaigns')}>Кампании</button><button className={tab === 'requests' ? 'selected' : ''} onClick={() => setTab('requests')}>Запросы регистрации</button></nav>
    {error && <div className="panel error" role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></div>}
    {!loaded && <p aria-live="polite">Загрузка регистрации…</p>}
    {loaded && !error && tab === 'installer' && <div className="detail-columns"><section className="panel"><h2>Endpoint Agent для Windows</h2>{latest ? <><div className="installer-facts"><div><span>Версия агента</span><strong>{latest.agent_version}</strong></div><div><span>Версия установщика</span><strong>{latest.version}</strong></div><div><span>Файл</span><strong>{latest.filename}</strong></div><div><span>SHA-256 Setup</span><code>{latest.setup_sha256}</code></div><div><span>SHA-256 MSI</span><code>{latest.msi_sha256}</code></div><div><span>Подпись</span><strong>{latest.authenticode_status === 'valid' && latest.msi_authenticode_status === 'valid' ? 'Подпись проверена' : 'Только для тестирования'}</strong></div><div><span>Издатель</span><strong>{latest.authenticode_publisher ?? '—'}</strong></div><div><span>Ревизия исходного кода</span><code>{latest.source_commit}</code></div></div><div className="action-row"><a className="primary-button" href={latest.download_url}>Скачать установщик</a><button onClick={() => navigator.clipboard.writeText(`${latest.filename} --quiet`)}>Копировать команду тихой установки</button></div></> : <p className="muted">Установочный релиз ещё не опубликован. Данные версии и ссылка появятся после регистрации проверенного Setup.</p>}</section><section className="panel"><h2>Как проходит установка</h2><ol className="lifecycle">{lifecycle.map(step => <li key={step}>{step}</li>)}</ol></section></div>}
    {loaded && !error && tab === 'campaigns' && <><div className="page-heading"><div><h2>Кампании Windows</h2><p className="muted">{summary?.status === 'single_active_campaign' ? `Активная кампания: ${summary.label ?? 'без названия'} · ${summary.enrollment_mode?.toUpperCase()}` : summary?.status === 'ambiguous_active_campaigns' ? 'Несколько активных кампаний: требуется устранить неоднозначность' : 'Активной кампании нет'}</p></div><button onClick={startCreate}>Создать кампанию</button></div>{formOpen && <form className="panel campaign-form" onSubmit={saveCampaign}><h2>{editing ? 'Изменить кампанию' : 'Новая кампания'}</h2><label>Название<input required value={label} onChange={event => setLabel(event.target.value)} maxLength={256} /></label><label>Площадка<input value={site} onChange={event => setSite(event.target.value)} maxLength={128} /></label><label>Режим<select value={mode} onChange={event => setMode(event.target.value)}><option value="auto">AUTO</option><option value="manual">MANUAL</option></select></label><label>ID политики<input required value={policyId} onChange={event => setPolicyId(event.target.value)} /></label><label>Разрешённые сети CIDR<input required value={networks} onChange={event => setNetworks(event.target.value)} placeholder="192.168.100.0/24" /></label><label>Допустимые установщики<div className="version-options">{knownVersions.length ? knownVersions.map(version => <label key={version}><input type="checkbox" checked={allowedVersions.includes(version)} onChange={event => setAllowedVersions(previous => event.target.checked ? [...previous, version] : previous.filter(item => item !== version))} />{version}</label>) : <span className="muted">Сначала зарегистрируйте установочный релиз.</span>}</div></label><label>Действует до<input required type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></label><label>Максимум установок<input required type="number" min={1} value={maxUses} onChange={event => setMaxUses(Number(event.target.value))} /></label><div className="action-row"><button type="submit" className="primary-button" disabled={busy || !allowedVersions.length}>Сохранить</button><button type="button" onClick={() => setFormOpen(false)}>Отмена</button></div></form>}<div className="card-grid">{campaigns.filter(item => item.target_platform === 'windows').map(campaign => <article className="panel" key={campaign.id}><h2>{campaign.label ?? campaign.id}</h2><p><strong>{campaign.revoked_at ? 'Отозвана' : campaign.disabled_at ? 'Отключена' : new Date(campaign.expires_at) < new Date() ? 'Истекла' : 'Активна'}</strong> · {campaign.policy.enrollment_mode?.toUpperCase() ?? 'Режим не задан'}</p><dl className="simple-facts"><dt>Сети</dt><dd>{campaign.allowed_cidrs.join(', ')}</dd><dt>Установщики</dt><dd>{campaign.policy.allowed_installer_releases?.join(', ') ?? '—'}</dd><dt>Использовано</dt><dd>{campaign.use_count} / {campaign.max_uses}</dd><dt>Действует до</dt><dd>{dateText(campaign.expires_at)}</dd></dl><div className="action-row"><button onClick={() => startEdit(campaign)}>Изменить</button>{!campaign.revoked_at && <button onClick={() => revokeCampaign(campaign)} disabled={busy}>Отозвать</button>}</div></article>)}</div>{!campaigns.length && <p className="muted">Кампаний пока нет.</p>}</>}
    {loaded && !error && tab === 'requests' && <div className="request-queues">
      {queueError && <div className="panel error" role="alert">{queueError} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></div>}
      {!queuesLoaded && <p aria-live="polite">Загрузка очередей регистрации…</p>}
      {queuesLoaded && !queueError && requestQueues.map(queue => {
        const page = queuePages[queue.id]
        if (!page || (queue.id === 'other' && page.total === 0)) return null
        return <RequestQueue key={queue.id} title={queue.title} page={page} busy={busy}
          onOpen={openRequest} onDecide={decide}
          onMove={offset => setQueueOffsets(current => ({ ...current, [queue.id]: offset }))}
        />
      })}
    </div>}
    {selected && <div className="dialog-backdrop" role="presentation" onClick={() => setSelected(null)}>
      <section className="dialog panel" role="dialog" aria-modal="true" aria-label="Запрос регистрации" onClick={event => event.stopPropagation()}>
        <button className="dialog-close" onClick={() => setSelected(null)}>Закрыть</button>
        <h2>{selected.hostname}</h2><p>{requestLabels[selected.status] ?? selected.status}</p>
        <h3>Этапы регистрации</h3>
        <ol className="lifecycle">{enrollmentStages.map((stage, index) => <li key={stage.label} aria-current={selectedStageIndex === index ? 'step' : undefined}>
          {stage.label}{selectedStageIndex === index && <strong> · Текущий этап</strong>}
        </li>)}</ol>
        <h3>Решение оператора</h3>
        <p>{selected.status === 'denied' ? 'Регистрация отклонена' : selected.decided_at ? 'Решение принято' : selected.status === 'auto_approved' ? 'Одобрено автоматически' : 'Ожидается'}</p>
        <dl className="simple-facts"><dt>Производитель</dt><dd>{selected.manufacturer ?? '—'}</dd><dt>Модель</dt><dd>{selected.model ?? '—'}</dd><dt>Серийный номер</dt><dd>{selected.serial ?? '—'}</dd><dt>MAC</dt><dd>{selected.macs.join(', ') || '—'}</dd><dt>IP</dt><dd>{selected.source_address}</dd><dt>Установщик</dt><dd>{selected.installer_release_id}</dd><dt>Кампания</dt><dd>{selected.selected_campaign_id ?? '—'}</dd><dt>Причина</dt><dd>{selected.reason ?? '—'}</dd><dt>Создан</dt><dd>{dateText(selected.created_at)}</dd><dt>Решение принято</dt><dd>{dateText(selected.decided_at ?? null)}</dd><dt>ID устройства</dt><dd>{selected.device_id ?? '—'}</dd></dl>
        {selected.device_id && <Link to={`/admin/devices/${selected.device_id}`}>Открыть зарегистрированное устройство</Link>}
      </section>
    </div>}
  </>
}
