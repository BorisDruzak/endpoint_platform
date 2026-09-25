import { useEffect, useState, type FormEvent } from 'react'
import { request } from './api'

type PolicySummary = { id: string; name: string; created_at: string; versions_total: number }
type VersionSummary = { version_id: string; policy_version: number; digest: string; created_at: string }
type PolicyDocument = {
  schema_version: 'endpoint_policy_v1'; policy_id: string; policy_version: number
  activity: { enabled: boolean; idle_threshold_seconds: number; foreground_application: boolean; browser_context: boolean }
  dlp: { usb_device_events: 'disabled' | 'audit'; removable_write_events: 'disabled'; print_events: 'disabled' | 'audit'; browser_upload_events: 'disabled' | 'audit'; browser_paste_events: 'disabled' | 'audit' }
  browser_sensor: { required: boolean; deployment_mode: 'agent_managed' | 'external_managed' }
  event_retention: { security_event_days: number }
}
type VersionDetail = VersionSummary & { policy: PolicyDocument }
type DefaultAssignment = { policy_id: string; policy_version_id: string; policy_version: number; policy_name: string }
type Page<T> = { data: T[]; total: number; limit: number; offset: number }

const modeText = (value: 'disabled' | 'audit') => value === 'audit' ? 'Аудит' : 'Отключено'
const enabledText = (value: boolean) => value ? 'Включено' : 'Отключено'
const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))

export function PolicyCatalog() {
  const [policies, setPolicies] = useState<PolicySummary[]>([])
  const [defaultAssignment, setDefaultAssignment] = useState<DefaultAssignment | null>(null)
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null)
  const [versions, setVersions] = useState<VersionSummary[]>([])
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)
  const [preferredVersionId, setPreferredVersionId] = useState<string | null>(null)
  const [detail, setDetail] = useState<VersionDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [draft, setDraft] = useState<PolicyDocument | null>(null)
  const [draftMode, setDraftMode] = useState<'create' | 'version' | null>(null)
  const [newName, setNewName] = useState('')
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState('')
  const [actionError, setActionError] = useState('')
  const [revision, setRevision] = useState(0)
  const [catalogRevision, setCatalogRevision] = useState(0)
  const [deviceId, setDeviceId] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([
      request<Page<PolicySummary>>('/api/admin/console/policies?limit=50'),
      request<{ data: DefaultAssignment | null }>('/api/admin/console/policies/assignments/default'),
    ]).then(async ([page, assignment]) => {
      const activeSummary = assignment.data && !page.data.some(item => item.id === assignment.data?.policy_id)
        ? (await request<{ data: PolicySummary }>(`/api/admin/console/policies/${assignment.data.policy_id}`)).data
        : null
      if (!active) return
      const available = activeSummary ? [activeSummary, ...page.data] : page.data
      setPolicies(available)
      setDefaultAssignment(assignment.data)
      setSelectedPolicyId(available.find(item => item.id === assignment.data?.policy_id)?.id ?? available[0]?.id ?? null)
      setLoading(false)
    }).catch(() => { if (active) { setError('Не удалось загрузить политики'); setLoading(false) } })
    return () => { active = false }
  }, [catalogRevision])

  useEffect(() => {
    if (!selectedPolicyId) return
    let active = true
    setVersions([])
    setSelectedVersionId(null)
    setDetail(null)
    request<Page<VersionSummary>>(`/api/admin/console/policies/${selectedPolicyId}/versions?limit=50`)
      .then(page => {
        if (!active) return
        setVersions(page.data)
        setSelectedVersionId(page.data.find(item => item.version_id === preferredVersionId)?.version_id
          ?? page.data.find(item => item.version_id === defaultAssignment?.policy_version_id)?.version_id
          ?? page.data[0]?.version_id ?? null)
      })
      .catch(() => { if (active) setError('Не удалось загрузить версии политики') })
    return () => { active = false }
  }, [selectedPolicyId, revision])

  async function saveVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!draft || (draftMode === 'version' && !selectedPolicyId)) return
    setSaving(true); setActionError('')
    try {
      const response = await request<{ data: { policy_version: number; version_id: string } }>(
        draftMode === 'create' ? '/api/admin/console/policies'
          : `/api/admin/console/policies/${selectedPolicyId}/versions`,
        { method: 'POST', body: JSON.stringify(draftMode === 'create'
          ? { name: newName.trim(), policy: draft } : { policy: draft }) },
      )
      setDraft(null)
      setDraftMode(null)
      setNotice(draftMode === 'create' ? 'Политика создана' : `Версия ${response.data.policy_version} создана`)
      if (draftMode === 'create') { setPreferredVersionId(null); setCatalogRevision(value => value + 1) }
      else { setPreferredVersionId(response.data.version_id); setRevision(value => value + 1) }
    } catch {
      setActionError(draftMode === 'create' ? 'Не удалось создать политику' : 'Не удалось создать версию политики')
    } finally {
      setSaving(false)
    }
  }

  async function assignDefault() {
    if (!detail || !selectedPolicyId || !selectedPolicy) return
    setSaving(true); setActionError('')
    try {
      await request('/api/admin/console/policies/assignments/default', {
        method: 'PUT', body: JSON.stringify({ policy_version_id: detail.version_id }),
      })
      setDefaultAssignment({ policy_id: selectedPolicyId,
        policy_version_id: detail.version_id, policy_version: detail.policy_version,
        policy_name: selectedPolicy.name })
      setNotice('Политика назначена по умолчанию')
    } catch {
      setActionError('Не удалось назначить политику по умолчанию')
    } finally {
      setSaving(false)
    }
  }

  async function assignDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!detail) return
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(deviceId)) {
      setActionError('Укажите корректный ID устройства'); return
    }
    setSaving(true); setActionError('')
    try {
      await request(`/api/admin/console/policies/assignments/devices/${deviceId}`, {
        method: 'PUT', body: JSON.stringify({ policy_version_id: detail.version_id }),
      })
      setNotice('Политика назначена устройству')
      setDeviceId('')
    } catch {
      setActionError('Не удалось назначить политику устройству')
    } finally {
      setSaving(false)
    }
  }

  useEffect(() => {
    if (!selectedPolicyId || !selectedVersionId) return
    let active = true
    setDetail(null)
    request<{ data: VersionDetail }>(`/api/admin/console/policies/${selectedPolicyId}/versions/${selectedVersionId}`)
      .then(value => { if (active) setDetail(value.data) })
      .catch(() => { if (active) setError('Не удалось загрузить выбранную версию') })
    return () => { active = false }
  }, [selectedPolicyId, selectedVersionId])

  const selectedPolicy = policies.find(item => item.id === selectedPolicyId)
  const doc = detail?.policy
  function startNewPolicy() {
    setDraft({
      schema_version: 'endpoint_policy_v1', policy_id: crypto.randomUUID(), policy_version: 1,
      activity: { enabled: false, idle_threshold_seconds: 600, foreground_application: false, browser_context: false },
      browser_sensor: { required: false, deployment_mode: 'external_managed' },
      dlp: { usb_device_events: 'disabled', removable_write_events: 'disabled', print_events: 'disabled',
        browser_upload_events: 'disabled', browser_paste_events: 'disabled' },
      event_retention: { security_event_days: 30 },
    })
    setDraftMode('create'); setNewName(''); setNotice(''); setActionError('')
  }
  return <>
    <section className="panel"><h2>Активная политика</h2>
      {loading ? <p aria-live="polite">Загрузка политик…</p> : error ? <p role="alert">{error}</p> : policies.length === 0 ? <p>Политики ещё не созданы.</p> : <>
        <div className="filters">
          <label>Политика<select value={selectedPolicyId ?? ''} onChange={event => { setPreferredVersionId(null); setSelectedPolicyId(event.target.value) }}>{policies.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <label>Версия<select value={selectedVersionId ?? ''} onChange={event => { setPreferredVersionId(null); setSelectedVersionId(event.target.value) }}>{versions.map(item => <option key={item.version_id} value={item.version_id}>Версия {item.policy_version}</option>)}</select></label>
        </div>
        <dl className="detail-grid">
          <div><dt>Название</dt><dd>{selectedPolicy?.name ?? 'Нет данных'}</dd></div>
          <div><dt>Версия</dt><dd>{detail ? `Версия ${detail.policy_version}` : 'Загрузка…'}</dd></div>
          <div><dt>Создана</dt><dd>{detail ? dateText(detail.created_at) : 'Нет данных'}</dd></div>
          <div><dt>Состояние</dt><dd>{detail?.version_id === defaultAssignment?.policy_version_id ? 'По умолчанию' : 'Не назначена по умолчанию'}</dd></div>
        </dl>
        {detail && <button className="policy-action" disabled={detail.version_id !== versions[0]?.version_id} onClick={() => {
          setDraft({ ...detail.policy, policy_version: detail.policy_version + 1 })
          setDraftMode('version')
          setNotice(''); setActionError('')
        }}>Создать новую версию</button>}
        {detail && <button className="policy-action" disabled={saving || detail.version_id === defaultAssignment?.policy_version_id} onClick={assignDefault}>Сделать политикой по умолчанию</button>}
        {detail && <form onSubmit={assignDevice} className="filters policy-assign">
          <label>ID устройства<input value={deviceId} onChange={event => setDeviceId(event.target.value)} placeholder="UUID устройства" required /></label>
          <button type="submit" disabled={saving}>Назначить устройству</button>
        </form>}
        {actionError && !draft && <p role="alert">{actionError}</p>}
      </>}
      {!loading && !error && <button className="policy-action" onClick={startNewPolicy}>Создать политику</button>}
      {notice && <p role="status">{notice}</p>}
    </section>
    {draft && <section className="panel"><h2>{draftMode === 'create' ? 'Новая политика' : 'Новая версия политики'}</h2>
      <form onSubmit={saveVersion}>
        {draftMode === 'create' && <label>Название новой политики<input value={newName} onChange={event => setNewName(event.target.value)} minLength={1} maxLength={128} required /></label>}
        <div className="filters">
          <label>Активность<select value={String(draft.activity.enabled)} onChange={event => setDraft(value => value && ({ ...value, activity: { ...value.activity, enabled: event.target.value === 'true' } }))}><option value="true">Включено</option><option value="false">Отключено</option></select></label>
          <label>Порог бездействия, секунд<input type="number" min="60" max="3600" required value={draft.activity.idle_threshold_seconds} onChange={event => setDraft(value => value && ({ ...value, activity: { ...value.activity, idle_threshold_seconds: Number(event.target.value) } }))} /></label>
          <label>Приложение на переднем плане<select value={String(draft.activity.foreground_application)} onChange={event => setDraft(value => value && ({ ...value, activity: { ...value.activity, foreground_application: event.target.value === 'true' } }))}><option value="true">Включено</option><option value="false">Отключено</option></select></label>
          <label>Контекст браузера<select value={String(draft.activity.browser_context)} onChange={event => setDraft(value => value && ({ ...value, activity: { ...value.activity, browser_context: event.target.value === 'true' } }))}><option value="true">Включено</option><option value="false">Отключено</option></select></label>
          <label>Browser Sensor обязателен<select value={String(draft.browser_sensor.required)} onChange={event => setDraft(value => value && ({ ...value, browser_sensor: { ...value.browser_sensor, required: event.target.value === 'true' } }))}><option value="true">Да</option><option value="false">Нет</option></select></label>
          <label>Управление Browser Sensor<select value={draft.browser_sensor.deployment_mode} onChange={event => setDraft(value => value && ({ ...value, browser_sensor: { ...value.browser_sensor, deployment_mode: event.target.value as PolicyDocument['browser_sensor']['deployment_mode'] } }))}><option value="agent_managed">Endpoint Agent</option><option value="external_managed">Внешняя политика</option></select></label>
          <label>USB<select value={draft.dlp.usb_device_events} onChange={event => setDraft(value => value && ({ ...value, dlp: { ...value.dlp, usb_device_events: event.target.value as 'disabled' | 'audit' } }))}><option value="disabled">Отключено</option><option value="audit">Аудит</option></select></label>
          <label>Печать<select value={draft.dlp.print_events} onChange={event => setDraft(value => value && ({ ...value, dlp: { ...value.dlp, print_events: event.target.value as 'disabled' | 'audit' } }))}><option value="disabled">Отключено</option><option value="audit">Аудит</option></select></label>
          <label>Загрузка через браузер<select value={draft.dlp.browser_upload_events} onChange={event => setDraft(value => value && ({ ...value, dlp: { ...value.dlp, browser_upload_events: event.target.value as 'disabled' | 'audit' } }))}><option value="disabled">Отключено</option><option value="audit">Аудит</option></select></label>
          <label>Вставка в браузере<select value={draft.dlp.browser_paste_events} onChange={event => setDraft(value => value && ({ ...value, dlp: { ...value.dlp, browser_paste_events: event.target.value as 'disabled' | 'audit' } }))}><option value="disabled">Отключено</option><option value="audit">Аудит</option></select></label>
          <label>Хранение событий, дней<input type="number" min="7" max="365" required value={draft.event_retention.security_event_days} onChange={event => setDraft(value => value && ({ ...value, event_retention: { security_event_days: Number(event.target.value) } }))} /></label>
        </div>
        {actionError && <p role="alert">{actionError}</p>}
        <div className="pagination"><button type="button" onClick={() => { setDraft(null); setDraftMode(null) }}>Отмена</button><button type="submit" disabled={saving}>{saving ? 'Сохранение…' : draftMode === 'create' ? 'Сохранить политику' : 'Сохранить версию'}</button></div>
      </form>
    </section>}
    {doc && <div className="detail-columns">
      <section className="panel"><h2>Активность</h2><dl className="detail-grid">
        <div><dt>Сбор состояния</dt><dd>{enabledText(doc.activity.enabled)}</dd></div>
        <div><dt>Порог бездействия</dt><dd>{doc.activity.idle_threshold_seconds} сек.</dd></div>
        <div><dt>Приложение на переднем плане</dt><dd>{enabledText(doc.activity.foreground_application)}</dd></div>
        <div><dt>Контекст браузера</dt><dd>{enabledText(doc.activity.browser_context)}</dd></div>
      </dl></section>
      <section className="panel"><h2>Browser Sensor</h2><dl className="detail-grid">
        <div><dt>Обязателен</dt><dd>{doc.browser_sensor.required ? 'Да' : 'Нет'}</dd></div>
        <div><dt>Управление</dt><dd>{doc.browser_sensor.deployment_mode === 'agent_managed' ? 'Endpoint Agent' : 'Внешняя политика'}</dd></div>
      </dl></section>
      <section className="panel"><h2>DLP</h2><dl className="detail-grid">
        <div><dt>USB</dt><dd>{modeText(doc.dlp.usb_device_events)}</dd></div>
        <div><dt>Печать</dt><dd>{modeText(doc.dlp.print_events)}</dd></div>
        <div><dt>Загрузка через браузер</dt><dd>{modeText(doc.dlp.browser_upload_events)}</dd></div>
        <div><dt>Вставка в браузере</dt><dd>{modeText(doc.dlp.browser_paste_events)}</dd></div>
      </dl></section>
      <section className="panel"><h2>Хранение событий</h2><p>{doc.event_retention.security_event_days} дней</p></section>
    </div>}
  </>
}
