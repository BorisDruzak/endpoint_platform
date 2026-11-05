import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, request } from './api'

type Release = { id: string; version: string; artifact_name: string }
type Device = { id: string; display_name: string; hostname?: string | null }
type Policy = { revision: number; enabled: boolean; release_id: string | null; scope: 'all_active' | 'selected'; device_ids: string[]; max_parallel: number; reason: string; safe_code: string | null }
type Draft = Omit<Policy, 'revision' | 'safe_code'> & { expected_revision: number }
type Item = { device_id: string; display_name: string | null; status: string; safe_code: string; job_id?: string | null; policy_revision?: number }
type Status = { data: Policy; qualifications: Record<string, { source_foundation: string; expires_at: string }[]>; active_chains: number; decisions: Item[] }
type Preview = { read_only: boolean; counts: Record<string, number>; active_chains: number; available_slots: number; evaluated_count: number; truncated: boolean; data: Item[] }
const initial: Policy = { revision: 0, enabled: false, release_id: null, scope: 'all_active', device_ids: [], max_parallel: 1, reason: '', safe_code: null }
function draftOf(policy: Policy): Draft {
  return { expected_revision: policy.revision, enabled: policy.enabled, release_id: policy.release_id, scope: policy.scope, device_ids: policy.device_ids, max_parallel: policy.max_parallel, reason: policy.reason }
}
const reasons: Record<string, string> = {
  eligible: 'Готово к обновлению', already_current: 'Целевая или более новая Foundation уже установлена',
  waiting_reconnect: 'Ожидается свежее подключение WSS', platform_unknown: 'Платформа неизвестна; требуется новое подключение',
  waiting_setup_client: 'Ожидается готовый клиент установки', waiting_source_confirmation: 'Ожидается совпадение версий WSS и клиента установки',
  platform_unsupported: 'Другая платформа', source_unknown: 'Исходная версия неизвестна',
  source_unsupported: 'Исходная версия не поддерживается', source_not_qualified: 'Нет квалификации для исходной Foundation',
  native_recovery_required: 'Неизвестный результат Setup; сохранена блокировка восстановления',
  previous_attempt_requires_review: 'Предыдущая попытка требует разбора; повтор не запускается',
  active_operation: 'Устройство занято текущей операцией', capacity_full: 'Лимит занят текущими цепочками или удержаниями',
  policy_paused: 'Политика на паузе', fleet_failure_requires_review: 'Новые назначения остановлены после ошибки цепочки',
  canonical_request_rejected: 'Контроллер отклонил подготовку; требуется разбор',
  fleet_request_requires_review: 'Новые назначения остановлены: контроллер отклонил подготовку',
  target_not_product: 'Выберите полный выпуск продукта', outside_scope: 'Вне выбранной группы', chain_requested: 'Цепочка назначена',
}

export function SetupFleetPolicy({ canWrite, releases, devices, revision, renderCanary }: { canWrite: boolean; releases: Release[]; devices: Device[]; revision: number; renderCanary?: (releaseId: string, qualify: (assignmentId: string) => Promise<void>, busy: boolean, pinTarget: () => void) => ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [draft, setDraft] = useState<Draft>(() => draftOf(initial))
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const dirty = useRef(false)
  const generation = useRef(0)
  const loadedRevision = useRef(-1)
  useEffect(() => {
    let mounted = true
    let timer: ReturnType<typeof setTimeout>
    async function poll() {
      try {
        const result = await request<Status>('/api/admin/setup-updates/fleet')
        if (mounted) {
          setStatus(result)
          if (!dirty.current) {
            if (loadedRevision.current !== result.data.revision) {
              generation.current += 1; setPreview(null)
            }
            loadedRevision.current = result.data.revision
            setDraft(draftOf(result.data))
          }
        }
      } catch (e) { if (mounted) setError(e instanceof Error ? e.message : 'Не удалось получить политику') }
      finally { if (mounted) timer = setTimeout(poll, 10_000) }
    }
    void poll()
    return () => { mounted = false; clearTimeout(timer) }
  }, [revision])
  function change(update: Partial<Draft>) {
    generation.current += 1
    dirty.current = true; setDraft(current => ({ ...current, ...update })); setPreview(null); setNotice('')
  }
  const qualified = draft.release_id ? (status?.qualifications[draft.release_id]?.length ?? 0) > 0 : false
  const invalid = !draft.release_id || (draft.scope === 'selected' && draft.device_ids.length === 0)
  async function showPreview() {
    if (invalid) return
    setBusy(true); setError('')
    const currentGeneration = generation.current
    try {
      const result = await request<Preview>('/api/admin/setup-updates/fleet/preview', { method: 'POST', body: JSON.stringify({ release_id: draft.release_id, scope: draft.scope, device_ids: draft.device_ids, max_parallel: draft.max_parallel }) })
      if (currentGeneration === generation.current) setPreview(result)
    }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось получить предпросмотр') }
    finally { setBusy(false) }
  }
  async function qualify(assignmentId: string) {
    if (!canWrite || !draft.release_id || busy) return
    const currentGeneration = generation.current
    setBusy(true); setError(''); setNotice(''); setPreview(null)
    try {
      await request('/api/admin/setup-updates/fleet/qualifications', { method: 'POST', body: JSON.stringify({ release_id: draft.release_id, evidence_assignment_id: assignmentId }) })
      const result = await request<Status>('/api/admin/setup-updates/fleet')
      setStatus(result)
      if (currentGeneration === generation.current) setNotice('Сервер квалифицировал точный Setup и исходную Foundation по сохранённому результату. Политика не изменена.')
    } catch (e) { setError(e instanceof ApiError && e.status === 409 ? 'Результат не прошёл квалификацию: проверьте свежий нативный результат, подключение и датчик пользователя.' : e instanceof Error ? e.message : 'Не удалось квалифицировать выпуск') }
    finally { setBusy(false) }
  }
  async function save(event: FormEvent) {
    event.preventDefault(); if (!canWrite || busy) return
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await request<{ data: Policy }>('/api/admin/setup-updates/fleet', { method: 'PUT', body: JSON.stringify({ ...draft, reason: draft.reason.trim() }) })
      generation.current += 1; setPreview(null)
      dirty.current = false; setDraft(draftOf(result.data)); setStatus(current => current ? { ...current, data: result.data } : current)
      setNotice(result.data.enabled ? 'Политика сохранена. Новые цепочки будут назначаться автоматически.' : 'Политика сохранена на паузе. Новые цепочки не назначаются.')
    } catch (e) {
      setError(e instanceof ApiError && e.status === 409 ? 'Политика изменена другим администратором или выпуск больше не квалифицирован. Черновик сохранён; обновите состояние и проверьте настройки.' : e instanceof Error ? e.message : 'Не удалось сохранить политику')
    } finally { setBusy(false) }
  }
  async function reloadDraft() {
    setBusy(true); setError('')
    try {
      const result = await request<Status>('/api/admin/setup-updates/fleet')
      generation.current += 1
      setStatus(result); setDraft(draftOf(result.data)); dirty.current = false; setPreview(null)
      setNotice('Черновик заменён свежим состоянием сервера.')
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось обновить состояние') }
    finally { setBusy(false) }
  }
  const selectedMissing = draft.device_ids.filter(id => !devices.some(d => d.id === id))
  return <section className="panel setup-fleet-policy" aria-label="Автообновление Windows">
    <h3>Автообновление Windows полным Setup</h3>
    <p className="muted">После включения сервер обновляет подходящие Windows-устройства по выбранному выпуску. Отключённые устройства дождутся подключения. Уже установленная или более новая Foundation пропускается.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!status ? <p aria-live="polite">Получение политики…</p> : <>
      <p aria-live="polite">{status.data.enabled ? 'Включено' : 'На паузе'} · Версия политики: {status.data.revision} · Занято цепочек: {status.active_chains}</p>
      {status.data.safe_code && <p role="status">{reasons[status.data.safe_code] ?? status.data.safe_code}</p>}
      <h4>1. Выберите опубликованный полный Setup</h4>
      <p className="muted">Сборка и подпись выполняются по процедуре публикации. Один выбранный артефакт используется для теста и автоматического обновления.</p>
        <label>Целевой полный Setup<select value={draft.release_id ?? ''} disabled={!canWrite || busy} onChange={e => change({ release_id: e.target.value || null, enabled: false })}><option value="">Выберите выпуск</option>{releases.map(r => <option key={r.id} value={r.id}>{r.version} · {r.artifact_name}{status.qualifications[r.id]?.length ? ' · квалифицирован' : ' · без квалификации'}</option>)}</select></label>
        {draft.release_id && <p className="muted">Цель: {releases.find(r => r.id === draft.release_id)?.artifact_name ?? draft.release_id}{status.qualifications[draft.release_id]?.map(q => ` · исходная Foundation ${q.source_foundation} · квалификация до ${new Date(q.expires_at).toLocaleDateString('ru-RU')}`).join('')}</p>}
      {renderCanary?.(draft.release_id ?? '', qualify, busy, () => { dirty.current = true })}
      <form className="form-grid" onSubmit={save}>
        <h4 className="setup-step">4. Проверьте охват и лимит цепочек</h4>
        <label>Охват обновления<select value={draft.scope} disabled={!canWrite || busy} onChange={e => change({ scope: e.target.value as Draft['scope'], device_ids: [] })}><option value="all_active">Все активные Windows-устройства</option><option value="selected">Выбранная группа устройств</option></select></label>
        {draft.scope === 'selected' && <fieldset className="setup-fleet-selection"><legend>Устройства группы ({draft.device_ids.length})</legend><p className="muted">Список использует поиск устройств в шаге 2. Выбор сохраняется при поиске.</p>{devices.map(d => <label key={d.id}><input type="checkbox" checked={draft.device_ids.includes(d.id)} disabled={!canWrite || busy} onChange={e => change({ device_ids: e.target.checked ? [...draft.device_ids, d.id] : draft.device_ids.filter(i => i !== d.id) })} /> {d.hostname ? `${d.hostname} · ${d.display_name}` : d.display_name}</label>)}{selectedMissing.map(id => <label key={id}><input type="checkbox" checked disabled={!canWrite || busy} onChange={() => change({ device_ids: draft.device_ids.filter(i => i !== id) })} /> Выбрано: {id}</label>)}</fieldset>}
        <label>Одновременных цепочек<select value={draft.max_parallel} disabled={!canWrite || busy} onChange={e => change({ max_parallel: Number(e.target.value) })}><option value={1}>1</option><option value={2}>2</option></select></label>
        <p className="muted">Лимит включает полные цепочки Setup с подготовкой Core и удержания восстановления, в том числе ручные назначения Setup. Неизвестный результат установки сохраняет занятый слот.</p>
        {!qualified && <p className="muted">Нет действующей квалификации точного Setup и исходного профиля с работающим датчиком. Выполните одиночный тест и квалификацию выше.</p>}
        <div className="row-actions"><button type="button" disabled={busy || invalid} onClick={() => void showPreview()}>Предпросмотр охвата</button></div>
      {preview && <div aria-live="polite"><p>Предпросмотр без назначений · Проверено: {preview.evaluated_count} · Готовы: {preview.counts.eligible ?? 0} · Уже актуальны: {preview.counts.already_current ?? 0} · Ожидают: {preview.counts.waiting ?? 0} · Заблокированы: {preview.counts.blocked ?? 0} · Свободных слотов: {preview.available_slots}</p>{preview.truncated && <p>Показаны первые 500 устройств. Предпросмотр неполный; планировщик обрабатывает весь выбранный охват.</p>}<DecisionList items={preview.data} /></div>}
        <h4 className="setup-step">5. Сохраните постоянную политику</h4>
        {canWrite && <><label className="checkbox-label"><input type="checkbox" checked={draft.enabled} disabled={busy || (!qualified && !draft.enabled)} onChange={e => change({ enabled: e.target.checked })} /> Включить автоматическое обновление</label><label>Причина политики<input required maxLength={256} value={draft.reason} disabled={busy} onChange={e => change({ reason: e.target.value })} /></label></>}
        <div className="row-actions">{canWrite && <button className="primary" disabled={busy || !draft.reason.trim() || (draft.enabled && (invalid || !qualified))}>Сохранить политику</button>}<button type="button" disabled={busy} onClick={() => void reloadDraft()}>Сбросить изменения</button></div>
      </form>
      <h4>6. Контроль результатов и пауза</h4>
      <p className="muted">Для паузы снимите «Включить автоматическое обновление» и сохраните политику в шаге 5. Пауза останавливает новые назначения. Уже начатые цепочки продолжаются до проверяемого результата; автоматического повтора MSI нет.</p>
      {notice && <p role="status">{notice}</p>}

      {status.decisions.length > 0 && <><h4>Последние решения сервера</h4><DecisionList items={status.decisions} /></>}
    </>}
  </section>
}

function DecisionList({ items }: { items: Item[] }) {
  return <ul className="setup-fleet-decisions">{items.map((item, index) => <li key={`${item.device_id}-${item.policy_revision ?? index}`}><strong>{item.display_name ?? item.device_id}</strong> · {reasons[item.safe_code] ?? item.safe_code}{item.policy_revision !== undefined && ` · политика ${item.policy_revision}`}{item.job_id && <span className="muted"> · операция {item.job_id}</span>}</li>)}</ul>
}
