import { useEffect, useState, type FormEvent } from 'react'
import { request } from './api'

type Release = { id: string; version: string }
type Device = { id: string; display_name: string }
type Client = { client_version: string; core_version: string | null; foundation_version: string | null; ready: boolean; last_seen_at: string }
type Job = { id: string; release_id: string; status: string; reason: string; safe_code?: string | null; updated_at: string; last_report?: { proof?: { soak?: { sensor_cpu_percent_max: number; duration_seconds: number } } } }
type State = { client: Client | null; data: Job[] }
const labels: Record<string, string> = { recovery_required: 'Требуется восстановление', preparing_client: 'Подготовка клиента', restoring_core: 'Подготовка полного Setup', assigned: 'Назначено', downloading: 'Загрузка', verified: 'Проверено перед установкой', installing: 'Установка', verifying: 'Проверка после перезапуска', applied: 'Установлено и проверено', already_current: 'Уже установлено', blocked: 'Требуется разбор', failed: 'Ошибка', cancelled: 'Отменено', rolled_back: 'Выполнен откат' }
const cancellable = ['preparing_client', 'restoring_core', 'assigned', 'downloading', 'verified']
const active = [...cancellable, 'installing', 'verifying', 'recovery_required']

export function FullSetupPage({ canWrite, initialDevice = '', revision }: { canWrite: boolean; initialDevice?: string; revision: number }) {
  const [releases, setReleases] = useState<Release[]>([])
  const [devices, setDevices] = useState<Device[]>([])
  const [device, setDevice] = useState(initialDevice)
  const [release, setRelease] = useState('')
  const [reason, setReason] = useState('')
  const [search, setSearch] = useState('')
  const [state, setState] = useState<State | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    let mounted = true
    Promise.all([request<{ data: Release[] }>('/api/admin/setup-updates/releases'), request<{ data: Device[] }>(`/api/admin/console/devices?${new URLSearchParams({ limit: '100', platform: 'windows', search })}`)])
      .then(([r, d]) => { if (mounted) { setReleases(r.data); setDevices(d.data) } })
      .catch(e => { if (mounted) setError(e.message) })
    return () => { mounted = false }
  }, [search, revision])
  useEffect(() => {
    if (!device) return
    let mounted = true
    let timer: ReturnType<typeof setTimeout>
    setState(null)
    async function poll() {
      try { const result = await request<State>(`/api/admin/setup-updates/devices/${device}`); if (mounted) setState(result) }
      catch (e) { if (mounted) setError(e instanceof Error ? e.message : 'Не удалось получить состояние') }
      finally { if (mounted) timer = setTimeout(poll, 10_000) }
    }
    void poll()
    return () => { mounted = false; clearTimeout(timer) }
  }, [device, revision, refresh])
  async function assign(event: FormEvent) {
    event.preventDefault(); if (!release || !device || !reason.trim()) return
    setBusy(true); setError('')
    try { await request('/api/admin/setup-updates/assignments', { method: 'POST', body: JSON.stringify({ release_id: release, device_id: device, reason: reason.trim() }) }); setRefresh(v => v + 1) }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось назначить обновление') }
    finally { setBusy(false) }
  }
  async function cancel(job: Job) {
    setBusy(true); setError('')
    try { await request(`/api/admin/setup-updates/assignments/${job.id}/cancel`, { method: 'POST' }); setRefresh(v => v + 1) }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось отменить задание') }
    finally { setBusy(false) }
  }
  const fresh = state?.client && Date.now() - Date.parse(state.client.last_seen_at) <= 600_000
  return <section className="panel" aria-label="Обновление полным Setup">
    <h2>Полный Setup Windows</h2><p className="muted">Установка и проверка выполняются автоматически на выбранном устройстве. Существующие учётные данные и регистрация сохраняются.</p>
    {error && <p role="alert" className="error">{error}</p>}
    <form className="form-grid" onSubmit={assign}>
      <label>Поиск устройства<input value={search} onChange={e => setSearch(e.target.value)} /></label>
      <label>Устройство<select value={device} onChange={e => { setDevice(e.target.value); setState(null) }}><option value="">Выберите Windows-устройство</option>{devices.map(d => <option key={d.id} value={d.id}>{d.display_name}</option>)}{device && !devices.some(d => d.id === device) && <option value={device}>Выбранное устройство</option>}</select></label>
      <label>Полный Setup<select value={release} onChange={e => setRelease(e.target.value)}><option value="">Выберите выпуск</option>{releases.map(r => <option key={r.id} value={r.id}>{r.version}</option>)}</select></label>
      {device && !state && <p aria-live="polite">Получение состояния…</p>}
      {state && <p aria-live="polite">{state.client ? `Core ${state.client.core_version ?? 'неизвестен'} · Foundation ${state.client.foundation_version ?? 'неизвестен'} · ${fresh ? state.client.ready ? 'клиент готов' : 'клиент ожидает завершения текущей операции' : 'нет свежего ответа клиента'}` : 'Клиент будет подготовлен автоматически, если исходная версия поддерживается.'}</p>}
      {canWrite && <><label>Причина<input required maxLength={256} value={reason} onChange={e => setReason(e.target.value)} /></label><div><button className="primary" disabled={busy || !state || !device || !release || !reason.trim() || state.data.some(j => active.includes(j.status))}>Обновить полным Setup</button></div></>}
    </form>
    {state?.data.map(job => <article className="panel" key={job.id}><h3>{labels[job.status] ?? job.status} · {releases.find(r => r.id === job.release_id)?.version ?? 'Setup'}</h3><p>{job.reason}</p><p className="muted">{new Date(job.updated_at).toLocaleString('ru-RU')}</p>{job.last_report?.proof?.soak && <p>Проверка {Math.round(job.last_report.proof.soak.duration_seconds)} с · CPU датчика, максимум {job.last_report.proof.soak.sensor_cpu_percent_max}%</p>}{job.safe_code && ['failed', 'blocked', 'rolled_back', 'recovery_required'].includes(job.status) && <p>Код диагностики: {job.safe_code}</p>}{canWrite && cancellable.includes(job.status) && <><button disabled={busy} onClick={() => void cancel(job)}>Отменить следующие этапы</button><p className="muted">Уже начатый этап подготовки Core может завершиться.</p></>}</article>)}
    {state && state.data.length === 0 && <p className="empty-text">Обновления полным Setup ещё не назначены.</p>}
  </section>
}
