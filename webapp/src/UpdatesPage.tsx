import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { request } from './api'

type Build = {
  id: string; build_identifier: string; version: string; platform: string; channel: string
  sha256: string; size: number; artifact_name: string; release_notes: string | null; created_at: string
}
type Rollout = {
  id: string; rollout_identifier: string; build_id: string; build_identifier: string
  version: string; platform: string; mode: string; status: string; reason: string | null
  created_at: string; started_at: string | null; paused_at: string | null
  completed_at: string | null; cancelled_at: string | null; counts: Record<string, number>
}
type Target = { device_id: string; device_name: string; status: string; assigned_at: string; terminal_at: string | null; safe_reason: string | null }
type RolloutDetail = Rollout & { targets: Target[]; targets_total: number; target_limit: number; target_offset: number }
type Device = { id: string; display_name: string; device_identifier: string; platform: string | null; online: boolean }

const dateText = (value: string | null) => value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
const statuses: Record<string, string> = {
  draft: 'Черновик', active: 'Активно', paused: 'Приостановлено', completed: 'Завершено', cancelled: 'Отменено',
  assigned: 'Назначено', requested: 'Запрошено', scheduled: 'Запланировано', applied: 'Применено',
  failed: 'Ошибка', rolled_back: 'Откат выполнен',
}
const modes: Record<string, string> = { canary: 'Канареечное', bulk: 'Массовое', rollback: 'Откат' }
const platforms: Record<string, string> = { windows_amd64: 'Windows', linux_amd64: 'ALT Linux' }

export function UpdatesPage({ canWrite }: { canWrite: boolean }) {
  const [searchParams] = useSearchParams()
  const [tab, setTab] = useState('builds')
  const [builds, setBuilds] = useState<Build[]>([])
  const [rollouts, setRollouts] = useState<Rollout[]>([])
  const [totalBuilds, setTotalBuilds] = useState(0)
  const [totalRollouts, setTotalRollouts] = useState(0)
  const [buildOffset, setBuildOffset] = useState(0)
  const [rolloutOffset, setRolloutOffset] = useState(0)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [revision, setRevision] = useState(0)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [detail, setDetail] = useState<RolloutDetail | null>(null)
  const [targetOffset, setTargetOffset] = useState(0)
  const [wizard, setWizard] = useState(false)
  const [mode, setMode] = useState<'canary' | 'bulk' | 'rollback'>('canary')
  const [trigger, setTrigger] = useState<Rollout | null>(null)
  const [buildId, setBuildId] = useState('')
  const [reason, setReason] = useState('')
  const [search, setSearch] = useState('')
  const [candidates, setCandidates] = useState<Device[]>([])
  const [selected, setSelected] = useState<Record<string, Device>>({})
  const [busy, setBusy] = useState(false)
  useEffect(() => { const open = searchParams.get('open'); if (open) { setTab('rollouts'); setDetailId(open) } }, [searchParams])

  useEffect(() => {
    let active = true
    Promise.all([
      request<{ data: Build[]; total: number }>(`/api/admin/updates/builds?limit=50&offset=${buildOffset}`),
      request<{ data: Rollout[]; total: number }>(`/api/admin/updates/rollouts?limit=50&offset=${rolloutOffset}`),
    ]).then(([buildPage, rolloutPage]) => {
      if (!active) return
      setBuilds(buildPage.data); setTotalBuilds(buildPage.total)
      setRollouts(rolloutPage.data); setTotalRollouts(rolloutPage.total)
      setLoaded(true); setError('')
    }).catch(reason => { if (active) { setError(reason.message); setLoaded(true) } })
    return () => { active = false }
  }, [revision, buildOffset, rolloutOffset])

  useEffect(() => {
    if (!detailId) return
    let active = true
    request<RolloutDetail>(`/api/admin/updates/rollouts/${detailId}?limit=50&offset=${targetOffset}`)
      .then(value => { if (active) setDetail(value) })
      .catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [detailId, targetOffset, revision])

  const chosenBuild = builds.find(item => item.id === buildId)
  useEffect(() => {
    if (!wizard || !chosenBuild) return
    let active = true
    const platform = chosenBuild.platform === 'windows_amd64' ? 'windows' : 'linux'
    const query = new URLSearchParams({ limit: '100', platform, search })
    request<{ data: Device[] }>(`/api/admin/console/devices?${query.toString()}`)
      .then(value => { if (active) setCandidates(value.data) })
      .catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [wizard, chosenBuild?.id, search])

  function openWizard(nextMode: 'canary' | 'bulk' | 'rollback', source: Rollout | null = null) {
    setMode(nextMode); setTrigger(source); setBuildId(''); setReason(''); setSearch('')
    setSelected({}); setCandidates([]); setWizard(true); setError('')
  }
  function toggleDevice(device: Device) {
    setSelected(previous => {
      const next = { ...previous }
      if (next[device.id]) delete next[device.id]; else next[device.id] = device
      return next
    })
  }
  async function createRollout(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!chosenBuild || Object.keys(selected).length === 0) return
    const chosen = Object.values(selected)
    const summary = mode === 'rollback' ? `Откат с ${trigger?.version} на ${chosenBuild.version}` : `${modes[mode]}: ${chosenBuild.version}`
    if (!window.confirm(`${summary}\nУстройств: ${chosen.length}\n${chosen.map(item => item.display_name).join(', ')}`)) return
    setBusy(true); setError('')
    try {
      const body = {
        schema_version: 'update_rollout_v1', build_identifier: chosenBuild.build_identifier,
        mode, device_ids: chosen.map(item => item.id), reason: reason.trim() || null,
      }
      const path = mode === 'rollback' ? `/api/admin/updates/rollouts/${trigger?.id}/rollback` : '/api/admin/updates/rollouts'
      const created = await request<{ id: string }>(path, { method: 'POST', body: JSON.stringify(body) })
      setWizard(false); setTab('rollouts'); setDetailId(created.id); setTargetOffset(0)
      setRevision(value => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Развёртывание создать не удалось') }
    finally { setBusy(false) }
  }
  async function transition(action: 'pause' | 'activate') {
    if (!detail || !window.confirm(`${action === 'pause' ? 'Приостановить' : 'Продолжить'} развёртывание ${detail.version}?`)) return
    setBusy(true); setError('')
    try { await request(`/api/admin/updates/rollouts/${detail.id}/${action}`, { method: 'POST' }); setRevision(value => value + 1) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Состояние обновить не удалось') }
    finally { setBusy(false) }
  }
  return <>
    <div className="page-heading"><div><p className="eyebrow">ОБНОВЛЕНИЯ</p><h1>Релизы и обновления</h1><p className="muted">Неизменяемые сборки и состояние развёртывания</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <nav className="tabs" aria-label="Разделы обновлений"><button className={tab === 'builds' ? 'selected' : ''} onClick={() => setTab('builds')}>Релизы агента</button><button className={tab === 'rollouts' ? 'selected' : ''} onClick={() => setTab('rollouts')}>Развёртывания</button><button className={tab === 'history' ? 'selected' : ''} onClick={() => setTab('history')}>История</button></nav>
    {error && <div className="panel error" role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></div>}
    {!loaded && <p aria-live="polite">Загрузка обновлений…</p>}
    {loaded && tab === 'builds' && <section className="panel table-panel"><div className="table-top"><h2>Релизы агента</h2><span>{totalBuilds} всего</span></div>{builds.length ? <div className="table-scroll"><table><thead><tr><th>Версия</th><th>Платформа</th><th>Канал</th><th>Артефакт</th><th>SHA-256</th><th>Размер</th><th>Создан</th></tr></thead><tbody>{builds.map(build => <tr key={build.id}><td><strong>{build.version}</strong><small>{build.release_notes ?? ''}</small></td><td>{platforms[build.platform] ?? build.platform}</td><td>{build.channel}</td><td>{build.artifact_name}</td><td><code>{build.sha256}</code></td><td>{(build.size / 1024 ** 2).toFixed(1)} МБ</td><td>{dateText(build.created_at)}</td></tr>)}</tbody></table></div> : <p className="empty-text">Релизы ещё не зарегистрированы.</p>}<div className="pagination"><button disabled={buildOffset === 0} onClick={() => setBuildOffset(Math.max(0, buildOffset - 50))}>Назад</button><span>{Math.min(buildOffset + 50, totalBuilds)} из {totalBuilds}</span><button disabled={buildOffset + 50 >= totalBuilds} onClick={() => setBuildOffset(buildOffset + 50)}>Далее</button></div></section>}
    {loaded && tab === 'rollouts' && <><div className="page-heading"><div><h2>Развёртывания</h2><p className="muted">{totalRollouts} всего</p></div>{canWrite && <div className="action-row"><button onClick={() => openWizard('canary')}>Создать канареечное обновление</button><button onClick={() => openWizard('bulk')}>Массовое обновление</button></div>}</div><div className="card-grid">{rollouts.map(rollout => <article className="panel" key={rollout.id}><h2>{rollout.version} · {modes[rollout.mode] ?? rollout.mode}</h2><p>{statuses[rollout.status] ?? rollout.status} · {platforms[rollout.platform] ?? rollout.platform}</p><p className="muted">Создано: {dateText(rollout.created_at)}</p><p className="muted">Применено: {rollout.counts.applied ?? 0} · Ошибки: {rollout.counts.failed ?? 0} · В работе: {(rollout.counts.assigned ?? 0) + (rollout.counts.requested ?? 0) + (rollout.counts.scheduled ?? 0)}</p><button onClick={() => { setDetailId(rollout.id); setTargetOffset(0) }}>Открыть</button></article>)}</div>{!rollouts.length && <p className="muted">Развёртываний пока нет.</p>}<div className="pagination"><button disabled={rolloutOffset === 0} onClick={() => setRolloutOffset(Math.max(0, rolloutOffset - 50))}>Назад</button><span>{Math.min(rolloutOffset + 50, totalRollouts)} из {totalRollouts}</span><button disabled={rolloutOffset + 50 >= totalRollouts} onClick={() => setRolloutOffset(rolloutOffset + 50)}>Далее</button></div></>}
    {loaded && tab === 'history' && <section className="panel"><h2>История развёртываний</h2>{rollouts.filter(item => ['completed', 'cancelled'].includes(item.status)).length ? <ul className="change-list">{rollouts.filter(item => ['completed', 'cancelled'].includes(item.status)).map(item => <li key={item.id}><button onClick={() => setDetailId(item.id)}>{item.version} · {modes[item.mode] ?? item.mode}</button><span>{statuses[item.status] ?? item.status} · {dateText(item.completed_at ?? item.cancelled_at)}</span></li>)}</ul> : <p className="muted">В текущей странице нет завершённых развёртываний.</p>}</section>}
    {detailId && detail && <div className="dialog-backdrop" role="presentation" onClick={() => { setDetailId(null); setDetail(null) }}><section className="dialog panel rollout-dialog" role="dialog" aria-modal="true" aria-label="Развёртывание" onClick={event => event.stopPropagation()}><button className="dialog-close" onClick={() => { setDetailId(null); setDetail(null) }}>Закрыть</button><h2>{detail.version} · {modes[detail.mode] ?? detail.mode}</h2><p>{statuses[detail.status] ?? detail.status}</p><dl className="simple-facts"><dt>Создано</dt><dd>{dateText(detail.created_at)}</dd><dt>Начато</dt><dd>{dateText(detail.started_at)}</dd><dt>Завершено</dt><dd>{dateText(detail.completed_at)}</dd><dt>Причина</dt><dd>{detail.reason ?? '—'}</dd>{Object.entries(detail.counts).map(([status, count]) => <div key={status} className="fact-pair"><dt>{statuses[status] ?? status}</dt><dd>{count}</dd></div>)}</dl>{canWrite && <div className="action-row">{detail.status === 'active' && <button disabled={busy} onClick={() => transition('pause')}>Приостановить</button>}{detail.status === 'paused' && <button disabled={busy} onClick={() => transition('activate')}>Продолжить</button>}{['active', 'paused', 'completed'].includes(detail.status) && <button onClick={() => { openWizard('rollback', detail); setDetailId(null); setDetail(null) }}>Создать откат</button>}</div>}<h3>Устройства · {detail.targets_total}</h3><ul className="change-list">{detail.targets.map(target => <li key={target.device_id}><Link to={`/admin/devices/${target.device_id}`}>{target.device_name}</Link><span>{statuses[target.status] ?? target.status}{target.safe_reason ? ` · ${target.safe_reason}` : ''}</span></li>)}</ul><div className="pagination"><button disabled={targetOffset === 0} onClick={() => setTargetOffset(Math.max(0, targetOffset - 50))}>Назад</button><span>{Math.min(targetOffset + 50, detail.targets_total)} из {detail.targets_total}</span><button disabled={targetOffset + 50 >= detail.targets_total} onClick={() => setTargetOffset(targetOffset + 50)}>Далее</button></div></section></div>}
    {wizard && <div className="dialog-backdrop" role="presentation" onClick={() => setWizard(false)}><form className="dialog panel rollout-dialog" role="dialog" aria-modal="true" aria-label="Новое развёртывание" onClick={event => event.stopPropagation()} onSubmit={createRollout}><button className="dialog-close" type="button" onClick={() => setWizard(false)}>Закрыть</button><h2>{mode === 'rollback' ? `Откат с ${trigger?.version} на другую версию` : mode === 'bulk' ? 'Массовое обновление' : 'Канареечное обновление'}</h2><label className="form-field">Релиз<select required value={buildId} onChange={event => { setBuildId(event.target.value); setSelected({}) }}><option value="">Выберите релиз</option>{builds.filter(item => !trigger || item.platform === trigger.platform).map(item => <option key={item.id} value={item.id}>{item.version} · {platforms[item.platform] ?? item.platform}</option>)}</select></label><label className="form-field">Причина<input value={reason} onChange={event => setReason(event.target.value)} required={mode === 'rollback'} maxLength={512} /></label>{chosenBuild && <><label className="form-field">Найти устройство<input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Имя устройства" /></label><div className="candidate-list">{candidates.map(device => <label key={device.id}><input type="checkbox" checked={Boolean(selected[device.id])} onChange={() => toggleDevice(device)} />{device.display_name} <small>{device.device_identifier}</small></label>)}</div><h3>Точный список устройств ({Object.keys(selected).length})</h3><ul className="selected-list">{Object.values(selected).map(device => <li key={device.id}>{device.display_name} <button type="button" onClick={() => toggleDevice(device)}>Убрать</button></li>)}</ul></>}<div className="action-row"><button className="primary-button" type="submit" disabled={busy || !chosenBuild || !Object.keys(selected).length}>Создать развёртывание</button><button type="button" onClick={() => setWizard(false)}>Отмена</button></div></form></div>}
  </>
}
