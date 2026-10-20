import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'
import { ApiError, request } from './api'
import { categoryLabels, duration, stateLabels, type ActivityState, type AnalyticsMetrics,
  type AnalyticsOverview, type AnalyticsTimeline, type AnalyticsUser, type TimelineSegment } from './activityAnalyticsApi'

const prefix = '/api/admin/console/activity-analytics'
const states = Object.keys(stateLabels) as ActivityState[]
const stamp = (value: string | null, timezone: string) => value
  ? new Intl.DateTimeFormat('ru-RU', { timeZone: timezone, dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value)) : '—'
const coverage = (metrics: AnalyticsMetrics | null) => metrics?.coverage == null ? '—' : `${Math.round(metrics.coverage * 100)}%`

function Metrics({ value }: { value: AnalyticsMetrics | null }) {
  return <>
    <div className="metric-grid analytics-metrics">
      {states.map(state => <div className="metric-card" key={state}><span>{stateLabels[state]}</span>
        <strong>{duration(value?.observed_span_seconds ? value.seconds[state] : null)}</strong></div>)}
    </div>
    <p className="muted">Полнота данных: {coverage(value)}. Период наблюдения: {duration(value?.observed_span_seconds || null)}.
      {' '}Это промежуток между первым и последним наблюдением, включая внутренние пропуски, без предположений о длительности рабочего дня.</p>
    {value?.pending && <p role="status" className="analytics-note">Дневные итоги ожидают пересчёта worker’ом. Показаны последние рассчитанные значения.</p>}
    {!!value?.overlap_seconds && <p className="analytics-note">Пересечение устройств: {duration(value.overlap_seconds)}.
      {' '}Время учтено один раз, приоритет ACTIVE → IDLE → LOCKED → DISCONNECTED → UNKNOWN. Приложение выбрано по стабильному порядку устройств.
      {' '}Протокол не различает все параллельные интерактивные сеансы; распределение этого времени по приложениям неоднозначно.</p>}
  </>
}

function Timeline({ value }: { value: AnalyticsTimeline }) {
  const [selected, setSelected] = useState<TimelineSegment | null>(null)
  const start = Date.parse(value.started_at), length = Date.parse(value.ended_at) - start
  const position = (from: string, to: string) => ({ left: `${(Date.parse(from) - start) / length * 100}%`, width: `${(Date.parse(to) - Date.parse(from)) / length * 100}%` })
  const device = (id: string | null) => value.devices.find(d => d.id === id)?.name ?? 'Без привязки к устройству'
  return <>
    <div className="analytics-legend">{states.map(state => <span key={state}><i className={`activity-color activity-${state}`} />{state}</span>)}</div>
    <div className="analytics-timeline" aria-label="Временная шкала активности">
      {value.data.map((segment, index) => <button key={index} className={`activity-segment activity-${segment.state}`}
        style={position(segment.started_at, segment.ended_at)}
        title={`${stateLabels[segment.state]} · ${stamp(segment.started_at, value.timezone)} — ${stamp(segment.ended_at, value.timezone)} · ${duration(segment.seconds)} · ${segment.process_name ?? 'Приложение неизвестно'} · ${device(segment.device_id)}`}
        aria-label={`${segment.state} ${segment.process_name ?? ''} ${stamp(segment.started_at, value.timezone)}`}
        onClick={() => setSelected(segment)} />)}
    </div>
    <div className="analytics-scale">{[0, 1, 2, 3, 4].map(index => <span key={index}>{index === 4 ? '24:00'
      : new Intl.DateTimeFormat('ru-RU', { timeZone: value.timezone, hour: '2-digit', minute: '2-digit' })
        .format(new Date(start + length * index / 4))}</span>)}</div>
    {selected && <div className="analytics-selection" aria-live="polite">
      <strong>{stateLabels[selected.state]}</strong> · {stamp(selected.started_at, value.timezone)} — {stamp(selected.ended_at, value.timezone)} · {duration(selected.seconds)}
      <p>{selected.process_name ?? 'Приложение неизвестно'} · {device(selected.device_id)}</p>
      {!selected.attributed && <p>За пределами подтверждённого наблюдения. Время не приписано сотруднику.</p>}
      {selected.overlap && <p>Есть пересечение устройств; выбран один интервал без двойного учёта.</p>}
    </div>}
    <p className="muted">Нажмите сегмент или выберите его с клавиатуры для подробностей. Светлый остаток шкалы — ещё не наступившее время.</p>
    {!!value.connection_gaps.length && <div className="analytics-connections"><h3>Нет соединения WSS с устройством</h3>
      {value.connection_gaps.map((gap, index) => <p key={index}>{device(gap.device_id)} · {stamp(gap.started_at, value.timezone)} — {stamp(gap.ended_at, value.timezone)}</p>)}
      <p className="muted">Подтверждено историей Gateway. Это состояние транспорта устройства, оно не доказывает отсутствие сотрудника.</p>
    </div>}
  </>
}

export function ActivityAnalyticsPage() {
  const [params, setParams] = useSearchParams()
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null)
  const [user, setUser] = useState<AnalyticsUser | null>(null)
  const [timeline, setTimeline] = useState<AnalyticsTimeline | null>(null)
  const [error, setError] = useState(''), [timelineError, setTimelineError] = useState('')
  const [loading, setLoading] = useState(true), [revision, setRevision] = useState(0)
  const daysGrid = useRef<HTMLDivElement>(null)
  const selected = params.get('user_key')
  const reportParams = new URLSearchParams()
  for (const name of ['period', 'since', 'until', 'timezone']) {
    const value = params.get(name)
    if (value) reportParams.set(name, value)
  }
  const reportQuery = reportParams.toString()
  const listQuery = new URLSearchParams(reportParams)
  for (const name of ['search', 'sort', 'offset']) {
    const value = params.get(name)
    if (value) listQuery.set(name, value)
  }
  const query = selected ? `${reportQuery}&user_key=${encodeURIComponent(selected)}` : listQuery.toString()
  const meta = (selected ? user : overview)?.meta
  const day = params.get('day') ?? meta?.until ?? ''

  useEffect(() => {
    const grid = daysGrid.current
    const button = grid?.querySelector<HTMLElement>('[aria-pressed="true"]')
    if (grid && button) grid.scrollTop = button.offsetTop
  }, [selected, day, user?.meta.since, user?.meta.until])

  useEffect(() => {
    let active = true
    const controller = new AbortController()
    setLoading(true)
    const path = selected ? 'user' : 'overview'
    request<AnalyticsOverview | AnalyticsUser>(`${prefix}/${path}?${query}`, { signal: controller.signal })
      .then(value => {
        if (!active) return
        if (selected) setUser(value as AnalyticsUser); else setOverview(value as AnalyticsOverview)
        setError('')
      }).catch(reason => { if (active) setError(reason instanceof ApiError && reason.status === 422
        ? 'Проверьте даты, часовой пояс и допустимый срок истории.' : reason instanceof Error ? reason.message : 'Не удалось загрузить аналитику') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false; controller.abort() }
  }, [selected, query, revision])

  useEffect(() => {
    const timer = window.setInterval(() => setRevision(value => value + 1), 30_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    setTimelineError('')
    if (!selected || !day || !meta || day < meta.detail_available_from || day < meta.since || day > meta.until) return
    let active = true
    const controller = new AbortController()
    request<AnalyticsTimeline>(`${prefix}/timeline?user_key=${encodeURIComponent(selected)}&day=${day}&timezone=${encodeURIComponent(meta.timezone)}`, { signal: controller.signal })
      .then(value => { if (active) setTimeline(value) })
      .catch(reason => { if (active) setTimelineError(reason instanceof ApiError && reason.status === 410
        ? 'Подробные интервалы удалены по retention. Дневные итоги сохранены.' : 'Не удалось загрузить временную шкалу.') })
    return () => { active = false; controller.abort() }
  }, [selected, day, meta?.timezone, meta?.since, meta?.until, meta?.detail_available_from, revision])

  function change(values: Record<string, string | null>, reset = true) {
    const next = new URLSearchParams(params)
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value); else next.delete(key)
    }
    if (reset) { next.delete('offset'); next.delete('day') }
    if (next.toString() === params.toString()) return
    const dayOnly = Object.keys(values).every(key => key === 'day')
    if (!dayOnly) { setOverview(null); setUser(null); setError(''); setLoading(true) }
    setTimeline(null)
    setParams(next)
  }
  const period = params.get('period') ?? 'today'
  const measured = selected ? user?.data.metrics : null

  return <div className="activity-analytics">
    <div className="page-heading"><div><p className="eyebrow">ACTIVITY SENSOR</p><h1>Аналитика активности</h1>
      <p className="muted">Наблюдения сеанса и ввода. ACTIVE не доказывает производительность или выполнение служебных задач.</p></div>
      <button onClick={() => setRevision(value => value + 1)} disabled={loading}>Обновить</button></div>
    <div className="filters panel">
      <label>Период<select value={period} onChange={event => change({ period: event.target.value,
        since: event.target.value === 'custom' ? meta?.since ?? null : null,
        until: event.target.value === 'custom' ? meta?.until ?? null : null })}>
        <option value="today">Сегодня</option><option value="yesterday">Вчера</option><option value="7d">7 дней</option>
        <option value="30d">30 дней</option><option value="custom">Произвольный</option></select></label>
      {period === 'custom' && <>
        <label>С<input type="date" min={meta?.aggregate_available_from} max={meta?.today} value={params.get('since') ?? ''}
          onChange={event => change({ since: event.target.value })} /></label>
        <label>По<input type="date" min={params.get('since') ?? meta?.aggregate_available_from} max={meta?.today} value={params.get('until') ?? ''}
          onChange={event => change({ until: event.target.value })} /></label>
      </>}
      <label>Часовой пояс<select value={params.get('timezone') ?? meta?.timezone ?? 'Asia/Yekaterinburg'}
        onChange={event => change({ timezone: event.target.value })}>
        {(meta?.timezones ?? ['Asia/Yekaterinburg', 'UTC']).map(zone => <option key={zone}>{zone}</option>)}</select></label>
      {!selected && <>
        <label>Поиск<input placeholder="Сотрудник или компьютер" value={params.get('search') ?? ''} onChange={event => change({ search: event.target.value })} /></label>
        <label>Сортировка<select value={params.get('sort') ?? 'active'} onChange={event => change({ sort: event.target.value })}>
          <option value="active">По активному времени</option><option value="last_observed">По последнему наблюдению</option>
          <option value="state">По текущему состоянию</option><option value="user">По сотруднику</option></select></label>
      </>}
    </div>
    {error && <div className="state-inline"><p role="alert" className="error">{error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить</button></div>}
    {loading && <p role="status">Обновление данных…</p>}
    {meta && <p className="muted">{meta.since} — {meta.until} · {meta.timezone} · Статусы обновляются каждые 30 с, дневные итоги — worker’ом.
      {' '}Граница достоверности наблюдений: {meta.max_gap_seconds} с.</p>}
    {meta && !meta.collection_enabled && <p className="analytics-note">Подсистема политик сейчас отключена. История доступна; новые наблюдения требуют включённого Activity Sensor и подтверждённой применённой политики.</p>}
    {!selected && overview && <>
      <div className="metric-grid analytics-metrics">{[
        ['Актуальное состояние', 'fresh'], ['Активны', 'active'], ['IDLE', 'idle'], ['LOCKED / DISCONNECTED', 'locked_disconnected'], ['Нет данных / устарели', 'unknown'],
      ].map(([label, key]) => <div className="metric-card" key={key}><span>{label}</span><strong>{overview.summary[key]}</strong></div>)}</div>
      <section className="panel table-panel"><div className="table-top"><h2>Сотрудники и устройства</h2><span>{overview.total} записей</span></div>
        <p className="analytics-note">Учётные записи Windows/AD. Подключение устройства ONLINE показано независимо от активности сотрудника.
          {' '}Для ALT Linux и старых агентов без Activity измерения недоступны.</p>
        <div className="table-scroll"><table><thead><tr>{['Сотрудник', 'Устройство', 'Текущее состояние', 'Последняя активность', 'Активное время', 'Бездействие', 'Основное приложение', 'Полнота данных'].map(text => <th key={text}>{text}</th>)}</tr></thead>
          <tbody>{overview.data.map(row => <tr key={row.user_key ?? row.devices[0].id} className={row.user_key ? 'analytics-employee-row' : ''}
            onClick={event => { if (row.user_key && !(event.target as HTMLElement).closest('button')) change({ user_key: row.user_key }, false) }}>
            <td>{row.user_key ? <button className="text-button" onClick={() => change({ user_key: row.user_key }, false)}>{row.user_login}</button> : 'Учётная запись неизвестна'}
              {row.reason && <small>{row.reason}</small>}</td>
            <td>{row.devices.map(device => <div key={device.id}>{device.name}<small>{device.online ? 'ONLINE' : 'OFFLINE'}</small></div>)}</td>
            <td><span className={`analytics-state activity-${row.state}`}>{row.state}</span>{!row.fresh && <small>Нет актуального наблюдения</small>}</td>
            <td>{stamp(row.last_observed_at, overview.meta.timezone)}</td>
            <td>{duration(row.metrics?.observed_span_seconds ? row.metrics.seconds.ACTIVE : null)}</td>
            <td>{duration(row.metrics?.observed_span_seconds ? row.metrics.seconds.IDLE : null)}</td>
            <td>{row.metrics?.applications[0]?.label ?? '—'}</td>
            <td>{coverage(row.metrics)}{row.metrics?.pending && <small>Ожидается пересчёт</small>}{!!row.metrics?.overlap_seconds && <small>Пересечение устройств</small>}</td>
          </tr>)}</tbody></table></div>
        {!overview.data.length && <p className="analytics-note">За выбранный период записи не найдены.</p>}
        <div className="pagination"><button disabled={overview.offset === 0} onClick={() => change({ offset: String(Math.max(0, overview.offset - overview.limit)) }, false)}>Назад</button>
          <span>{overview.total ? overview.offset + 1 : 0}–{Math.min(overview.offset + overview.limit, overview.total)} из {overview.total}</span>
          <button disabled={overview.offset + overview.limit >= overview.total} onClick={() => change({ offset: String(overview.offset + overview.limit) }, false)}>Далее</button></div>
      </section>
    </>}
    {selected && <button className="text-button" onClick={() => change({ user_key: null, day: null }, false)}>К таблице</button>}
    {selected && user && <>
      <section className="panel analytics-detail"><h2>{user.data.user_login}</h2><p>Текущее состояние: {user.data.state}. Последний обнаруженный сеанс: {stamp(user.data.last_observed_at, user.meta.timezone)}.</p>
        <p>Устройства: {user.data.devices.map(d => `${d.name} (${d.online ? 'ONLINE' : 'OFFLINE'})`).join(', ')}</p>
        <p className="muted">Связь с сотрудником подтверждается OS-учётной записью. Имена из разных доменов не объединяются; учётные записи без домена привязаны к устройству.</p>
        <p className="muted">Источник передаёт один наблюдаемый сеанс на устройство. Полный учёт параллельных интерактивных сеансов не гарантирован.</p>
        <Metrics value={measured ?? null} />
      </section>
      <section className="panel analytics-detail"><h2>Динамика по дням</h2><div className="analytics-days" ref={daysGrid} aria-label="Дни отчёта">
        {user.daily.map(item => <button key={item.day} aria-pressed={day === item.day} disabled={!item.timeline_available}
          title={item.timeline_available ? 'Открыть временную шкалу' : 'Подробные интервалы удалены по retention'} onClick={() => change({ day: item.day }, false)}>
          <span>{item.day}</span><div className="analytics-day-bar">
            <i className="activity-ACTIVE" style={{ width: `${item.metrics?.observed_span_seconds ? item.metrics.seconds.ACTIVE / item.metrics.observed_span_seconds * 100 : 0}%` }} />
            <i className="activity-IDLE" style={{ width: `${item.metrics?.observed_span_seconds ? item.metrics.seconds.IDLE / item.metrics.observed_span_seconds * 100 : 0}%` }} /></div>
          <small>ACTIVE {duration(item.metrics?.observed_span_seconds ? item.metrics.seconds.ACTIVE : null)} · IDLE {duration(item.metrics?.observed_span_seconds ? item.metrics.seconds.IDLE : null)}</small>
          {!item.timeline_available && <small>Только дневной итог</small>}
        </button>)}
      </div></section>
      <section className="panel analytics-detail"><div className="analytics-section-heading"><h2>Временная шкала</h2>
        <label>День<input type="date" min={user.meta.since} max={user.meta.until} value={day} onChange={event => change({ day: event.target.value }, false)} /></label></div>
        {day < user.meta.detail_available_from ? <p>Подробные интервалы удалены по retention. Доступны дневные итоги.</p>
          : day < user.meta.since || day > user.meta.until ? <p>Выберите день внутри периода отчёта.</p>
            : timelineError ? <p role="alert" className="error">{timelineError}</p> : timeline ? <Timeline key={`${selected}:${day}:${timeline.timezone}`} value={timeline} /> : <p role="status">Загрузка шкалы…</p>}
      </section>
      <section className="panel analytics-detail"><h2>Приложения</h2><p className="muted">Только подтверждённый foreground при ACTIVE. Browser Sensor не требуется для учёта времени браузера.</p>
        {measured?.applications.length ? <div className="analytics-apps">{measured.applications.map(app => <div key={`${app.label}:${app.category}`}>
          <span>{app.label}<small>{categoryLabels[app.category] ?? app.category}</small></span><strong>{duration(app.seconds)}</strong>
          <progress aria-label={app.label} max={measured.seconds.ACTIVE || 1} value={app.seconds} /></div>)}</div> : <p>Подтверждённого активного времени приложений нет.</p>}
        <h3>По категориям</h3><div className="analytics-categories">{Object.entries(measured?.categories ?? {}).map(([category, seconds]) => <span key={category}>{categoryLabels[category] ?? category}: <strong>{duration(seconds)}</strong></span>)}</div>
      </section>
    </>}
  </div>
}
