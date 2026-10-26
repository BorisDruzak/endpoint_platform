import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useNavigate, useSearchParams } from 'react-router'
import { EmployeeApiError, employeeClient, getEmployeeSession, worktimePath, type Category, type Correction, type EmployeeRequest, type EmployeeSession, type WorkDay, type WorkHistory, type WorkMonth } from './employeeApi'
import { WorkTimeRing, durationText, intervalLabel, selectableIntervals, statusColors, statusLabels, timeText, type SelectedInterval } from './WorkTimeRing'
import './employee.css'
import { DlpPortal } from './DlpPortal'
import { HrTimesheets } from './HrTimesheets'

const messageOf = (reason: unknown) => reason instanceof Error ? reason.message : 'Не удалось загрузить данные.'
const hasRole = (session: EmployeeSession, ...roles: string[]) => session.grants.some(grant => roles.includes(grant.role))
const canDlp = (session: EmployeeSession) => session.grants.some(grant => grant.role === 'dlp_officer' && grant.department_id === null)
const today = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Yekaterinburg', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
const dateLabel = (day: string) => new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', weekday: 'long', timeZone: 'UTC' }).format(new Date(`${day}T12:00:00Z`))
const shiftDate = (day: string, delta: number) => new Date(Date.parse(`${day}T12:00:00Z`) + delta * 86400000).toISOString().slice(0, 10)
const localValue = (instant: string) => new Date(Date.parse(instant) + 5 * 3600000).toISOString().slice(0, 16)
const instantValue = (local: string) => new Date(`${local}:00+05:00`).toISOString()

export function EmployeeLogin() {
  useEffect(() => { const previous = document.title; document.title = 'WorkTime — Вход сотрудника'; return () => { document.title = previous } }, [])
  return <main className="login-page employee-login"><section className="login-panel">
    <p className="product-name">WorkTime · Кабинет сотрудника</p><h1>Вход сотрудника</h1>
    <p className="muted">Рабочий день, объяснения и корректировки — с вашей доменной учётной записью.</p>
    <a className="primary-button wt-login-link" href="/auth/employee/login">Войти с доменной учётной записью</a>
    <p className="muted">Доступ открывается после подтверждения связи с реестром сотрудников.</p>
  </section></main>
}

export function EmployeePortal({ dlp = false }: { dlp?: boolean }) {
  useEffect(() => { const previous = document.title; document.title = dlp ? 'DLP — Endpoint Platform' : 'WorkTime — Кабинет сотрудника'; return () => { document.title = previous } }, [dlp])
  const navigate = useNavigate()
  const [session, setSession] = useState<EmployeeSession | null>(null)
  const [checking, setChecking] = useState(true)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const unauthorized = useCallback(() => { setSession(null); navigate('/employee/login', { replace: true }) }, [navigate])
  useEffect(() => {
    let active = true
    let pending: AbortController | null = null
    const check = () => {
      pending?.abort(); const current = new AbortController(); pending = current
      setChecking(true)
      getEmployeeSession(current.signal).then(value => {
        if (!active || current.signal.aborted) return
        setSession(previous => JSON.stringify(previous) === JSON.stringify(value) ? previous : value); setError(''); setChecking(false)
      }).catch(reason => {
        if (!active || current.signal.aborted || reason?.name === 'AbortError') return
        setSession(null)
        setChecking(false)
        if (reason instanceof EmployeeApiError && reason.status === 401) unauthorized()
        else setError(messageOf(reason))
      })
    }
    check(); window.addEventListener('focus', check)
    return () => { active = false; pending?.abort(); window.removeEventListener('focus', check) }
  }, [unauthorized, revision])
  if (error) return <main className="state-page"><p role="alert">{error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить</button></main>
  if (!session) return <main className="state-page" aria-live="polite">Проверка сеанса сотрудника…</main>
  return <>{checking && <main className="state-page" aria-live="polite">Проверка сеанса сотрудника…</main>}<div hidden={checking}><EmployeeRealm key={`${session.person_id}:${session.department_id}:${session.csrf_token}:${session.privileged_assurance}:${JSON.stringify(session.grants)}`} session={session} unauthorized={unauthorized} dlp={dlp} /></div></>
}

function EmployeeRealm({ session, unauthorized, dlp }: { session: EmployeeSession; unauthorized: () => void; dlp: boolean }) {
  const controller = useRef<AbortController | null>(null)
  const ended = useRef(false)
  const [error, setError] = useState('')
  const [stepUpRequired, setStepUpRequired] = useState(false)
  useEffect(() => { ended.current = false; return () => { ended.current = true; controller.current?.abort(); controller.current = null } }, [])
  const request: EmployeeRequest = useCallback(async <T,>(path: string, init?: RequestInit): Promise<T> => {
    controller.current ??= new AbortController()
    try { return await employeeClient(session, controller.current.signal, unauthorized)<T>(path, init) }
    catch (reason) {
      if (reason instanceof EmployeeApiError && reason.code === 'mfa_step_up_required' && !ended.current) setStepUpRequired(true)
      throw reason
    }
  }, [session, unauthorized])
  async function signOut() {
    try { await request('/api/employee/session', { method: 'DELETE' }); unauthorized() }
    catch (reason) { if (!ended.current) setError(messageOf(reason)) }
  }
  const manager = hasRole(session, 'manager', 'worktime_admin')
  const hr = hasRole(session, 'hr', 'worktime_admin')
  const approver = hasRole(session, 'manager', 'hr', 'worktime_admin')
  return <div className="app-shell employee-shell"><aside className="sidebar">
    <div className="brand">WorkTime</div><p className="wt-sidebar-note">Кабинет сотрудника</p>
    <nav aria-label="Навигация сотрудника">
      <NavLink className="nav-link" to="/employee" end>Мой день</NavLink>
      <NavLink className="nav-link" to="/employee/history">История и корректировки</NavLink>
      {manager && <NavLink className="nav-link" to="/employee/manager">Подразделение</NavLink>}
      {approver && <NavLink className="nav-link" to="/employee/approvals">Согласования</NavLink>}
      {hr && <NavLink className="nav-link" to="/employee/reports">Табели и отчёты</NavLink>}
      {canDlp(session) && <NavLink className="nav-link" to="/dlp">DLP</NavLink>}
    </nav><p className="wt-sidebar-note">Часовой пояс отчётов<br />Екатеринбург · UTC+5</p>
  </aside><div className="content-shell"><header className="topbar"><strong>Рабочее время</strong><div className="account"><span>Сеанс сотрудника</span><button onClick={signOut}>Выйти</button></div></header>
    <main className="content employee-content">{error && <p role="alert" className="error">{error}</p>}{(stepUpRequired || session.privileged_assurance === false && hasRole(session, 'manager', 'hr', 'worktime_admin', 'dlp_officer')) && <section className="panel wt-mfa" aria-label="Подтверждение MFA"><p>Для кадровых действий и DLP подтвердите вход с MFA.</p><a href="/auth/employee/step-up">Подтвердить вход с MFA</a></section>}<Routes>
      {dlp ? <Route path="*" element={canDlp(session) ? <DlpPortal request={request} /> : <AccessDenied />} /> : <>
      <Route index element={<WorkTimePage request={request} session={session} />} />
      <Route path="history" element={<WorkTimePage request={request} session={session} historyMode />} />
      <Route path="manager" element={manager ? <ManagerPage request={request} session={session} /> : <AccessDenied />} />
      <Route path="approvals" element={approver ? <ManagerPage request={request} session={session} approvalsOnly /> : <AccessDenied />} />
      <Route path="reports" element={hr ? <ReportsPage request={request} /> : <AccessDenied />} />
      <Route path="*" element={<Navigate to="/employee" replace />} />
      </>}
    </Routes></main>
  </div></div>
}

function AccessDenied() { return <section className="panel"><h1>Доступ ограничен</h1><p>Для этого раздела требуется отдельное полномочие.</p><Link to="/employee">Мой день</Link></section> }

function useResource<T>(load: () => Promise<T>, key: string) {
  const [state, setState] = useState<{ key: string; value?: T; error?: string }>({ key })
  useEffect(() => {
    let active = true
    load().then(value => { if (active) setState({ key, value }) }).catch(reason => { if (active && reason?.name !== 'AbortError') setState({ key, error: messageOf(reason) }) })
    return () => { active = false }
    // The explicit key includes every request parameter; load may be an inline function.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  return state.key === key ? state : { key }
}

function WorkTimePage({ request, session, historyMode = false, personId }: { request: EmployeeRequest; session: EmployeeSession; historyMode?: boolean; personId?: string }) {
  const [params, setParams] = useSearchParams()
  const rawDay = params.get('day') ?? ''
  const day = /^\d{4}-\d{2}-\d{2}$/.test(rawDay) && Number.isFinite(Date.parse(`${rawDay}T12:00Z`)) ? rawDay : today()
  const [revision, setRevision] = useState(0)
  const [view, setView] = useState<'day' | 'week' | 'month'>('day')
  const [zoom, setZoom] = useState(false)
  const [selection, setSelection] = useState<{ key: string; item: SelectedInterval } | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [actionError, setActionError] = useState('')
  const writing = useRef(false)
  const pendingMutation = useRef<{ signature: string; id: string } | null>(null)
  const live = useRef(true)
  useEffect(() => { live.current = true; return () => { live.current = false } }, [])
  const person = personId ?? session.person_id
  const scope = personId ? `&person_id=${encodeURIComponent(personId)}` : ''
  const key = `${person}:${day}:${revision}`
  const data = useResource(async () => {
    const [dayData, categories, history] = await Promise.all([
      request<WorkDay>(`${worktimePath}/day?day=${day}${scope}`),
      request<{ categories: Category[] }>(`${worktimePath}/categories`),
      request<WorkHistory>(`${worktimePath}/history?day=${day}${scope}`),
    ])
    if (dayData.person_id !== person || dayData.day !== day) throw new Error('Ответ сервера не соответствует выбранному сотруднику или дню.')
    return { day: dayData, categories: categories.categories, history }
  }, key)
  function selectDay(value: string) { const next = new URLSearchParams(params); next.set('day', value); setParams(next); setNotice(''); setActionError('') }
  async function mutate(path: string, body: object) {
    if (writing.current) return
    writing.current = true
    const signature = `${path}:${JSON.stringify(body)}`
    if (pendingMutation.current?.signature !== signature) pendingMutation.current = { signature, id: crypto.randomUUID() }
    setBusy(true); setActionError(''); setNotice('')
    try {
      await request(`${worktimePath}${path}`, { method: 'POST', body: JSON.stringify({ ...body, idempotency_key: pendingMutation.current.id }) })
      pendingMutation.current = null
      if (live.current) { setRevision(value => value + 1); setSelection(null); setNotice('Изменение сохранено. Итоги обновлены.') }
    } catch (reason) { if (live.current && !(reason instanceof Error && reason.name === 'AbortError')) setActionError(messageOf(reason)) }
    finally { writing.current = false; if (live.current) setBusy(false) }
  }
  const requestedId = params.get('request_id') ?? ''
  const ownedRequest = !personId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(requestedId)
    ? data.value?.day.pending_explanations.find(item => item.id === requestedId) : undefined
  const selected: SelectedInterval | null = selection?.key === key ? selection.item : ownedRequest ? { ...ownedRequest, request_id: ownedRequest.id, request: ownedRequest, kind: 'work', status: 'UNEXPLAINED', source: 'Серверный запрос объяснения', annotation: { state: 'pending', label: 'Требует объяснения', source: 'Серверный запрос объяснения' } } : null
  const isSelf = !personId || personId === session.person_id
  return <div className="worktime-page"><div className="page-heading"><div><p className="eyebrow">WORKTIME</p><h1>{historyMode ? 'История и корректировки' : personId ? 'Рабочий день сотрудника' : 'Мой рабочий день'}</h1><p className="muted">{dateLabel(day)} · Екатеринбург</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <div className="wt-toolbar panel"><button aria-label="Предыдущий день" onClick={() => selectDay(shiftDate(day, -1))}>←</button><label>Дата<input type="date" value={day} onChange={event => { if (event.target.value) selectDay(event.target.value) }} /></label><button aria-label="Следующий день" onClick={() => selectDay(shiftDate(day, 1))}>→</button><button onClick={() => selectDay(today())}>Сегодня</button><div className="wt-view-buttons" role="group" aria-label="Период просмотра">{([['day', 'День'], ['week', 'Неделя'], ['month', 'Месяц']] as const).map(([code, label]) => <button key={code} aria-pressed={view === code} onClick={() => setView(code)}>{label}</button>)}</div></div>
    {notice && <p className="wt-notice" role="status">{notice}</p>}{actionError && <p className="error" role="alert">{actionError}</p>}
    {data.error ? <section className="panel"><p role="alert">{data.error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить</button></section> : !data.value ? <p aria-live="polite">Загрузка рабочего дня…</p> : <>
      {requestedId && !ownedRequest && <p className="muted" role="status">Запрос уже объяснён или недоступен в вашем рабочем дне.</p>}
      {view !== 'day' && <PeriodCalendar request={request} day={day} personId={personId} view={view} revision={revision} onSelect={selectDay} categories={data.value.categories} />}
      <div className="wt-day-layout"><section className="panel wt-day-card"><div className="wt-card-heading"><h2>Шкала дня</h2><label className="wt-check"><input type="checkbox" checked={zoom} disabled={!data.value.day.schedule.length} onChange={event => setZoom(event.target.checked)} />Масштаб графика</label></div>
        <WorkTimeRing day={data.value.day} zoom={zoom} categories={data.value.categories} onSelect={item => setSelection({ key, item })} />
        <p className="wt-confirmed">Подтверждено: {durationText(data.value.day.totals.work_seconds)}</p><p className="muted wt-small">Внешнее кольцо — рабочие отметки. Внутреннее — компьютер. Техническая активность сама по себе не подтверждает рабочее время.</p>
        <div className="wt-legend">{['WORKING', 'BREAK', 'OFF_PC', 'ACTIVE', 'IDLE', 'LOCKED', 'DISCONNECTED', 'UNKNOWN'].map(status => <span key={status}><i style={{ background: statusColors[status] }} />{statusLabels[status]}</span>)}</div>
        <div className="wt-legend"><span><i style={{ background: '#8b62ac' }} />Объяснение сотрудника</span><span><i style={{ background: '#d17926' }} />Требует объяснения</span></div><p className="muted wt-small">Полоса на внешнем кольце обозначает объяснение поверх рабочей отметки. Объяснение не добавляет подтверждённое время.</p>
      </section><section className="panel"><h2>Рабочий статус</h2><p className="wt-current-status">{statusLabels[data.value.day.status] ?? data.value.day.status}</p><dl className="wt-summary"><div><dt>Перерыв</dt><dd>{durationText(data.value.day.totals.break_seconds)}</dd></div><div><dt>Работа вне ПК</dt><dd>{durationText(data.value.day.totals.off_pc_seconds)}</dd></div><div><dt>По графику</dt><dd>{durationText(data.value.day.totals.scheduled_seconds)}</dd></div><div><dt>Нет достоверных данных ПК</dt><dd>{durationText(data.value.day.coverage.unknown_seconds)}</dd></div></dl>
        {isSelf && day === today() ? <div className="wt-status-actions">{([['start', 'Начать день', ['NOT_STARTED', 'ENDED']], ['break', 'Начать перерыв', ['WORKING', 'OFF_PC']], ['resume', 'Продолжить работу', ['BREAK', 'OFF_PC']], ['off_pc', 'Работа вне ПК', ['WORKING']], ['end', 'Завершить день', ['WORKING', 'BREAK', 'OFF_PC']]] as const).map(([action, label, statuses]) => <button key={action} disabled={busy || !(statuses as readonly string[]).includes(data.value!.day.status)} onClick={() => void mutate('/transitions', { action })}>{label}</button>)}</div> : <p className="muted wt-small">Отметки начала и окончания доступны для вашего текущего дня. Для прошлого дня отправьте корректировку.</p>}
        <h3>Ожидают объяснения</h3>{data.value.day.pending_explanations.length ? <ul className="wt-list">{data.value.day.pending_explanations.map(item => <li key={item.id}><button onClick={() => setSelection({ key, item: { ...item, kind: 'work', status: 'UNEXPLAINED', source: 'Серверный запрос объяснения', request_id: item.id, request: item } })}>{timeText(item.started_at)}–{timeText(item.ended_at)} · Объяснить интервал</button></li>)}</ul> : <p className="muted">Необъяснённых запросов нет.</p>}
      </section></div>
      <section className="panel wt-intervals"><h2>Интервалы дня — текстовое представление</h2><p className="muted wt-small">Выберите интервал мышью или клавишей Enter. UNKNOWN означает отсутствие достоверных наблюдений, а не перерыв.</p><ul className="wt-list">{selectableIntervals(data.value.day, data.value.categories).map((item, index) => <li key={`${item.kind}-${index}`}><button aria-pressed={selected?.started_at === item.started_at && selected?.kind === item.kind} onClick={() => setSelection({ key, item })}>Текст: {intervalLabel(item, data.value!.day.timezone)}</button></li>)}</ul>{!selectableIntervals(data.value.day).length && <p className="muted">За этот день интервалы отсутствуют.</p>}</section>
      {selected && <section className="panel wt-selection" aria-label="Выбранный интервал"><h2>{statusLabels[selected.status] ?? selected.status}</h2><dl className="wt-summary"><div><dt>Начало</dt><dd>{timeText(selected.started_at)}</dd></div><div><dt>Окончание</dt><dd>{timeText(selected.ended_at)}</dd></div><div><dt>Продолжительность</dt><dd>{durationText((Date.parse(selected.ended_at) - Date.parse(selected.started_at)) / 1000)}</dd></div><div><dt>Источник</dt><dd>{selected.source}</dd></div></dl>{selected.attributed === false && <p className="muted">Время не приписано сотруднику. Достоверность технических данных не меняется после объяснения.</p>}
        {selected.annotation && <p className="wt-annotation-detail"><strong>{selected.annotation.label}</strong> · {selected.annotation.source}. Основная рабочая отметка: {statusLabels[selected.status] ?? selected.status}.</p>}{selected.request && <p className="muted wt-small">Объяснение относится ко всему запросу: {timeText(selected.request.started_at)}–{timeText(selected.request.ended_at)}.</p>}
        <h3>Объяснения интервала</h3>{data.value.day.explanations.filter(item => Date.parse(item.started_at) < Date.parse(selected.ended_at) && Date.parse(item.ended_at) > Date.parse(selected.started_at)).map(item => <p key={item.id}>{data.value!.categories.find(category => category.code === item.category_code)?.label ?? item.category_code}: {item.comment || 'Без комментария'}</p>)}
        {isSelf && <ExplanationForm key={`${key}:${selected.kind}:${selected.started_at}`} selection={selected} categories={data.value.categories} busy={busy} submit={body => mutate('/explanations', body)} />}
      </section>}
      {isSelf && <CorrectionForm key={day} day={day} busy={busy} submit={body => mutate('/corrections', body)} />}
      <HistoryPanel history={data.value.history} />
    </>}
  </div>
}

function ExplanationForm({ selection, categories, busy, submit }: { selection: SelectedInterval; categories: Category[]; busy: boolean; submit: (body: object) => Promise<void> }) {
  const categoryId = useId()
  const [category, setCategory] = useState(''), [comment, setComment] = useState('')
  const required = categories.find(item => item.code === category)?.requires_comment ?? false
  return <form className="wt-form" onSubmit={(event: FormEvent) => { event.preventDefault(); if (category && (!required || comment.trim())) void submit({ started_at: selection.request?.started_at ?? selection.started_at, ended_at: selection.request?.ended_at ?? selection.ended_at, category_code: category, comment: comment.trim(), ...(selection.request_id ? { request_id: selection.request_id } : {}) }) }}>
    <label htmlFor={categoryId}>Причина</label><select id={categoryId} value={category} onChange={event => setCategory(event.target.value)} required><option value="">Выберите причину</option>{categories.map(item => <option key={item.code} value={item.code}>{item.label}</option>)}</select>
    <label>Комментарий<textarea value={comment} onChange={event => setComment(event.target.value)} maxLength={2000} required={required} rows={3} /></label><button className="primary-button" disabled={busy || !category || required && !comment.trim()} type="submit">Сохранить объяснение</button>
  </form>
}

function CorrectionForm({ day, busy, submit }: { day: string; busy: boolean; submit: (body: object) => Promise<void> }) {
  const [start, setStart] = useState(`${day}T08:00`), [end, setEnd] = useState(`${day}T09:00`), [status, setStatus] = useState('WORKING'), [reason, setReason] = useState('')
  const valid = !!start && !!end && start < end && !!reason.trim()
  return <section className="panel wt-corrections"><h2>Запросить корректировку</h2><p className="muted wt-small">Изменение сохраняется в истории и применяется после согласования.</p><form className="wt-form" onSubmit={event => { event.preventDefault(); if (valid) void submit({ started_at: instantValue(start), ended_at: instantValue(end), status, reason: reason.trim() }) }}>
    <div className="wt-form-row"><label>Начало корректировки<input type="datetime-local" value={start} onChange={event => setStart(event.target.value)} required /></label><label>Конец корректировки<input type="datetime-local" value={end} onChange={event => setEnd(event.target.value)} min={start} required /></label><label>Рабочая отметка<select value={status} onChange={event => setStatus(event.target.value)}>{['WORKING', 'BREAK', 'OFF_PC', 'ENDED'].map(item => <option key={item} value={item}>{statusLabels[item]}</option>)}</select></label></div>
    <label>Обоснование корректировки<textarea value={reason} onChange={event => setReason(event.target.value)} required maxLength={2000} rows={2} /></label>{start && end && start >= end && <p className="error">Окончание должно быть позже начала.</p>}<button type="submit" disabled={busy || !valid}>Отправить на согласование</button>
  </form></section>
}

const correctionState: Record<string, string> = { pending: 'Ожидает согласования', approved: 'Согласовано', rejected: 'Отклонено' }
function HistoryPanel({ history }: { history: WorkHistory }) {
  const empty = !history.events.length && !history.explanations.length && !history.corrections.length && !history.approvals.length
  return <section className="panel wt-history"><h2>История изменений</h2>{empty && <p className="muted">За выбранный день изменений нет.</p>}
    <ul className="wt-list">{history.events.map(item => <li key={`event-${item.id}`}>{timeText(item.occurred_at)} · {({ start: 'Начало дня', end: 'Конец дня', break: 'Перерыв', resume: 'Продолжение работы', off_pc: 'Работа вне ПК' } as Record<string, string>)[item.action] ?? item.action}</li>)}
      {history.explanations.map(item => <li key={`explanation-${item.id}`}>Объяснение · {timeText(item.started_at)}–{timeText(item.ended_at)} · {item.comment || item.category_code}</li>)}
      {history.corrections.map(item => <li key={`correction-${item.id}`}>Корректировка · {timeText(item.started_at)}–{timeText(item.ended_at)} · {statusLabels[item.status] ?? item.status} · {correctionState[item.decision] ?? item.decision} · {item.reason}</li>)}
      {history.approvals.map(item => <li key={`approval-${item.id}`}>Решение · {correctionState[item.decision] ?? item.decision} · {item.comment || 'Без комментария'}</li>)}
    </ul></section>
}

function PeriodCalendar({ request, day, personId, view, revision, onSelect, categories }: { request: EmployeeRequest; day: string; personId?: string; view: 'week' | 'month'; revision: number; onSelect: (day: string) => void; categories: Category[] }) {
  const weekDay = new Date(`${day}T12:00Z`).getUTCDay(), weekStart = shiftDate(day, -(weekDay || 7) + 1)
  const dates = view === 'week' ? Array.from({ length: 7 }, (_, index) => shiftDate(weekStart, index)) : Array.from({ length: new Date(Number(day.slice(0, 4)), Number(day.slice(5, 7)), 0).getDate() }, (_, index) => `${day.slice(0, 8)}${String(index + 1).padStart(2, '0')}`)
  const months = [...new Set(dates.map(date => date.slice(0, 7)))]
  const key = `${months.join(',')}:${personId}:${revision}`
  const data = useResource(async () => {
    const results = await Promise.all(months.map(month => request<WorkMonth>(`${worktimePath}/month?month=${month}${personId ? `&person_id=${encodeURIComponent(personId)}` : ''}`)))
    return new Map(results.flatMap(result => result.days.map(item => [item.day, item] as const)))
  }, key)
  return <section className="panel wt-calendar"><h2>{view === 'week' ? 'Неделя' : 'Календарь месяца'}</h2>{data.error ? <p role="alert">{data.error}</p> : !data.value ? <p aria-live="polite">Загрузка календаря…</p> : <div className="wt-calendar-grid">{dates.map(date => { const value = data.value!.get(date); return <button key={date} aria-pressed={date === day} aria-label={`${date}, ${value ? durationText(value.totals.work_seconds) : 'нет записей'}`} onClick={() => onSelect(date)}><span>{dateLabel(date)}</span>{value ? <><WorkTimeRing day={value} categories={categories} mini /><strong>{durationText(value.totals.work_seconds)}</strong><small>UNKNOWN: {durationText(value.coverage.unknown_seconds)}</small></> : <span className="wt-mini-empty">Нет записей</span>}</button> })}</div>}</section>
}

type Person = { person_id: string; department_id: string | null; status: string }
function ManagerPage({ request, session, approvalsOnly = false }: { request: EmployeeRequest; session: EmployeeSession; approvalsOnly?: boolean }) {
  const [revision, setRevision] = useState(0), [person, setPerson] = useState('')
  const data = useResource(async () => { const [people, approvals] = await Promise.all([approvalsOnly ? Promise.resolve({ people: [] as Person[] }) : request<{ people: Person[] }>(`${worktimePath}/people`), request<{ corrections: Correction[] }>(`${worktimePath}/approvals`)]); return { people: people.people, approvals: approvals.corrections } }, `manager:${approvalsOnly}:${revision}`)
  return <><div className="page-heading"><div><p className="eyebrow">{approvalsOnly ? 'СОГЛАСОВАНИЯ' : 'РУКОВОДИТЕЛЬ'}</p><h1>{approvalsOnly ? 'Согласования корректировок' : 'Подразделение и согласования'}</h1><p className="muted">Доступ ограничен подразделениями, указанными в ваших полномочиях.</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить список</button></div>
    {data.error ? <p role="alert">{data.error}</p> : !data.value ? <p aria-live="polite">Загрузка согласований…</p> : <>{!approvalsOnly && <section className="panel"><h2>Сотрудники подразделения</h2>{data.value.people.length ? <ul className="wt-list">{data.value.people.map(item => <li key={item.person_id}><button aria-pressed={person === item.person_id} onClick={() => setPerson(item.person_id)}>Сотрудник {item.person_id} · {statusLabels[item.status] ?? item.status}</button></li>)}</ul> : <p className="muted">Доступных сотрудников нет.</p>}</section>}<section className="panel wt-approvals"><h2>Ожидают согласования</h2>{data.value.approvals.length ? data.value.approvals.map(item => <ApprovalCard key={item.id} correction={item} request={request} onDecision={() => setRevision(value => value + 1)} />) : <p className="muted">Ожидающих корректировок нет.</p>}</section></>}
    {!approvalsOnly && person && data.value?.people.some(item => item.person_id === person) && <WorkTimePage key={person} request={request} session={session} personId={person} />}
  </>
}

function ApprovalCard({ correction, request, onDecision }: { correction: Correction; request: EmployeeRequest; onDecision: () => void }) {
  const [comment, setComment] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState('')
  const retry = useRef<{ signature: string; id: string } | null>(null)
  const writing = useRef(false)
  async function decide(decision: string) {
    if (writing.current) return
    writing.current = true
    const payload = { decision, comment: comment.trim() }, signature = JSON.stringify(payload)
    if (retry.current?.signature !== signature) retry.current = { signature, id: crypto.randomUUID() }
    setBusy(true); setError('')
    try { await request(`${worktimePath}/corrections/${encodeURIComponent(correction.id)}/decision`, { method: 'POST', body: JSON.stringify({ ...payload, idempotency_key: retry.current.id }) }); retry.current = null; onDecision() }
    catch (reason) { if (!(reason instanceof Error && reason.name === 'AbortError')) setError(messageOf(reason)) } finally { writing.current = false; setBusy(false) }
  }
  return <article className="wt-approval"><h3>Сотрудник {correction.person_id}</h3><p>{localValue(correction.started_at).replace('T', ' ')}–{timeText(correction.ended_at)} · {statusLabels[correction.status] ?? correction.status}</p><p>{correction.reason}</p><label>Комментарий к решению<textarea value={comment} onChange={event => setComment(event.target.value)} maxLength={2000} /></label><div className="wt-status-actions"><button disabled={busy} onClick={() => void decide('approved')}>Согласовать</button><button disabled={busy || !comment.trim()} onClick={() => void decide('rejected')}>Отклонить</button></div>{error && <p role="alert" className="error">{error}</p>}</article>
}

function ReportsPage({ request }: { request: EmployeeRequest }) {
  const [month, setMonth] = useState(today().slice(0, 7)), [personId, setPersonId] = useState('')
  const people = useResource(() => request<{ people: Person[] }>(`${worktimePath}/people`), 'report-people')
  const report = useResource(() => personId ? request<WorkMonth>(`${worktimePath}/report?month=${month}&person_id=${encodeURIComponent(personId)}`) : Promise.resolve(null), `${month}:${personId}`)
  function exportCsv() {
    if (!report.value) return
    const rows = [['Дата', 'Работа, секунд', 'Перерыв, секунд', 'Вне ПК, секунд', 'По графику, секунд', 'UNKNOWN, секунд'], ...report.value.days.map(item => [item.day, item.totals.work_seconds, item.totals.break_seconds, item.totals.off_pc_seconds, item.totals.scheduled_seconds, item.coverage.unknown_seconds])]
    const blob = new Blob(['\uFEFF', rows.map(row => row.join(';')).join('\r\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = `worktime-${month}.csv`; anchor.click(); URL.revokeObjectURL(url)
  }
  return <><div className="page-heading"><div><p className="eyebrow">КАДРОВАЯ СЛУЖБА</p><h1>Табели и отчёты</h1><p className="muted">Подтверждённое время, график и полнота технических данных.</p></div></div><section className="panel wt-toolbar"><label>Месяц табеля<input type="month" value={month} onChange={event => { if (event.target.value) setMonth(event.target.value) }} /></label><label>Сотрудник табеля<select value={personId} onChange={event => setPersonId(event.target.value)}><option value="">Выберите сотрудника</option>{people.value?.people.map(person => <option key={person.person_id} value={person.person_id}>{person.person_id}</option>)}</select></label></section>
    {people.error && <p role="alert">{people.error}</p>}{report.error && <p role="alert">{report.error}</p>}{personId && !report.value && !report.error && <p aria-live="polite">Загрузка табеля…</p>}
    {personId && <><ScheduleEditor key={personId} personId={personId} request={request} /><HrCorrection key={`correction:${personId}:${month}`} personId={personId} month={month} request={request} /><HrTimesheets key={`timesheets:${personId}:${month}`} request={request} personId={personId} month={month} /></>}
    {report.value && <section className="panel"><div className="wt-card-heading"><h2>Табель за {month}</h2><button onClick={exportCsv}>Экспорт CSV</button></div><p>Подтверждено за месяц: {durationText(report.value.totals.work_seconds)}</p><div className="table-scroll"><table className="wt-report"><thead><tr><th>Дата</th><th>Работа</th><th>Перерыв</th><th>Вне ПК</th><th>График</th><th>UNKNOWN</th><th>Согласования</th></tr></thead><tbody>{report.value.days.map(item => <tr key={item.day}><td>{item.day}</td><td>{durationText(item.totals.work_seconds)}</td><td>{durationText(item.totals.break_seconds)}</td><td>{durationText(item.totals.off_pc_seconds)}</td><td>{durationText(item.totals.scheduled_seconds)}</td><td>{durationText(item.coverage.unknown_seconds)}</td><td>{item.corrections.map(correction => correctionState[correction.decision] ?? correction.decision).join(', ') || 'Нет корректировок'}</td></tr>)}</tbody></table></div></section>}
  </>
}

function HrCorrection({ request, personId, month }: { request: EmployeeRequest; personId: string; month: string }) {
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('')
  const retry = useRef<{ signature: string; id: string } | null>(null), writing = useRef(false)
  async function submit(body: object) {
    if (writing.current) return
    const signature = JSON.stringify(body)
    if (retry.current?.signature !== signature) retry.current = { signature, id: crypto.randomUUID() }
    writing.current = true; setBusy(true); setError(''); setNotice('')
    try { await request(`${worktimePath}/people/${encodeURIComponent(personId)}/corrections`, { method: 'POST', body: JSON.stringify({ ...body, idempotency_key: retry.current.id }) }); retry.current = null; setNotice('Кадровая корректировка отправлена на независимое согласование.') }
    catch (reason) { if (!(reason instanceof Error && reason.name === 'AbortError')) setError(messageOf(reason)) } finally { writing.current = false; setBusy(false) }
  }
  return <section className="wt-hr-correction" aria-label="Кадровая корректировка"><h2>Кадровая корректировка сотрудника</h2><p className="muted wt-small">Для выбранного сотрудника. Автор корректировки не может согласовать собственное изменение.</p><CorrectionForm day={`${month}-01`} busy={busy} submit={submit} />{notice && <p role="status" className="wt-notice">{notice}</p>}{error && <p role="alert" className="error">{error}</p>}</section>
}

type ScheduleDefinition = { weekdays: number[]; start: string; end: string; overrides: Record<string, { start: string; end: string } | null> }
function ScheduleEditor({ personId, request }: { personId: string; request: EmployeeRequest }) {
  const [effective, setEffective] = useState(today()), [start, setStart] = useState('08:00'), [end, setEnd] = useState('17:00')
  const [weekdays, setWeekdays] = useState([0, 1, 2, 3, 4]), [overrides, setOverrides] = useState<ScheduleDefinition['overrides']>({})
  const [overrideDay, setOverrideDay] = useState(''), [off, setOff] = useState(true), [overrideStart, setOverrideStart] = useState('08:00'), [overrideEnd, setOverrideEnd] = useState('17:00')
  const [revision, setRevision] = useState(0), [busy, setBusy] = useState(false), [notice, setNotice] = useState(''), [error, setError] = useState('')
  const retry = useRef<{ signature: string; id: string } | null>(null)
  const schedules = useResource(() => request<{ schedules: { id: string; effective_from: string; definition: ScheduleDefinition; created_at: string }[] }>(`${worktimePath}/schedules?person_id=${encodeURIComponent(personId)}`), `${personId}:${revision}`)
  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !effective || !start || !end || start === end) return
    const body = { person_id: personId, effective_from: effective, definition: { weekdays, start, end, overrides } }
    const signature = JSON.stringify(body)
    if (retry.current?.signature !== signature) retry.current = { signature, id: crypto.randomUUID() }
    setBusy(true); setNotice(''); setError('')
    try { await request(`${worktimePath}/schedules`, { method: 'POST', body: JSON.stringify({ ...body, idempotency_key: retry.current.id }) }); retry.current = null; setNotice('Версия графика сохранена.'); setRevision(value => value + 1) }
    catch (reason) { if (!(reason instanceof Error && reason.name === 'AbortError')) setError(messageOf(reason)) } finally { setBusy(false) }
  }
  return <section className="panel wt-schedule"><h2>График сотрудника</h2><p className="muted wt-small">Каждое сохранение создаёт новую версию. Для ночной смены окончание может быть раньше начала. Исключения задают выходные и отдельные смены.</p>
    <form className="wt-form" onSubmit={event => void save(event)}><div className="wt-form-row"><label>Дата начала графика<input type="date" value={effective} onChange={event => setEffective(event.target.value)} required /></label><label>Начало смены<input type="time" value={start} onChange={event => setStart(event.target.value)} required /></label><label>Конец смены<input type="time" value={end} onChange={event => setEnd(event.target.value)} required /></label></div>
      <fieldset className="wt-weekdays"><legend>Рабочие дни недели</legend>{['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'].map((label, index) => <label key={label}><input type="checkbox" checked={weekdays.includes(index)} onChange={event => setWeekdays(current => event.target.checked ? [...current, index].sort() : current.filter(value => value !== index))} />{label}</label>)}</fieldset>
      <fieldset><legend>Исключения в календаре</legend><div className="wt-form-row"><label>Дата исключения<input type="date" value={overrideDay} onChange={event => setOverrideDay(event.target.value)} /></label><label className="wt-check"><input type="checkbox" checked={off} onChange={event => setOff(event.target.checked)} />Выходной</label>{!off && <><label>Начало особой смены<input type="time" value={overrideStart} onChange={event => setOverrideStart(event.target.value)} /></label><label>Конец особой смены<input type="time" value={overrideEnd} onChange={event => setOverrideEnd(event.target.value)} /></label></>}</div><button type="button" disabled={!overrideDay || !off && (!overrideStart || !overrideEnd || overrideStart === overrideEnd)} onClick={() => { if (overrideDay) { setOverrides(current => ({ ...current, [overrideDay]: off ? null : { start: overrideStart, end: overrideEnd } })); setOverrideDay('') } }}>Добавить исключение</button><ul className="wt-list">{Object.entries(overrides).map(([day, shift]) => <li key={day}>{day}: {shift ? `${shift.start}–${shift.end}` : 'Выходной'} <button type="button" aria-label={`Удалить исключение ${day}`} onClick={() => setOverrides(current => Object.fromEntries(Object.entries(current).filter(([date]) => date !== day)))}>Удалить</button></li>)}</ul></fieldset>
      <button type="submit" disabled={busy || !effective || !start || !end || start === end}>Сохранить график</button>
    </form>{notice && <p className="wt-notice" role="status">{notice}</p>}{error && <p className="error" role="alert">{error}</p>}
    <h3>История графиков</h3>{schedules.error ? <p role="alert">{schedules.error}</p> : !schedules.value ? <p aria-live="polite">Загрузка графиков…</p> : schedules.value.schedules.length ? <ul className="wt-list">{schedules.value.schedules.map(item => <li key={item.id}>С {item.effective_from} · {item.definition.start}–{item.definition.end} · {item.definition.weekdays.map(value => ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'][value]).join(', ')} · Исключений: {Object.keys(item.definition.overrides).length}</li>)}</ul> : <p className="muted">График ещё не назначен.</p>}
  </section>
}
