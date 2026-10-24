import { useEffect, useState } from 'react'
import { request } from './api'
import type { PowerEvent, PowerPage, PowerSummary } from './powerApi'

export const powerEventLabels: Record<PowerEvent['event_kind'], string> = {
  OS_STARTED: 'Запуск ОС', OS_SHUTDOWN_STARTED: 'Завершение работы ОС', OS_SLEEP_STARTED: 'Переход в сон',
  OS_RESUMED: 'Возобновление работы ОС', OS_UNEXPECTED_SHUTDOWN_REPORTED: 'ОС сообщила о предыдущем некорректном завершении',
}
const availabilityLabels = { READY: 'Источник событий питания доступен', DEGRADED: 'Неполное покрытие источника событий питания',
  UNAVAILABLE: 'Источник событий питания недоступен', UNSUPPORTED: 'Источник событий питания не поддерживается' }
const dateText = (value: string | null | undefined) => value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Нет данных'

export const connectionLabel = (online: boolean) => online ? 'В сети' : 'Нет связи — причина неизвестна'

export function powerEventLabel(event: PowerEvent) {
  const label = powerEventLabels[event.event_kind]
  return event.evidence === 'request' ? `Запрос: ${label[0].toLocaleLowerCase('ru-RU') + label.slice(1)}` : label
}

export function PowerStatus({ value }: { value: PowerSummary | null | undefined }) {
  const event = value?.latest_event
  return <div className="power-status">
    <span>{event ? `Последнее событие: ${powerEventLabel(event)[0].toLocaleLowerCase('ru-RU') + powerEventLabel(event).slice(1)}` : 'Событий питания нет'}</span>
    {event && <small>{dateText(event.occurred_at)} · {event.source}</small>}
    <small>{value?.source_status ? availabilityLabels[value.source_status.availability] : 'Состояние источника событий питания неизвестно'}</small>
    {value?.source_status && !value.source_fresh && <small>Состояние источника устарело</small>}
  </div>
}

export function DevicePowerHistory({ deviceId, online, lastSeenAt, activityObservedAt, summary }: {
  deviceId: string; online: boolean; lastSeenAt: string | null; activityObservedAt: string | null | undefined; summary: PowerSummary | null | undefined
}) {
  const [page, setPage] = useState<PowerPage | null>(null)
  const [offset, setOffset] = useState(0), [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true), [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const controller = new AbortController()
    setLoading(true); setError('')
    request<PowerPage>(`/api/admin/console/devices/${deviceId}/power?limit=20&offset=${offset}`, { signal: controller.signal })
      .then(value => { if (active) setPage(value) })
      .catch(() => { if (active) setError('Не удалось загрузить историю питания') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false; controller.abort() }
  }, [deviceId, offset, revision])
  const current = summary ?? page?.summary
  const source = current?.source_status
  return <section className="panel power-history" aria-label="Питание и связь">
    <h2>Питание и связь</h2>
    <p><span className={`status ${online ? 'online' : 'offline'}`}>{connectionLabel(online)}</span></p>
    <dl className="detail-grid">
      <div><dt>Последняя связь</dt><dd>{dateText(lastSeenAt)}</dd></div>
      <div><dt>Последняя активность</dt><dd>{dateText(activityObservedAt)}<small>Последнее наблюдение Activity Sensor; не время действия сотрудника. Без доступного источника или политики — неизвестно.</small></dd></div>
      <div><dt>Последнее событие питания</dt><dd><PowerStatus value={current} /></dd></div>
    </dl>
    <p className="muted">События ОС не подтверждают физическое отключение питания. Отсутствие связи не означает бездействие сотрудника.</p>
    <p className="muted">История питания хранится 30 дней независимо от политики активности. Пробелы в наблюдениях остаются неизвестными.</p>
    {current && <p className="muted">История доступна с {dateText(current.history_available_from)}.</p>}
    {source && <p className="muted">Источник: {source.source} · Покрытие с {dateText(source.coverage_started_at)} · Отчёт: {dateText(source.reported_at)}.
      {' '}Потеряно событий: {source.loss_count}; сбросов источника: {source.reset_count}. Начало покрытия не гарантирует непрерывную историю.</p>}
    <h3>События питания ОС</h3>
    {loading ? <p role="status">Загрузка истории питания…</p> : error ? <p role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></p>
      : page?.data.length ? <ul className="change-list">{page.data.map(event => <li key={event.event_identifier}>
        <div><strong>{powerEventLabel(event)}</strong><small>{event.source}{event.sleep_subtype ? ` · ${event.sleep_subtype}` : ''}</small></div>
        <span>Событие: {dateText(event.occurred_at)}<small>Обнаружено: {dateText(event.observed_at)}</small></span>
      </li>)}</ul> : <p>Событий питания за доступный период нет.</p>}
    <div className="pagination"><button disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - 20))}>Назад</button>
      <span>{loading ? 'Загрузка…' : page ? `${page.total ? page.offset + 1 : 0}–${Math.min(page.offset + page.limit, page.total)} из ${page.total}` : 'Нет данных'}</span>
      <button disabled={loading || !!error || !page?.has_more} onClick={() => setOffset(offset + 20)}>Далее</button></div>
  </section>
}
