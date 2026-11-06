import { useEffect, useState } from 'react'
import { request } from './api'
import { Link } from 'react-router'
export type InstallationState = 'unknown' | 'installed' | 'removed'
export function installationLabel(state: InstallationState = 'unknown', online: boolean) {
  if (state === 'removed') return 'Удалён'
  if (state === 'installed') return online ? 'Установлен · в сети' : 'Установлен · не в сети'
  return `Установка не подтверждена · ${online ? 'в сети' : 'не в сети'}`
}
type Entry = { event: { event_id: string; action: 'installed' | 'removed'; occurred_at: string; native: { version: string; exit_code: number }; cleanup: { support: string; browser: string } }; acknowledgement: { received_at: string } }
type Page = { installation: { state: InstallationState; previous_device_id?: string | null }; data: Entry[]; has_more: boolean }
const cleanupLabels: Record<string, string> = { complete: 'Завершено', incomplete: 'Не завершено', not_applicable: 'Не требуется', external_preserved: 'Внешние настройки сохранены', conflict: 'Конфликт настроек', failed: 'Ошибка' }
const date = (value: string) => new Date(value).toLocaleString('ru-RU')
export function InstallationHistory({ deviceId }: { deviceId: string }) {
  const [offset, setOffset] = useState(0)
  const [revision, setRevision] = useState(0)
  const [result, setResult] = useState<{ key: string; page?: Page; error?: string } | null>(null)
  const key = `${deviceId}:${offset}:${revision}`
  useEffect(() => {
    let ignore = false
    request<Page>(`/api/admin/console/devices/${deviceId}/installation-events?limit=20&offset=${offset}`)
      .then(page => { if (!ignore) setResult({ key, page }) })
      .catch(() => { if (!ignore) setResult({ key, error: 'Не удалось загрузить историю установки.' }) })
    return () => { ignore = true }
  }, [deviceId, offset, key])
  const current = result?.key === key ? result : null
  return <section className="panel"><h2>История установки</h2>
    {current?.error ? <p role="alert">{current.error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></p> : !current?.page ? <p aria-live="polite">Загрузка истории…</p> : <>
      {current.page.installation.previous_device_id && <p>Предыдущая установка: <Link to={`/admin/devices/${current.page.installation.previous_device_id}`}>открыть сохранённую карточку</Link></p>}
      {!current.page.data.length ? <p>Подтверждённых событий установки пока нет. Отсутствие связи не означает удаление.</p> : <ul className="change-list">{current.page.data.map(({ event, acknowledgement }) => <li key={event.event_id}><div><strong>{event.action === 'removed' ? 'Удалён' : 'Установлен'} · {event.native.version}</strong><p>Завершение установщика: {event.native.exit_code} · На компьютере: {date(event.occurred_at)}</p><p>Поддержка: {cleanupLabels[event.cleanup.support] ?? event.cleanup.support} · Браузеры: {cleanupLabels[event.cleanup.browser] ?? event.cleanup.browser}</p><small>Получено сервером: {date(acknowledgement.received_at)}</small></div></li>)}</ul>}
      <p className="muted">Показаны только полученные сервером факты. Отложенная доставка с отключённого компьютера ещё не подтверждена.</p>
      <div className="pagination"><button disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - 20))}>Назад</button><span>Страница {offset / 20 + 1}</span><button disabled={!current.page.has_more} onClick={() => setOffset(value => value + 20)}>Далее</button></div>
    </>}
  </section>
}
