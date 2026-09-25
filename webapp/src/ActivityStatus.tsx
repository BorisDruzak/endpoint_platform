import { useEffect, useState } from 'react'
import { request } from './api'

type Activity = {
  collected_at: string
  last_observed_at: string
  online: boolean
  fresh: boolean
  sections: {
    user_login: string | null
    session_state: 'ACTIVE' | 'IDLE' | 'LOCKED' | 'DISCONNECTED' | 'UNKNOWN'
    idle_seconds: number | null
    foreground: {
      process_name: string
      application_category: 'browser' | 'office' | 'business_app' | 'system' | 'remote_access' | 'other'
    } | null
    browser: {
      browser_family: 'chrome' | 'yandex'
      domain: string | null
      sensor_state: 'NOT_APPLICABLE' | 'NEVER_SEEN' | 'ACTIVE' | 'STALE' | 'ERROR'
      extension_version: string | null
      last_seen_at: string | null
    } | null
  }
}

const stateLabels: Record<Activity['sections']['session_state'], string> = {
  ACTIVE: 'Активен', IDLE: 'Неактивен', LOCKED: 'Заблокирован',
  DISCONNECTED: 'Сеанс отключён', UNKNOWN: 'Неизвестно',
}
const categoryLabels: Record<NonNullable<Activity['sections']['foreground']>['application_category'], string> = {
  browser: 'Браузер', office: 'Офисное приложение', business_app: 'Рабочее приложение',
  system: 'Система', remote_access: 'Удалённый доступ', other: 'Другое',
}
const browserLabels: Record<NonNullable<Activity['sections']['browser']>['browser_family'], string> = {
  chrome: 'Chrome', yandex: 'Яндекс Браузер',
}
const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', {
  dateStyle: 'medium', timeStyle: 'short',
}).format(new Date(value))

export function DeviceActivityStatus({ deviceId }: { deviceId: string }) {
  const [activity, setActivity] = useState<Activity | null | undefined>(undefined)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    request<{ data: Activity | null }>(`/api/admin/console/devices/${deviceId}/activity`)
      .then(value => { if (active) { setActivity(value.data); setError('') } })
      .catch(() => { if (active) setError('Не удалось загрузить активность устройства') })
    return () => { active = false }
  }, [deviceId])

  if (error) return <section className="panel" role="alert"><h2>Активность</h2><p>{error}</p></section>
  if (activity === undefined) return <p aria-live="polite">Загрузка активности…</p>
  if (activity === null) return <section className="panel"><h2>Активность</h2><p>Данные об активности ещё не получены.</p></section>

  const { sections } = activity
  return <section className="panel">
    <h2>Активность</h2>
    {!activity.online && <p className="muted">Устройство не в сети. Показано последнее наблюдение.</p>}
    {activity.online && !activity.fresh && <p className="muted">Данные об активности устарели. Показано последнее наблюдение.</p>}
    <dl className="detail-grid">
      <div><dt>Пользователь</dt><dd>{sections.user_login ?? 'Нет данных'}</dd></div>
      <div><dt>{activity.fresh ? 'Состояние' : 'Последнее состояние'}</dt><dd>{stateLabels[sections.session_state]}</dd></div>
      <div><dt>Неактивность</dt><dd>{sections.idle_seconds === null ? '—' : `${sections.idle_seconds.toLocaleString('ru-RU')} с`}</dd></div>
      <div><dt>Активное приложение</dt><dd>{sections.foreground?.process_name ?? 'Нет данных'}</dd></div>
      <div><dt>Категория</dt><dd>{sections.foreground ? categoryLabels[sections.foreground.application_category] : 'Нет данных'}</dd></div>
      <div><dt>Браузер</dt><dd>{sections.browser ? browserLabels[sections.browser.browser_family] : 'Нет данных'}</dd></div>
      <div><dt>Домен</dt><dd>{sections.browser?.domain ?? 'Нет данных'}</dd></div>
      <div><dt>Последнее наблюдение</dt><dd>{dateText(activity.last_observed_at)}</dd></div>
    </dl>
  </section>
}
