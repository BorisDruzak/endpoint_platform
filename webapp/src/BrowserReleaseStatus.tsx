import { useEffect, useState } from 'react'
import { ApiError, request } from './api'

type BrowserRelease = {
  extension_version: string
  extension_id: string
  protocol_version: number
  source_revision: string
  artifact_sha256: string
  minimum_agent_version: string
  built_at: string
  published_at: string
  update_url: string
  artifact_url: string
}

const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', {
  dateStyle: 'medium', timeStyle: 'short',
}).format(new Date(value))

export function BrowserReleaseStatus() {
  const [release, setRelease] = useState<BrowserRelease | null>(null)
  const [state, setState] = useState<'loading' | 'published' | 'missing' | 'error'>('loading')

  useEffect(() => {
    let active = true
    request<BrowserRelease>('/api/admin/console/browser-sensor/release')
      .then(value => { if (active) { setRelease(value); setState('published') } })
      .catch(reason => { if (active) setState(reason instanceof ApiError && reason.status === 404
        ? 'missing' : 'error') })
    return () => { active = false }
  }, [])

  return <section className="panel">
    <h2>Browser Sensor</h2>
    {state === 'loading' && <p aria-live="polite">Загрузка релиза Browser Sensor…</p>}
    {state === 'missing' && <p>Релиз Browser Sensor ещё не опубликован.</p>}
    {state === 'error' && <p role="alert">Не удалось загрузить релиз Browser Sensor.</p>}
    {state === 'published' && release && <>
      <dl className="detail-grid">
        <div><dt>Текущий релиз</dt><dd>{release.extension_version}</dd></div>
        <div><dt>Extension ID</dt><dd><code>{release.extension_id}</code></dd></div>
        <div><dt>Протокол</dt><dd>{release.protocol_version}</dd></div>
        <div><dt>SHA-256</dt><dd><code>{release.artifact_sha256}</code></dd></div>
        <div><dt>Минимальная версия Agent</dt><dd>{release.minimum_agent_version}</dd></div>
        <div><dt>Ревизия исходников</dt><dd><code>{release.source_revision}</code></dd></div>
        <div><dt>Собран</dt><dd>{dateText(release.built_at)}</dd></div>
        <div><dt>Опубликован</dt><dd>{dateText(release.published_at)}</dd></div>
      </dl>
      <p><a href={release.update_url}>Манифест обновления</a> · <a href={release.artifact_url}>Подписанный пакет</a></p>
      <p className="muted">Установка выполняется через корпоративные политики Chrome и Яндекс Браузера.</p>
    </>}
  </section>
}
