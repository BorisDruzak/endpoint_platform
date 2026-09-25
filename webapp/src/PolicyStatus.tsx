import { useEffect, useState } from 'react'
import { ApiError, request } from './api'

type BrowserStatus = {
  browser_family: 'chrome' | 'yandex'
  browser_state: 'DETECTED' | 'ABSENT' | 'UNKNOWN' | null
  running_state: 'RUNNING' | 'CLOSED' | 'UNKNOWN' | null
  policy_owner: 'ENDPOINT' | 'EXTERNAL' | 'NONE' | 'CONFLICT' | 'UNKNOWN' | null
  installation_policy_state: 'APPLIED' | 'NOT_APPLIED' | 'CONFLICT' | 'UNKNOWN' | null
  native_host_state: 'READY' | 'MISSING' | 'UNKNOWN' | null
  extension_version: string | null
  extension_install_type: 'ADMIN' | 'OTHER' | 'UNKNOWN' | null
  extension_last_seen_at: string | null
  last_running_at: string | null
  compliance_state: 'NOT_APPLICABLE' | 'UNKNOWN' | 'NEVER_SEEN' | 'ACTIVE' | 'STALE' | 'ERROR'
  reason: string | null
}
type PolicyStatus = {
  policy_id: string; policy_version: number; policy_version_id: string
  browser_required: boolean; deployment_mode: 'agent_managed' | 'external_managed'
  delivery_status: 'PENDING' | 'APPLIED' | 'STALE' | 'UNSUPPORTED' | 'ERROR'
  acknowledged_at: string | null
  browser_compliance: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'STALE' | 'UNSUPPORTED'
  observed_at: string | null
  browsers: BrowserStatus[]
}

const dateText = (value: string | null) => value
  ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : 'Нет данных'
const deliveryLabels: Record<PolicyStatus['delivery_status'], string> = {
  PENDING: 'Ожидает применения', APPLIED: 'Применена', STALE: 'Устарела',
  UNSUPPORTED: 'Агент не поддерживает политику', ERROR: 'Ошибка применения',
}
const complianceLabels: Record<PolicyStatus['browser_compliance'], string> = {
  COMPLIANT: 'Соответствует', PARTIAL: 'Частично соответствует',
  NON_COMPLIANT: 'Не соответствует', STALE: 'Данные устарели', UNSUPPORTED: 'Не поддерживается агентом',
}
const browserLabels: Record<BrowserStatus['browser_family'], string> = { chrome: 'Chrome', yandex: 'Яндекс Браузер' }
const browserStateLabels: Record<NonNullable<BrowserStatus['browser_state']>, string> = {
  DETECTED: 'Обнаружен', ABSENT: 'Не обнаружен', UNKNOWN: 'Неизвестно',
}
const runningLabels: Record<NonNullable<BrowserStatus['running_state']>, string> = {
  RUNNING: 'Открыт', CLOSED: 'Закрыт', UNKNOWN: 'Неизвестно',
}
const ownerLabels: Record<NonNullable<BrowserStatus['policy_owner']>, string> = {
  ENDPOINT: 'Endpoint Agent', EXTERNAL: 'Внешняя политика', NONE: 'Нет',
  CONFLICT: 'Конфликт', UNKNOWN: 'Неизвестно',
}
const installationLabels: Record<NonNullable<BrowserStatus['installation_policy_state']>, string> = {
  APPLIED: 'Настроена на устройстве', NOT_APPLIED: 'Не настроена', CONFLICT: 'Конфликт', UNKNOWN: 'Неизвестно',
}
const nativeHostLabels: Record<NonNullable<BrowserStatus['native_host_state']>, string> = {
  READY: 'Готов', MISSING: 'Не найден', UNKNOWN: 'Неизвестно',
}
const extensionLabels: Record<BrowserStatus['compliance_state'], string> = {
  NOT_APPLICABLE: 'Не требуется', UNKNOWN: 'Нет подтверждения', NEVER_SEEN: 'Ещё не обнаружено',
  ACTIVE: 'Активно', STALE: 'Связь устарела', ERROR: 'Ошибка',
}
const reasonLabels: Record<string, string> = {
  AGENT_UNSUPPORTED: 'Текущий агент не поддерживает Browser Sensor',
  POLICY_STALE: 'Нет текущего подключения агента или политика устарела',
  POLICY_NOT_APPLIED: 'Агент ещё не подтвердил применение политики',
  STATUS_NOT_REPORTED: 'Агент ещё не прислал состояние браузера',
  STATUS_POLICY_MISMATCH: 'Отчёт относится к другой версии политики',
  STATUS_STALE: 'Отчёт браузера устарел',
  POLICY_CONFLICT: 'Конфликт политики установки',
  BROWSER_ABSENT: 'Браузер не обнаружен',
  BROWSER_DETECTION_UNKNOWN: 'Не удалось определить наличие браузера',
  POLICY_OWNER_MISMATCH: 'Политикой установки управляет другой владелец',
  INSTALLATION_POLICY_NOT_APPLIED: 'Политика установки не настроена',
  EXTENSION_NOT_MANAGED: 'Расширение установлено без корпоративной политики',
  BROWSER_POLICY_EFFECT_UNKNOWN: 'Браузер не подтвердил корпоративную установку расширения',
  NATIVE_HOST_UNAVAILABLE: 'Native Bridge недоступен',
  BROWSER_NOT_LAUNCHED: 'Браузер не запускался после настройки политики',
  EXTENSION_NEVER_SEEN: 'Расширение ещё не выходило на связь',
  BROWSER_CLOSED: 'Браузер сейчас закрыт',
  BROWSER_RUNNING_UNKNOWN: 'Не удалось определить, открыт ли браузер',
  EXTENSION_STALE: 'Связь с расширением устарела',
}
const label = <T extends string>(value: T | null, labels: Record<T, string>) => value === null ? 'Нет данных' : labels[value]
const policyConfirmed = (browser: BrowserStatus, mode: PolicyStatus['deployment_mode']) =>
  browser.installation_policy_state === 'APPLIED'
  && browser.extension_install_type === 'ADMIN'
  && browser.policy_owner === (mode === 'agent_managed' ? 'ENDPOINT' : 'EXTERNAL')

export function DevicePolicyStatus({ deviceId }: { deviceId: string }) {
  const [status, setStatus] = useState<PolicyStatus | null | undefined>(undefined)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    request<{ data: PolicyStatus | null }>(`/api/admin/console/policies/devices/${deviceId}/status`)
      .then(value => { if (active) { setStatus(value.data); setError('') } })
      .catch(reason => { if (active) setError(reason instanceof ApiError && reason.status === 404
        ? 'Состояние политики недоступно для этого устройства'
        : reason instanceof Error ? reason.message : 'Не удалось загрузить состояние политики') })
    return () => { active = false }
  }, [deviceId])

  if (error) return <section className="panel" role="alert">{error}</section>
  if (status === undefined) return <p aria-live="polite">Загрузка политики…</p>
  if (status === null) return <section className="panel"><h2>Политика и Browser Sensor</h2><p>Политика устройству не назначена.</p></section>
  return <>
    <section className="panel"><h2>Политика и Browser Sensor</h2><dl className="detail-grid">
      <div><dt>Версия политики</dt><dd>{status.policy_version}</dd></div>
      <div><dt>Применение</dt><dd>{deliveryLabels[status.delivery_status]}</dd></div>
      <div><dt>Подтверждена</dt><dd>{dateText(status.acknowledged_at)}</dd></div>
      <div><dt>Browser Sensor</dt><dd>{status.browser_required ? 'Обязателен' : 'Не требуется'}</dd></div>
      <div><dt>Управление</dt><dd>{status.deployment_mode === 'agent_managed' ? 'Endpoint Agent' : 'Внешняя политика'}</dd></div>
      <div><dt>Соответствие</dt><dd>{complianceLabels[status.browser_compliance]}</dd></div>
      <div><dt>Последний отчёт</dt><dd>{dateText(status.observed_at)}</dd></div>
    </dl></section>
    <div className="detail-columns">{status.browsers.map(browser => <section className="panel" key={browser.browser_family}>
      <h2>{browserLabels[browser.browser_family]}</h2>
      <dl className="detail-grid">
        <div><dt>Браузер</dt><dd>{label(browser.browser_state, browserStateLabels)}</dd></div>
        <div><dt>Сейчас</dt><dd>{label(browser.running_state, runningLabels)}</dd></div>
        <div><dt>Управление</dt><dd>{label(browser.policy_owner, ownerLabels)}</dd></div>
        <div><dt>Политика установки</dt><dd>{policyConfirmed(browser, status.deployment_mode)
          ? 'Применена' : label(browser.installation_policy_state, installationLabels)}</dd></div>
        <div><dt>Native Bridge</dt><dd>{label(browser.native_host_state, nativeHostLabels)}</dd></div>
        <div><dt>Расширение</dt><dd>{extensionLabels[browser.compliance_state]}</dd></div>
        <div><dt>Версия расширения</dt><dd>{browser.extension_version ?? 'Нет данных'}</dd></div>
        <div><dt>Последняя связь</dt><dd>{dateText(browser.extension_last_seen_at)}</dd></div>
      </dl>
      {browser.installation_policy_state === 'APPLIED' && !policyConfirmed(browser, status.deployment_mode)
        ? <p className="muted">Действие политики в браузере не подтверждено</p> : null}
      {browser.reason && <p className="muted">Причина: {reasonLabels[browser.reason] ?? 'Состояние требует проверки'}</p>}
    </section>)}</div>
  </>
}
