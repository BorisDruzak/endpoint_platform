import { useEffect, useRef, useState } from 'react'
import { ApiError } from './api'
import { getSupportAccess, getSupportPlatform, revokeSupportAccess, saveSupportPolicy, type SupportStatus, type SupportPlatform } from './supportAccessApi'

const dateText = (value: string | null) => value && Number.isFinite(Date.parse(value))
  ? new Date(value).toLocaleString('ru-RU') : 'Нет данных'
const failures: Record<string, string> = {
  dependency_unavailable: 'Компоненты OpenSSH недоступны', configuration_conflict: 'Конфликт конфигурации SSH',
  key_conflict: 'Конфликт ключей', policy_unavailable: 'Политика недоступна', tunnel_failed: 'Не удалось подключить туннель',
  host_key_mismatch: 'Ключ SSH-сервера не совпадает с доверенным', service_failed: 'Ошибка службы доступа',
}
const windowsAdminPattern = /^(?=.{1,64}$)(?:[A-Za-z0-9][A-Za-z0-9_\-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$/
function supportsDomainPrincipal(version: string) {
  if (version.match(/^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/)?.[0] !== version) return false
  const [major, minor, patch] = version.split('.').map(Number)
  return major > 1 || (major === 1 && (minor > 0 || patch >= 1))
}
function operatorKeys(text: string): string[] | null {
  const values = text.split(/\r?\n/).map(value => value.trim()).filter(Boolean)
  if (!values.length || values.length > 16 || new Set(values).size !== values.length) return null
  for (const key of values) {
    const match = /^ssh-ed25519 ([A-Za-z0-9+/]{68})$/.exec(key)
    if (!match) return null
    try {
      const blob = atob(match[1])
      if (blob.length !== 51 || blob.slice(0, 19) !== '\0\0\0\x0bssh-ed25519\0\0\0\x20') return null
    } catch { return null }
  }
  return values
}

export function SupportAccess({ deviceId, canWrite }: { deviceId: string; canWrite: boolean }) {
  return <SupportAccessView key={deviceId} deviceId={deviceId} canWrite={canWrite} />
}

function SupportAccessView({ deviceId, canWrite }: { deviceId: string; canWrite: boolean }) {
  const [platform, setPlatform] = useState<SupportPlatform | null>(null)
  const [state, setState] = useState<SupportStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [unregistered, setUnregistered] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const [reason, setReason] = useState('')
  const [keys, setKeys] = useState('')
  const [username, setUsername] = useState('')
  const [uid, setUid] = useState('')
  const [hours, setHours] = useState('1')
  const [now, setNow] = useState(Date.now())
  const generation = useRef(0)

  useEffect(() => {
    const current = ++generation.current
    setLoading(true); setError(''); setUnregistered(false); setState(null); setPlatform(null)
    setUsername(''); setUid(''); setKeys(''); setReason('')
    let discovered: SupportPlatform | null = null
    getSupportPlatform(deviceId).then(value => {
      if (generation.current !== current) return null
      if (value.device_id !== deviceId || !['windows_amd64', 'linux_amd64'].includes(value.platform ?? '')) throw new Error('Платформа устройства не подтверждена сервером. Действия заблокированы.')
      discovered = value.platform
      return getSupportAccess(deviceId, discovered!)
    }).then(value => {
      if (generation.current !== current) return
      if (!value || value.policy.device_id !== deviceId || (discovered === 'linux_amd64' ? value.policy.platform !== 'linux_amd64' : value.policy.platform !== undefined)) throw new Error('Платформа ответа не совпадает с подтверждённой платформой устройства.')
      if (discovered === 'linux_amd64' && !value.configured_policy) throw new Error('Сохранённая политика Linux недоступна. Обновите состояние.')
      const configured = value.configured_policy ?? value.policy
      setPlatform(discovered); setState(value); setKeys(configured.operator_public_keys.join('\n'))
      setUsername(discovered === 'linux_amd64' ? configured.linux_admin_username ?? '' : value.policy.windows_admin_username ?? '')
      setUid(configured.linux_admin_uid == null ? '' : String(configured.linux_admin_uid)); setLoading(false)
    }).catch(cause => {
      if (generation.current !== current) return
      setState(null); setLoading(false)
      if (discovered && cause instanceof ApiError && cause.status === 404) setUnregistered(true)
      else setError(cause instanceof Error ? cause.message : 'Не удалось загрузить доступ поддержки')
    })
    return () => { generation.current++ }
  }, [deviceId, revision])
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 15000)
    return () => window.clearInterval(timer)
  }, [])

  const linux = platform === 'linux_amd64'
  async function mutate(action: 'enable' | 'disable' | 'revoke' | 'reset-registration' | 'verify-access') {
    if (!state || !platform || !canWrite || busy || reason.trim().length < 3) return
    const approvedKeys = operatorKeys(keys)
    const duration = Number(hours)
    const validPrincipal = linux ? /^[a-z_][a-z0-9_-]{0,31}$/.test(username) && /^(0|[1-9][0-9]{0,9})$/.test(uid) && Number(uid) <= 2147483647 : username.match(windowsAdminPattern)?.[0] === username
    if (action === 'enable' && (!approvedKeys || !validPrincipal || !Number.isFinite(duration) || duration <= 0 || duration > 8)) {
      setError(linux ? 'Укажите публичные ключи Ed25519, точное имя существующего администратора Linux, целый UID от 0 до 2147483647 и срок до 8 часов.' : 'Укажите публичные ключи Ed25519, существующую локальную учётную запись или ДОМЕН\\пользователь и срок от 0 до 8 часов.'); return
    }
    const reportAge = state.reported_at ? Date.now() - Date.parse(state.reported_at) : NaN
    const domainReady = state.installed && reportAge >= -30000 && reportAge <= 90000 && supportsDomainPrincipal(state.component_version)
    if (!linux && action === 'enable' && username.includes('\\') && !domainReady) {
      setError('Для доменной учётной записи требуется свежий отчёт установленного компонента доступа поддержки 1.0.1 или новее. Обновите компонент и его состояние.'); return
    }
    const current = generation.current
    setBusy(true); setError(''); setNotice('')
    try {
      if (action === 'enable' || action === 'disable') {
        const configured = state.configured_policy ?? state.policy
        await saveSupportPolicy(deviceId, { enabled: action === 'enable',
          expires_at: action === 'enable' ? new Date(Date.now() + duration * 3600000).toISOString() : null,
          operator_public_keys: action === 'enable' ? approvedKeys! : configured.operator_public_keys,
          ...(linux ? { platform: 'linux_amd64' as const, linux_admin_username: action === 'enable' ? username : configured.linux_admin_username ?? null,
            linux_admin_uid: action === 'enable' ? Number(uid) : configured.linux_admin_uid ?? null } : {
            windows_admin_username: action === 'enable' ? (username.includes('\\') ? username.toLowerCase() : username) : state.policy.windows_admin_username ?? null }),
          reason: reason.trim() }, platform)
      } else await revokeSupportAccess(deviceId, action, reason.trim(), platform)
      if (generation.current !== current) return
      setNotice(action === 'verify-access' ? 'Подтверждение оператора сохранено. Console не выполнял SSH-команду.' : action === 'reset-registration' ? 'Разрешена одна повторная регистрация с новыми ключами. Доступ выключен.' : 'Изменение доступа сохранено.')
      setRevision(value => value + 1)
    } catch (cause) {
      if (generation.current !== current) return
      setError(cause instanceof ApiError && cause.status === 409
        ? 'Обнаружен конфликт регистрации или ключей. Обновите состояние и проверьте политику.'
        : cause instanceof Error ? cause.message : 'Не удалось изменить доступ')
    } finally { if (generation.current === current) setBusy(false) }
  }

  const fresh = !!state?.reported_at && Number.isFinite(Date.parse(state.reported_at))
    && now - Date.parse(state.reported_at) >= -30000 && now - Date.parse(state.reported_at) <= 90000
  const enabled = !!state?.policy.enabled && !!state.policy.expires_at && Date.parse(state.policy.expires_at) > now
  return <section className="panel support-access" aria-labelledby="support-access-heading">
    <div className="page-heading"><h2 id="support-access-heading">Доступ поддержки</h2><button disabled={loading || busy} onClick={() => setRevision(value => value + 1)}>Обновить доступ</button></div>
    <p className="muted">Независимый канал диагностики. Подключение туннеля само по себе не подтверждает вход по SSH.</p>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {loading ? <p aria-live="polite">Загрузка доступа поддержки…</p> : unregistered ? <p>Компонент доступа поддержки не зарегистрирован. Требуется установка подписанного компонента с действующей регистрацией устройства.</p> : state && <>
      <dl className="detail-grid">
        <div><dt>Компонент</dt><dd>{state.installed ? `Установлен · ${state.component_version}` : `Установка не подтверждена · ${state.component_version}`}</dd></div>
        <div><dt>Политика доступа</dt><dd>{enabled ? 'Включена' : 'Выключена'}</dd></div>
        <div><dt>Туннель</dt><dd>{!fresh ? 'Текущее подключение не подтверждено' : state.tunnel_connected ? 'Подключён по отчёту компонента' : 'Не подключён по отчёту компонента'}</dd></div>
        <div><dt>Свежесть отчёта</dt><dd>{fresh ? 'Свежий отчёт' : state.reported_at ? 'Отчёт устарел' : 'Отчёт не получен'} · {dateText(state.reported_at)}</dd></div>
        <div><dt>Проверка SSH-доступа</dt><dd>{state.access_verified_at ? `${enabled ? 'Подтверждение оператора' : 'Историческое подтверждение оператора'} · ${dateText(state.access_verified_at)} · ${state.access_verified_by ?? 'Оператор'}` : 'Оператор не подтвердил SSH-доступ'}</dd></div>
        <div><dt>Срок действия политики</dt><dd>{dateText(state.policy.expires_at)}</dd></div>
        <div><dt>Существующая учётная запись {linux ? 'Linux' : 'Windows'}</dt><dd>{linux ? state.policy.linux_admin_username == null ? 'Не назначена' : `${state.policy.linux_admin_username} · UID ${state.policy.linux_admin_uid}` : state.policy.windows_admin_username ?? 'Не назначена'}</dd></div>
        <div><dt>Шлюз</dt><dd>{state.policy.gateway_host}:{state.policy.gateway_port} · {state.policy.tunnel_user}</dd></div>
        <div><dt>Порт устройства на шлюзе</dt><dd>127.0.0.1:{state.policy.remote_port}</dd></div>
      </dl>
      {linux && state.configured_policy && <p className="muted">Сохранённая настройка: {state.configured_policy.enabled ? 'включена' : 'выключена'} · Исходный срок: {dateText(state.configured_policy.expires_at)}. Фактическая доступность показана выше. Обновление страницы и переустановка не продлевают доступ.</p>}
      <details><summary>SSH-ключ устройства, привязанный к Device UUID</summary><p><code>{state.policy.device_id}</code></p><p><code>{state.host_public_key}</code></p></details>
      {state.revoked_at && <p>Доступ отозван · {dateText(state.revoked_at)}</p>}
      {state.reset_registration_allowed && <p>Ожидается повторная регистрация с новыми ключами. Доступ выключен до завершения регистрации и отдельного включения политики.</p>}
      {state.last_error_code && <p>{failures[state.last_error_code] ?? 'Компонент сообщил об ошибке'}</p>}
      {!linux && !supportsDomainPrincipal(state.component_version) && <p className="muted">Этот компонент поддерживает локальные учётные записи. Для ДОМЕН\пользователь требуется версия компонента 1.0.1 или новее.</p>}
      {canWrite ? <div className="form-grid">
        {linux ? <><label>Существующий администратор Linux<input value={username} maxLength={32} pattern="[a-z_][a-z0-9_\-]{0,31}" onChange={event => setUsername(event.target.value)} /></label>
          <label>UID администратора Linux<input inputMode="numeric" value={uid} maxLength={10} onChange={event => setUid(event.target.value)} /></label>
          <p className="muted">Укажите точную существующую пару имени и UID. root с UID 0 допускается только при явном назначении; компонент отдельно проверяет учётную запись и административный доступ.</p></> : <label>Существующий администратор Windows (локальный или ДОМЕН\пользователь)<input value={username} maxLength={64} pattern={windowsAdminPattern.source} placeholder="test_agent_win или SOSNADM\admin-2" onChange={event => setUsername(event.target.value)} /></label>}
        <label>Срок доступа, часов<input type="number" min="0.25" max="8" step="0.25" value={hours} onChange={event => setHours(event.target.value)} /></label>
        <label>Публичные ключи операторов<textarea rows={4} maxLength={2200} value={keys} placeholder="ssh-ed25519 … (один публичный ключ в строке)" onChange={event => setKeys(event.target.value)} /></label>
        <label>Причина изменения доступа<input value={reason} minLength={3} maxLength={256} onChange={event => setReason(event.target.value)} /></label>
        <div className="actions">
          <button disabled={busy || reason.trim().length < 3 || state.reset_registration_allowed} onClick={() => void mutate('enable')}>Включить доступ</button>
          <button disabled={busy || reason.trim().length < 3} onClick={() => void mutate('disable')}>Выключить доступ</button>
          <button disabled={busy || reason.trim().length < 3} onClick={() => void mutate('revoke')}>Отозвать доступ</button>
          <button disabled={busy || reason.trim().length < 3} onClick={() => void mutate('reset-registration')}>Сбросить регистрацию ключей</button>
          <button disabled={busy || reason.trim().length < 3 || !enabled} onClick={() => void mutate('verify-access')}>Подтвердить выполненную SSH-команду</button>
        </div>
        <p className="muted">Отзыв делает прежний ключ политики недействительным. Сброс разрешает установщику однократно зарегистрировать новые ключи этого устройства; политика останется выключенной.</p>
        <p className="muted">Подтверждайте SSH-доступ только после реальной команды администратора через проверенный канал. Это свидетельство оператора, а не автоматическая проверка Console.</p>
      </div> : <p className="muted">Для изменения доступа требуется право управления обновлениями.</p>}
    </>}
  </section>
}
