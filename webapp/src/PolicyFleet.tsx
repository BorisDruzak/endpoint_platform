import { useEffect, useState, type FormEvent } from 'react'
import { request } from './api'

type Compliance = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'STALE' | 'UNSUPPORTED'
type Sensor = 'NOT_APPLICABLE' | 'ACTIVE' | 'UNKNOWN' | 'UNAVAILABLE' | 'STALE' | 'UNSUPPORTED'
type Delivery = 'PENDING' | 'APPLIED' | 'STALE' | 'UNSUPPORTED' | 'ERROR'
type FleetRow = {
  id: string; device_identifier: string; display_name: string; agent_version: string | null
  online: boolean; policy_name: string | null; policy_version: number | null
  applied_version: number | null; delivery_status: Delivery | null
  compliance: Compliance | null; acknowledged_at: string | null
  activity_sensor: Sensor; browser_sensor: Sensor; dlp_sensor: Sensor
}
type FleetPage = { data: FleetRow[]; total: number; limit: number; offset: number }

const complianceLabels: Record<Compliance, string> = {
  COMPLIANT: 'Соответствует', PARTIAL: 'Частично соответствует',
  NON_COMPLIANT: 'Не соответствует', STALE: 'Данные устарели',
  UNSUPPORTED: 'Не поддерживается агентом',
}
const sensorLabels: Record<Sensor, string> = {
  NOT_APPLICABLE: 'Не требуется', ACTIVE: 'Активен', UNKNOWN: 'Нет подтверждения',
  UNAVAILABLE: 'Недоступен', STALE: 'Данные устарели', UNSUPPORTED: 'Не поддерживается агентом',
}
const deliveryLabels: Record<Delivery, string> = {
  PENDING: 'Ожидает применения', APPLIED: 'Применена', STALE: 'Устарела',
  UNSUPPORTED: 'Агент не поддерживает политику', ERROR: 'Ошибка применения',
}
const dateText = (value: string | null) => value
  ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : 'Нет данных'
const LIMIT = 50

export function PolicyFleet() {
  const [compliance, setCompliance] = useState<Compliance | ''>('')
  const [searchDraft, setSearchDraft] = useState('')
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [page, setPage] = useState<FleetPage | null>(null)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    let active = true
    setPage(null)
    setError('')
    const params = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) })
    if (compliance) params.set('compliance', compliance)
    if (search) params.set('search', search)
    request<FleetPage>(`/api/admin/console/policies/fleet?${params}`)
      .then(value => { if (active) { setPage(value); setError('') } })
      .catch(() => { if (active) { setPage(null); setError('Не удалось загрузить состояние политики устройств') } })
    return () => { active = false }
  }, [compliance, search, offset, revision])

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setOffset(0)
    setSearch(searchDraft.trim())
  }

  return <section className="panel table-panel">
    <div className="table-top"><h2>Состояние политики по устройствам</h2><span>{page?.total.toLocaleString('ru-RU') ?? '—'} всего</span></div>
    <form className="filters" onSubmit={submitSearch}>
      <label>Соответствие<select value={compliance} onChange={event => {
        setOffset(0); setCompliance(event.target.value as Compliance | '')
      }}>
        <option value="">Все</option>
        {Object.entries(complianceLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <label>Поиск устройства<input value={searchDraft} maxLength={128}
        onChange={event => setSearchDraft(event.target.value)} placeholder="Имя или идентификатор" /></label>
      <button type="submit">Найти</button>
    </form>
    {error ? <div role="alert"><p>{error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить</button></div>
      : !page ? <p aria-live="polite">Загрузка состояния политики…</p>
        : <>
          {page.data.length ? <div className="table-scroll"><table>
            <thead><tr><th>Устройство</th><th>Агент</th><th>Политика</th><th>Применена версия</th>
              <th>Соответствие</th><th>Последнее подтверждение</th><th>Активность</th>
              <th>Browser Sensor</th><th>DLP</th><th></th></tr></thead>
            <tbody>{page.data.map(item => <tr key={item.id}>
              <td><strong>{item.display_name}</strong><small>{item.device_identifier}</small></td>
              <td>{item.agent_version ?? 'Нет данных'}<small>{item.online ? 'В сети' : 'Не в сети'}</small></td>
              <td>{item.policy_name ?? 'Не назначена'}<small>{item.policy_version === null ? '' : `Версия ${item.policy_version}`}</small></td>
              <td>{item.applied_version === null ? 'Нет данных' : `Версия ${item.applied_version}`}
                <small>{item.delivery_status ? deliveryLabels[item.delivery_status] : ''}</small></td>
              <td>{item.compliance ? complianceLabels[item.compliance] : 'Не оценено'}</td>
              <td>{dateText(item.acknowledged_at)}</td>
              <td>{sensorLabels[item.activity_sensor]}</td>
              <td>{sensorLabels[item.browser_sensor]}</td>
              <td>{sensorLabels[item.dlp_sensor]}</td>
              <td><a href={`/admin/devices/${item.id}`}>Открыть</a></td>
            </tr>)}</tbody>
          </table></div> : <p className="empty-text">Устройства по заданным условиям не найдены.</p>}
          <div className="pagination"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LIMIT))}>Назад</button>
            <span>{page.total ? `${offset + 1}–${Math.min(offset + LIMIT, page.total)}` : '0'} из {page.total}</span>
            <button disabled={offset + LIMIT >= page.total || offset + LIMIT > 100_000} onClick={() => setOffset(offset + LIMIT)}>Далее</button></div>
        </>}
  </section>
}
