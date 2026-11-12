import { useId } from 'react'

export const serverRoleLabels = {
  endpoint_platform: 'Endpoint Platform',
  openvpn: 'OpenVPN',
  directum: 'Directum RX',
  ad_directum: 'AD и Directum RX',
  ad_consultant: 'AD и КонсультантПлюс',
  proxmox: 'Proxmox VE',
}

export type ServerRole = keyof typeof serverRoleLabels

const statuses = {
  ok: ['В норме', 'online'],
  warning: ['Предупреждение', 'warning'],
  critical: ['Критично', 'critical'],
  failed: ['Ошибка', 'critical'],
  missing: ['Отсутствует', 'critical'],
  unknown: ['Нет данных', 'offline'],
}

type Status = keyof typeof statuses

export type ServerHealth = {
  role: ServerRole
  services: { name: string; status: Status; observed_state: string | null }[]
  volumes: {
    mount: string; status: Status; used_percent: number | null
    free_bytes: number | null; total_bytes: number | null
  }[]
  applications: { name: string; status: Status; http_status: number | null }[]
}

const applicationLabels: Record<string, string> = {
  endpoint_api_health: 'Endpoint API',
  openvpn_web_http: 'Веб-панель OpenVPN',
  openvpn_udp_listener: 'OpenVPN UDP 1194',
  directum_http: 'Веб-приложение Directum RX',
  directum_rabbitmq_tcp: 'RabbitMQ TCP 5672',
  ad_dns_tcp: 'DNS TCP 53',
  ad_kerberos_tcp: 'Kerberos TCP 88',
  ad_ldap_tcp: 'LDAP TCP 389',
  consultant_http: 'Веб-приложение КонсультантПлюс',
  consultant_tcp: 'КонсультантПлюс TCP 20024',
  proxmox_api: 'Локальный HTTPS API Proxmox',
  proxmox_quorum: 'Кворум кластера',
  proxmox_members: 'Доступность узлов кластера',
  proxmox_storage: 'Хранилища Proxmox',
}

const number = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 })

type Check = { label: string; status: Status; details: string | null }

function CheckList({ title, checks }: { title: string; checks: Check[] }) {
  return <div>
    <h3>{title}</h3>
    {checks.length === 0 ? <p className="muted">Нет проверок</p> :
      <ul className="server-checks">
        {checks.map(check => {
          const [label, tone] = statuses[check.status]
          return <li key={check.label}>
            <div>
              <strong>{check.label}</strong>
              {check.details && <small>{check.details}</small>}
            </div>
            <span className={`status ${tone}`}>{label}</span>
          </li>
        })}
      </ul>}
  </div>
}

export function ServerHealthChecks({ health, observed, fresh }: {
  health: ServerHealth; observed: string; fresh: boolean
}) {
  const heading = useId()
  const serviceChecks = health.services.map(item => ({
    label: item.name, status: item.status, details: item.observed_state,
  }))
  const volumeChecks = health.volumes.map(item => ({
    label: item.mount, status: item.status,
    details: item.used_percent === null || item.free_bytes === null ? null :
      `Занято ${number.format(item.used_percent)}% · Свободно ${number.format(item.free_bytes / 1024 ** 3)} ГиБ`,
  }))
  const applicationChecks = health.applications.map(item => ({
    label: applicationLabels[item.name] ?? item.name, status: item.status,
    details: item.name === 'proxmox_api' && item.http_status === 401 && item.status === 'ok'
      ? 'TLS проверен · API требует входа'
      : item.http_status === null ? null : `HTTP ${item.http_status}`,
  }))
  return <section className="panel server-health" aria-labelledby={heading}>
    <h2 id={heading}>Серверные проверки</h2>
    <p><span className="status offline">Профиль · {serverRoleLabels[health.role]}</span></p>
    <p className="muted">Последнее наблюдение · {observed}{!fresh && ' · Данные устарели'}</p>
    <div className="server-health-groups">
      <CheckList title="Службы" checks={serviceChecks} />
      <CheckList title="Тома" checks={volumeChecks} />
      <CheckList title="Приложения" checks={applicationChecks} />
    </div>
  </section>
}
