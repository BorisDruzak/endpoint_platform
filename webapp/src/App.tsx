import { useEffect, useState, type FormEvent } from 'react'
import { NavLink, Route, Routes, useNavigate } from 'react-router'
import { ApiError, getSession, login, logout, type AdminSession } from './api'
import { DashboardPage, DeviceDetailPage, DevicesPage } from './FleetPages'
import { EnrollmentPage } from './EnrollmentPage'
import { UpdatesPage } from './UpdatesPage'
import { OperationsPage } from './OperationsPage'
import { ModulesPage } from './ModulesPage'
import { AuditPage } from './AuditPage'

const navigation = [
  { to: '/admin', label: 'Главная', end: true },
  { to: '/admin/devices', label: 'Устройства' },
  { to: '/admin/enrollment', label: 'Установка и регистрация' },
  { to: '/admin/updates', label: 'Релизы и обновления' },
  { to: '/admin/operations', label: 'Операции' },
  { to: '/admin/modules', label: 'Модули' },
  { to: '/admin/audit', label: 'Аудит' },
]

function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(username, password)
      navigate('/admin', { replace: true })
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось войти')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-page">
      <form className="login-panel" onSubmit={submit}>
        <p className="product-name">Endpoint Platform</p>
        <h1>Вход в консоль</h1>
        <p className="muted">Административный доступ к устройствам и операциям</p>
        <label htmlFor="username">Имя пользователя</label>
        <input id="username" autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required />
        <label htmlFor="password">Пароль</label>
        <input id="password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required />
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary-button" type="submit" disabled={busy}>{busy ? 'Выполняется вход…' : 'Войти'}</button>
      </form>
    </main>
  )
}

function PendingPage({ title }: { title: string }) {
  return <section className="empty-panel"><h2>{title}</h2><p>Раздел готовится к подключению.</p></section>
}

function Console() {
  const navigate = useNavigate()
  const [session, setSession] = useState<AdminSession | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    getSession().then(value => {
      if (active) setSession(value)
    }).catch(reason => {
      if (!active) return
      if (reason instanceof ApiError && reason.status === 401) navigate('/admin/login', { replace: true })
      else setError(reason instanceof Error ? reason.message : 'Не удалось загрузить сеанс')
    })
    return () => { active = false }
  }, [navigate])

  async function signOut() {
    try {
      await logout()
      navigate('/admin/login', { replace: true })
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось выйти')
    }
  }

  if (error) return <main className="state-page"><p role="alert">{error}</p><button onClick={() => window.location.reload()}>Повторить</button></main>
  if (!session) return <main className="state-page" aria-live="polite">Проверка сеанса…</main>

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">Endpoint Platform</div>
        <nav aria-label="Основная навигация">
          {navigation.map(item => <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>{item.label}</NavLink>)}
        </nav>
      </aside>
      <div className="content-shell">
        <header className="topbar">
          <strong>Endpoint Platform</strong>
          <div className="account"><span>{session.username}</span><button type="button" onClick={signOut}>Выйти</button></div>
        </header>
        <main className="content">
          <Routes>
            <Route path="/admin" element={<DashboardPage />} />
            <Route path="/admin/devices" element={<DevicesPage />} />
            <Route path="/admin/devices/:deviceId" element={<DeviceDetailPage />} />
            <Route path="/admin/enrollment/*" element={<EnrollmentPage />} />
            <Route path="/admin/updates/*" element={<UpdatesPage canWrite={session.scopes.includes('updates:write')} />} />
            <Route path="/admin/operations/*" element={<OperationsPage />} />
            <Route path="/admin/modules/*" element={<ModulesPage />} />
            <Route path="/admin/audit/*" element={<AuditPage />} />
            <Route path="*" element={<PendingPage title="Страница не найдена" />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export function App() {
  return <Routes><Route path="/admin/login" element={<LoginPage />} /><Route path="*" element={<Console />} /></Routes>
}
