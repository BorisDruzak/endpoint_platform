export type AdminSession = {
  username: string
  scopes: string[]
  csrf_token: string
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message)
  }
}

let csrfToken: string | null = null

async function safeFetch(path: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(path, init)
  } catch {
    throw new ApiError(0, 'Не удалось связаться с сервером')
  }
}

export async function getSession(): Promise<AdminSession> {
  const response = await safeFetch('/api/admin/console/session', {
    credentials: 'same-origin',
    cache: 'no-store',
  })
  if (!response.ok) throw new ApiError(
    response.status,
    response.status >= 500 ? 'Сервер временно недоступен' : 'Не удалось проверить сеанс администратора',
  )
  const session = (await response.json()) as AdminSession
  csrfToken = session.csrf_token
  return session
}

export async function login(username: string, password: string): Promise<void> {
  const response = await safeFetch('/api/admin/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!response.ok) throw new ApiError(
    response.status,
    response.status === 401 ? 'Неверное имя пользователя или пароль' : 'Сервер временно недоступен',
  )
  const data = (await response.json()) as { csrf_token: string }
  csrfToken = data.csrf_token
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    if (!csrfToken) throw new ApiError(403, 'Сеанс устарел. Войдите снова')
    headers.set('X-CSRF-Token', csrfToken)
  }
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const response = await safeFetch(path, {
    ...init,
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
  })
  if (response.status === 401) {
    csrfToken = null
    throw new ApiError(401, 'Сеанс завершён. Войдите снова')
  }
  if (response.status === 403) throw new ApiError(403, 'Недостаточно прав для действия')
  if (!response.ok) throw new ApiError(
    response.status,
    response.status >= 500 ? 'Сервер временно недоступен' : 'Не удалось выполнить запрос',
  )
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T)
}

export async function logout(): Promise<void> {
  await request<void>('/api/admin/session', { method: 'DELETE' })
  csrfToken = null
}
