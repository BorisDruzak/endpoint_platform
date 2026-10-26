/** Employee cookies and CSRF never share the administrative API module's state. */
export type EmployeeGrant = { role: string; department_id: string | null }
export type EmployeeSession = { person_id: string; department_id: string | null; csrf_token: string; grants: EmployeeGrant[]; privileged_assurance?: boolean }
export type WorkInterval = { id?: string; started_at: string; ended_at: string; status: string; source: string }
export type ActivityInterval = { started_at: string; ended_at: string; state: string; seconds: number; attributed: boolean }
export type Explanation = { id: string; started_at: string; ended_at: string; category_code: string; comment: string; created_at?: string }
export type Correction = { id: string; person_id: string; started_at: string; ended_at: string; status: string; reason: string; decision: string; created_at?: string }
export type ExplanationRequest = { id: string; started_at: string; ended_at: string; state: string }
export type WorkDay = {
  person_id: string; day: string; timezone: string; status: string
  work_intervals: WorkInterval[]; activity_intervals: ActivityInterval[]
  totals: { work_seconds: number; break_seconds: number; off_pc_seconds: number; scheduled_seconds: number }
  coverage: { state: string; measured_seconds: number; unknown_seconds: number }
  schedule: { started_at: string; ended_at: string }[]
  explanations: Explanation[]; corrections: Correction[]; pending_explanations: ExplanationRequest[]
}
export type WorkMonth = { person_id: string; month: string; timezone: string; days: WorkDay[]; totals: WorkDay['totals'] }
export type Category = { code: string; label: string; requires_comment: boolean }
export type HistoryEvent = { id: string; action: string; occurred_at: string; created_at?: string }
export type WorkHistory = { events: HistoryEvent[]; explanations: Explanation[]; corrections: Correction[]; approvals: { id: string; correction_id: string; decision: string; comment: string; created_at: string }[] }

export class EmployeeApiError extends Error {
  constructor(public readonly status: number, message: string, public readonly code?: string) { super(message) }
}

async function employeeFetch<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response
  try { response = await fetch(path, { ...init, credentials: 'same-origin', cache: 'no-store' }) }
  catch (reason) {
    if (reason instanceof Error && reason.name === 'AbortError') throw reason
    throw new EmployeeApiError(0, 'Не удалось связаться с сервером. Попробуйте снова.')
  }
  let stepUp = false
  if (response.status === 403) {
    try { const body = await response.json() as { detail?: { code?: string } }; stepUp = body.detail?.code === 'mfa_step_up_required' } catch { /* No server text or arbitrary redirect enters the UI. */ }
  }
  if (!response.ok) throw new EmployeeApiError(response.status,
    response.status === 401 ? 'Сеанс завершён. Войдите снова.'
      : stepUp ? 'Требуется подтверждение входа с MFA.' : response.status === 403 ? 'Нет прав на эти данные или действие.'
        : response.status === 409 ? 'Данные изменились или переход недоступен. Обновите страницу.'
          : response.status === 404 ? 'Раздел или запись недоступны.'
            : response.status === 503 ? 'Сервис пока не настроен или временно недоступен.'
              : response.status === 422 ? 'Проверьте время, причину и обязательные поля.' : 'Не удалось выполнить запрос.', stepUp ? 'mfa_step_up_required' : undefined)
  return response.status === 204 ? undefined as T : await response.json() as T
}

export function getEmployeeSession(signal?: AbortSignal) {
  return employeeFetch<EmployeeSession>('/api/employee/session', { signal })
}

/** A client belongs to one rendered identity; it cannot inherit another realm's CSRF. */
export function employeeClient(session: EmployeeSession, signal: AbortSignal, unauthorized: () => void) {
  return async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!path.startsWith('/api/employee/') && !path.startsWith('/api/dlp/')) throw new Error('Недопустимый раздел')
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
    const method = (init.method ?? 'GET').toUpperCase()
    const headers = new Headers(init.headers)
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) headers.set('X-CSRF-Token', session.csrf_token)
    if (init.body) headers.set('Content-Type', 'application/json')
    try { return await employeeFetch<T>(path, { ...init, method, headers, signal }) }
    catch (reason) {
      if (reason instanceof EmployeeApiError && reason.status === 401 && !signal.aborted) unauthorized()
      throw reason
    }
  }
}
export type EmployeeRequest = ReturnType<typeof employeeClient>
export const worktimePath = '/api/employee/worktime'
