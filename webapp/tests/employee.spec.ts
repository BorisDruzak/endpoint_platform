import { test, expect, type Page } from '@playwright/test'

/** Contract fixtures exercise the browser only; they do not establish live SSO acceptance. */
const reportDay = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Yekaterinburg', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
const personId = '00000000-0000-4000-8000-000000000001'
const targetPersonId = '00000000-0000-4000-8000-000000000005'
const baseDay = (day: string, status = 'WORKING', person = personId) => ({ person_id: person, day, timezone: 'Asia/Yekaterinburg', status,
  work_intervals: [{ id: 'work', started_at: `${day}T03:00:00Z`, ended_at: `${day}T05:00:00Z`, status: 'WORKING', source: 'employee' }],
  activity_intervals: [{ started_at: `${day}T03:00:00Z`, ended_at: `${day}T04:00:00Z`, state: 'ACTIVE', seconds: 3600, attributed: true }, { started_at: `${day}T04:00:00Z`, ended_at: `${day}T05:00:00Z`, state: 'UNKNOWN', seconds: 3600, attributed: false }],
  totals: { work_seconds: 7200, break_seconds: 0, off_pc_seconds: 0, scheduled_seconds: 28800 }, coverage: { state: 'partial', measured_seconds: 3600, unknown_seconds: 3600 },
  schedule: [{ started_at: `${day}T03:00:00Z`, ended_at: `${day}T12:00:00Z` }], explanations: [], corrections: [], pending_explanations: [{ id: '00000000-0000-4000-8000-000000000002', started_at: `${day}T04:00:00Z`, ended_at: `${day}T05:00:00Z`, state: 'pending' }] })

async function fixture(page: Page, roles: string[] = []) {
  const calls: { path: string; method: string; body: Record<string, unknown> | null; csrf?: string }[] = []
  let status = 'ENDED'
  let explanations: object[] = []
  const timesheets: Record<string, unknown>[] = []
  await page.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname
    const body = req.postDataJSON() as Record<string, unknown> | null
    calls.push({ path, method: req.method(), body, csrf: req.headers()['x-csrf-token'] })
    let data: unknown
    if (path.startsWith('/api/admin')) return route.fulfill({ status: 403, json: { detail: 'Wrong realm' } })
    if (path === '/api/employee/session') data = { person_id: personId, department_id: 'department', csrf_token: 'test-employee-csrf', grants: roles.map(role => ({ role, department_id: role === 'manager' ? 'department' : null })) }
    else if (path.endsWith('/day')) data = { ...baseDay(url.searchParams.get('day')!, status, url.searchParams.get('person_id') ?? personId), explanations }
    else if (path.endsWith('/categories')) data = { categories: [{ code: 'meeting', label: 'Совещание', requires_comment: false }, { code: 'other', label: 'Другое', requires_comment: true }] }
    else if (path.endsWith('/history')) data = { events: [], explanations, corrections: [], approvals: [] }
    else if (path.endsWith('/month') || path.endsWith('/report')) { const month = url.searchParams.get('month')!, person = url.searchParams.get('person_id') ?? personId; data = { person_id: person, month, timezone: 'Asia/Yekaterinburg', days: [baseDay(`${month}-01`, 'WORKING', person), baseDay(reportDay, 'WORKING', person)], totals: baseDay(reportDay).totals } }
    else if (path.endsWith('/transitions')) { status = ({ start: 'WORKING', break: 'BREAK', resume: 'WORKING', off_pc: 'OFF_PC', end: 'ENDED' } as Record<string, string>)[String(body?.action)]; data = { id: 'event', status } }
    else if (path.endsWith('/explanations')) { explanations = [{ ...body, id: 'explanation' }]; data = explanations[0] }
    else if (path.endsWith('/people')) data = { people: [{ person_id: targetPersonId, department_id: 'department', status: 'WORKING' }] }
    else if (path.endsWith('/approvals')) data = { corrections: [{ id: 'correction', person_id: targetPersonId, actor_id: '00000000-0000-4000-8000-000000000006', started_at: `${reportDay}T03:00:00Z`, ended_at: `${reportDay}T04:00:00Z`, status: 'OFF_PC', reason: 'Работа с документами', decision: 'pending' }] }
    else if (path.endsWith('/decision')) data = { decision: body?.decision }
    else if (path.endsWith('/schedules')) data = req.method() === 'GET' ? { schedules: [] } : { id: 'schedule', ...body }
    else if (path.endsWith('/timesheets/finalize')) { const month = String(body?.month); data = { id: '00000000-0000-4000-8000-000000000004', person_id: targetPersonId, month, version: timesheets.length + 1, timezone: 'Asia/Yekaterinburg', finalized_by: personId, finalized_at: `${reportDay}T03:00:00Z`, reason: body?.reason, source_digest: 'fixture-digest', totals: baseDay(reportDay).totals, days: [{ ...baseDay(`${month}-01`, 'WORKING', targetPersonId), approvals: [] }] }; timesheets.unshift(data as Record<string, unknown>) }
    else if (path.endsWith('/timesheets')) data = { timesheets }
    else if (path.includes('/timesheets/')) data = timesheets.find(item => path.endsWith(String(item.id)))
    else if (path === '/api/dlp/events') data = { data: [{ id: 'security-event', device_id: 'device', device_name: 'PC-PILOT', event_type: 'PRINT_JOB', occurred_at: `${reportDay}T03:00:00Z`, channel: 'PRINT', user_login: null, policy_version: 1, domain: null }], total: 1, limit: 50, offset: 0 }
    else if (path === '/api/dlp/events/security-event') data = { data: { id: 'security-event', device_name: 'PC-PILOT', event_type: 'PRINT_JOB', occurred_at: `${reportDay}T03:00:00Z`, domain: null, safe_metadata: { page_count: 2 }, metadata_valid: true } }
    else if (path === '/api/dlp/policies') data = { data: [{ id: 'policy', name: 'Аудит пилота', created_at: `${reportDay}T03:00:00Z`, versions_total: 1 }], total: 1, limit: 50, offset: 0 }
    else if (path === '/api/dlp/policies/policy/versions') data = { data: [{ version_id: 'version', policy_version: 1, digest: 'fixture-digest', created_at: `${reportDay}T03:00:00Z` }], total: 1, limit: 50, offset: 0 }
    else if (path === '/api/dlp/policies/policy/versions/version') data = { data: { version_id: 'version', policy_version: 1, digest: 'fixture-digest', created_at: `${reportDay}T03:00:00Z`, policy: { schema_version: 'endpoint_policy_v1', policy_id: 'policy', policy_version: 1, dlp: { usb_device_events: 'audit', removable_write_events: 'disabled', print_events: 'audit', browser_upload_events: 'audit', browser_paste_events: 'disabled' }, browser_sensor: { required: true, deployment_mode: 'managed' }, event_retention: { security_event_days: 90 } } } }
    else if (path === '/api/dlp/sensors') data = { data: [{ device_id: 'device', device_name: 'PC-PILOT', observed_at: `${reportDay}T03:00:00Z`, activity_listener_state: 'ready', security_spool_state: 'ready', usb_source_state: 'ready', print_source_state: 'ready' }], total: 1, limit: 50, offset: 0 }
    else data = { id: 'saved' }
    await route.fulfill({ json: data })
  })
  return calls
}

test('employee SSO entry and protected realm do not call administrative APIs', async ({ page }) => {
  const calls = await fixture(page)
  await page.goto('/employee/login')
  await expect(page.getByRole('link', { name: 'Войти с доменной учётной записью' })).toHaveAttribute('href', '/auth/employee/login')
  await expect(page.getByLabel('Пароль')).toHaveCount(0)
  await page.goto('/employee/manager')
  await expect(page.getByRole('heading', { name: 'Доступ ограничен' })).toBeVisible()
  expect(calls.length).toBeGreaterThan(0)
  expect(calls.every(call => call.path === '/api/employee/session')).toBe(true)
})

test('independent rings, keyboard explanation and week/month views', async ({ page }) => {
  const calls = await fixture(page)
  await page.goto(`/employee?day=${reportDay}`)
  await expect(page.getByText('Подтверждено: 2 ч 00 мин')).toBeVisible()
  await expect(page.getByText('Данные ПК: 50%')).toBeVisible()
  const arc = page.getByRole('button', { name: /^Рабочий статус.*Требует объяснения/ })
  await arc.focus(); await arc.press('Enter')
  await expect(page.getByRole('region', { name: 'Выбранный интервал' })).toBeVisible()
  await page.getByLabel('Причина', { exact: true }).selectOption('other')
  await expect(page.getByRole('button', { name: 'Сохранить объяснение' })).toBeDisabled()
  await page.getByLabel('Комментарий', { exact: true }).fill('Встреча по проекту')
  await page.getByRole('button', { name: 'Сохранить объяснение' }).click()
  await expect(page.getByRole('status')).toHaveText('Изменение сохранено. Итоги обновлены.')
  await expect(page.getByRole('button', { name: /^Рабочий статус.*Объяснение: Другое/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /^Рабочий статус.*Требует объяснения/ })).toHaveCount(0)
  await expect(page.getByText('Подтверждено: 2 ч 00 мин')).toBeVisible()
  await expect(page.getByRole('button', { name: /^Компьютер.*UNKNOWN/ })).toBeVisible()
  const saved = calls.find(call => call.path.endsWith('/explanations'))!
  expect(saved.body).toMatchObject({ category_code: 'other', comment: 'Встреча по проекту', request_id: '00000000-0000-4000-8000-000000000002' }); expect(saved.body).not.toHaveProperty('person_id'); expect(saved.csrf).toBe('test-employee-csrf')
  await page.getByLabel('Масштаб графика').check()
  await expect(page.getByRole('group', { name: /масштаб графика/ })).toBeVisible()
  await page.getByRole('button', { name: 'Неделя', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Неделя', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Месяц', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Календарь месяца' })).toBeVisible()
  expect(calls.every(call => !call.path.startsWith('/api/admin'))).toBe(true)
  await page.screenshot({ path: 'test-results/employee/day-and-month.png', fullPage: true })
})

test('day transitions and correction preserve employee authority', async ({ page }) => {
  const calls = await fixture(page)
  await page.goto(`/employee?day=${reportDay}`)
  for (const name of ['Начать день', 'Начать перерыв', 'Продолжить работу', 'Работа вне ПК', 'Продолжить работу', 'Завершить день']) {
    await page.getByRole('button', { name, exact: true }).click()
    await expect(page.getByText('Подтверждено: 2 ч 00 мин')).toBeVisible()
  }
  await page.getByLabel('Обоснование корректировки').fill('Работа с документами вне компьютера')
  await page.getByRole('button', { name: 'Отправить на согласование' }).click()
  await expect.poll(() => calls.filter(call => call.path.endsWith('/corrections')).length).toBe(1)
  expect(calls.filter(call => call.method === 'POST').every(call => !Object.hasOwn(call.body ?? {}, 'person_id') && !!call.body?.idempotency_key && call.csrf === 'test-employee-csrf')).toBe(true)
})

test('manager reviews an allowed employee and approves a correction', async ({ page }) => {
  const calls = await fixture(page, ['manager'])
  await page.goto('/employee/manager')
  await page.getByRole('button', { name: new RegExp(`Сотрудник ${targetPersonId} ·`) }).click()
  await expect(page.getByRole('heading', { name: 'Рабочий день сотрудника' })).toBeVisible()
  await page.getByRole('button', { name: 'Согласовать', exact: true }).click()
  await expect.poll(() => calls.filter(call => call.path.endsWith('/decision')).length).toBe(1)
  expect(calls.find(call => call.path.endsWith('/decision'))?.body).toMatchObject({ decision: 'approved' })
})

test('HR month export and versioned schedule input', async ({ page }) => {
  const calls = await fixture(page, ['hr'])
  await page.goto('/employee/reports')
  await page.getByLabel('Сотрудник табеля').selectOption(targetPersonId)
  await expect(page.getByRole('heading', { name: /Табель за/ })).toBeVisible()
  const download = page.waitForEvent('download'); await page.getByRole('button', { name: 'Экспорт CSV' }).click(); expect((await download).suggestedFilename()).toMatch(/^worktime-/)
  await page.getByLabel('Дата начала графика').fill(reportDay)
  await page.getByRole('button', { name: 'Сохранить график' }).click()
  await expect.poll(() => calls.filter(call => call.path.endsWith('/schedules') && call.method === 'POST').length).toBe(1)
})

test('DLP officer has separate events, policy and sensor navigation', async ({ page }) => {
  const calls = await fixture(page, ['dlp_officer'])
  await page.goto('/dlp')
  await page.getByRole('button', { name: /PC-PILOT.*Печать/ }).click()
  await expect(page.getByRole('region', { name: 'Детали события DLP' })).toBeVisible()
  await page.getByRole('button', { name: 'Политики', exact: true }).click()
  await expect(page.getByText('Аудит пилота', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Версии политики Аудит пилота' }).click()
  await page.getByRole('button', { name: /^Версия политики 1/ }).click()
  await expect(page.getByRole('region', { name: 'Содержимое политики DLP' })).toBeVisible()
  await expect(page.getByText('90 дней', { exact: true })).toBeVisible()
  const disabled = page.getByText('Запись на съёмный носитель', { exact: true }).locator('..')
  await expect(disabled.locator('dd')).toHaveText('Отключено')
  await expect(page.getByText('События USB', { exact: true }).locator('..').locator('dd')).toHaveText('Включено')
  await page.getByRole('button', { name: 'Состояние сенсоров', exact: true }).click()
  await expect(page.getByRole('cell', { name: 'PC-PILOT' })).toBeVisible()
  expect(calls.every(call => !call.path.startsWith('/api/admin') && !call.path.includes('/worktime/'))).toBe(true)
})

test('small screen keeps the ring, text intervals and actions within the viewport', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.setViewportSize({ width: 390, height: 844 })
  await fixture(page)
  await page.goto(`/employee?day=${reportDay}`)
  await expect(page.getByText('Подтверждено: 2 ч 00 мин')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.getByRole('button', { name: /^Текст: Компьютер.*UNKNOWN/ }).click()
  await expect(page.getByRole('combobox', { name: 'Причина', exact: true })).toBeVisible()
  expect(errors).toEqual([])
  await page.screenshot({ path: 'test-results/employee/mobile-interval.png', fullPage: true })
})

test('companion deep link selects only the current employee pending request', async ({ page }) => {
  const calls = await fixture(page)
  await page.goto(`/employee?day=${reportDay}&request_id=00000000-0000-4000-8000-000000000002`)
  await expect(page.getByRole('region', { name: 'Выбранный интервал' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Требует объяснения' })).toBeVisible()
  expect(calls.every(call => !call.path.includes('00000000-0000-4000-8000-000000000002'))).toBe(true)
  await page.goto(`/employee?day=${reportDay}&request_id=00000000-0000-4000-8000-000000000099`)
  await expect(page.getByText('Запрос уже объяснён или недоступен в вашем рабочем дне.')).toBeVisible()
  await expect(page.getByRole('region', { name: 'Выбранный интервал' })).toHaveCount(0)
})

test('HR targets correction and preserves finalized monthly versions', async ({ page }) => {
  const calls = await fixture(page, ['hr'])
  const previousMonth = new Date(Date.parse(`${reportDay.slice(0, 7)}-01T12:00:00Z`) - 86400000).toISOString().slice(0, 7)
  await page.goto('/employee/reports')
  await page.getByLabel('Месяц табеля').fill(previousMonth)
  await page.getByLabel('Сотрудник табеля').selectOption(targetPersonId)
  const correction = page.getByRole('region', { name: 'Кадровая корректировка' })
  await correction.getByLabel('Обоснование корректировки').fill('Подтверждено руководителем')
  await correction.getByRole('button', { name: 'Отправить на согласование' }).click()
  await expect.poll(() => calls.filter(call => call.path === `/api/employee/worktime/people/${targetPersonId}/corrections`).length).toBe(1)
  await page.getByLabel('Основание фиксации табеля').fill('Проверены отметки и согласования')
  await page.getByRole('button', { name: 'Зафиксировать новую версию табеля' }).click()
  await expect(page.getByRole('heading', { name: `Табель ${previousMonth} · Версия 1` })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Скачать зафиксированный табель CSV' })).toHaveAttribute('href', '/api/employee/worktime/timesheets/00000000-0000-4000-8000-000000000004/export')
  expect(calls.find(call => call.path.endsWith('/timesheets/finalize'))?.body).toMatchObject({ month: previousMonth, reason: 'Проверены отметки и согласования' })
})

test('privileged API step-up challenge opens only the fixed employee MFA entry', async ({ page }) => {
  await fixture(page, ['hr'])
  await page.route('**/api/employee/worktime/people', route => route.fulfill({ status: 403, json: { detail: { code: 'mfa_step_up_required', login_url: 'https://untrusted.invalid/' } } }))
  await page.goto('/employee/reports')
  await expect(page.getByRole('link', { name: 'Подтвердить вход с MFA' })).toHaveAttribute('href', '/auth/employee/step-up')
})

test('pure HR approves through the scoped approval entry', async ({ page }) => {
  const calls = await fixture(page, ['hr'])
  await page.goto('/employee/reports')
  await page.getByRole('link', { name: 'Согласования', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Согласования корректировок' })).toBeVisible()
  await page.getByRole('button', { name: 'Согласовать', exact: true }).click()
  await expect.poll(() => calls.filter(call => call.path.endsWith('/decision')).length).toBe(1)
  expect(calls.find(call => call.path.endsWith('/decision'))?.body).toMatchObject({ decision: 'approved' })
  expect(calls.every(call => !call.path.startsWith('/api/admin'))).toBe(true)
})

test('HR author denial remains visible and does not remove the pending correction', async ({ page }) => {
  await fixture(page, ['hr'])
  await page.route('**/api/employee/worktime/approvals', route => route.fulfill({ json: { corrections: [{ id: 'correction', person_id: targetPersonId, actor_id: personId, started_at: `${reportDay}T03:00:00Z`, ended_at: `${reportDay}T04:00:00Z`, status: 'OFF_PC', reason: 'Работа с документами', decision: 'pending' }] } }))
  let decisions = 0
  await page.route('**/api/employee/worktime/corrections/correction/decision', route => { decisions++; return route.fulfill({ status: 409, json: { detail: 'Author cannot approve the same correction' } }) })
  await page.goto('/employee/approvals')
  await page.getByRole('button', { name: 'Согласовать', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveText('Данные изменились или переход недоступен. Обновите страницу.')
  await expect(page.getByText('Работа с документами', { exact: true })).toBeVisible()
  expect(decisions).toBe(1)
})

test('a department-scoped HR queue cannot be redirected to foreign personnel by URL', async ({ page }) => {
  const calls = await fixture(page, ['hr'])
  await page.route('**/api/employee/session', route => route.fulfill({ json: { person_id: personId, department_id: 'allowed-department', csrf_token: 'test-employee-csrf', privileged_assurance: true, grants: [{ role: 'hr', department_id: 'allowed-department' }] } }))
  await page.route('**/api/employee/worktime/approvals', route => route.fulfill({ json: { corrections: [] } }))
  await page.goto('/employee/approvals?person_id=00000000-0000-4000-8000-000000000099')
  await expect(page.getByText('Ожидающих корректировок нет.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Согласовать', exact: true })).toHaveCount(0)
  expect(calls.every(call => !call.path.includes('00000000-0000-4000-8000-000000000099'))).toBe(true)
})

test('a department denial clears the old approval queue and never displays error payload personnel', async ({ page }) => {
  await fixture(page, ['hr'])
  await page.goto('/employee/approvals')
  await expect(page.getByText('Работа с документами', { exact: true })).toBeVisible()
  await page.route('**/api/employee/worktime/approvals', route => route.fulfill({ status: 403, json: { detail: 'Foreign department', corrections: [{ person_id: 'foreign-person', reason: 'PRIVATE-FOREIGN-REASON' }] } }))
  await page.getByRole('button', { name: 'Обновить список' }).click()
  await expect(page.getByRole('alert')).toHaveText('Нет прав на эти данные или действие.')
  await expect(page.getByText('Работа с документами', { exact: true })).toHaveCount(0)
  await expect(page.getByText('PRIVATE-FOREIGN-REASON', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Согласовать', exact: true })).toHaveCount(0)
})
