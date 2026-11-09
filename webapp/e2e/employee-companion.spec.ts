import { expect, test } from '@playwright/test'

// Fixture acceptance of the browser flow; no real domain credentials or activity.
for (const width of [1440, 390]) {
  test(`companion target survives login and saves in the employee portal at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 })
    const requestId = '00000000-0000-4000-8000-000000000002'
    const query = `?day=2026-10-27&request_id=${requestId}`
    const interval = { started_at: '2026-10-27T03:00:00Z', ended_at: '2026-10-27T03:30:00Z' }
    let authenticated = false, saved = false
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    // The shared fixture keeps personnel features disabled on its real server.
    // Serve its same built SPA at the employee URL; APIs below remain fixtures.
    await page.route(url => url.pathname === '/employee' || url.pathname.startsWith('/employee/'), async route => {
      const response = await route.fetch({ url: new URL('/admin/login', route.request().url()).href })
      return route.fulfill({ response })
    })
    await page.route('**/api/employee/**', async route => {
      const path = new URL(route.request().url()).pathname
      if (!authenticated) return route.fulfill({ status: 401, json: { detail: 'Session expired' } })
      if (path === '/api/employee/worktime/session') return route.fulfill({ json: { person_id: 'person-a', department_id: null, csrf_token: 'fixture-csrf', grants: [] } })
      if (path.endsWith('/categories')) return route.fulfill({ json: { categories: [{ code: 'meeting', label: 'Совещание', requires_comment: true }] } })
      if (path.endsWith('/history')) return route.fulfill({ json: { events: [], explanations: [], corrections: [], approvals: [] } })
      if (path.endsWith('/explanations')) {
        expect(route.request().method()).toBe('POST')
        expect(route.request().headers()['x-csrf-token']).toBe('fixture-csrf')
        expect(route.request().postDataJSON()).toMatchObject({ ...interval, request_id: requestId, category_code: 'meeting', comment: 'Совещание отдела' })
        expect(route.request().postDataJSON()).not.toHaveProperty('person_id')
        saved = true
        return route.fulfill({ json: {} })
      }
      return route.fulfill({ json: { person_id: 'person-a', day: '2026-10-27', timezone: 'Asia/Yekaterinburg', status: 'WORKING',
        work_intervals: [], activity_intervals: [], schedule: [],
        totals: { work_seconds: 0, break_seconds: 0, off_pc_seconds: 0, scheduled_seconds: 28800 },
        coverage: { state: 'unknown', measured_seconds: 0, unknown_seconds: 86400 },
        explanations: saved ? [{ ...interval, id: 'saved', category_code: 'meeting', comment: 'Совещание отдела' }] : [],
        corrections: [], pending_explanations: saved ? [] : [{ ...interval, id: requestId, state: 'pending' }] } })
    })
    await page.route('**/auth/employee/login?**', route => {
      expect(new URL(route.request().url()).search).toBe(`${query}&worktime=1`)
      authenticated = true
      // A fresh navigation lets the employee document fixture intercept it;
      // Playwright routes only the first URL of an HTTP redirect chain.
      return route.fulfill({ contentType: 'text/html', body: `<script>location.replace(${JSON.stringify(`/employee${query}`)})</script>` })
    })
    await page.goto(`/employee${query}`)
    await expect(page.getByRole('heading', { name: 'Вход сотрудника' })).toBeVisible()
    await page.getByRole('link', { name: 'Войти через AD' }).click()
    await expect(page.getByRole('region', { name: 'Выбранный интервал' })).toBeVisible()
    await expect(page.getByLabel('Дата', { exact: true })).toHaveValue('2026-10-27')
    await page.getByLabel('Причина', { exact: true }).selectOption('meeting')
    await page.getByLabel('Комментарий', { exact: true }).fill('Совещание отдела')
    await page.getByRole('button', { name: 'Сохранить объяснение' }).click()
    await expect(page.getByText('Изменение сохранено. Итоги обновлены.')).toBeVisible()
    expect(saved).toBe(true)
    await expect(page.getByRole('link', { name: 'Согласования' })).toHaveCount(0)
    expect(errors).toEqual([])
    await page.screenshot({ path: test.info().outputPath(`employee-companion-${width}.png`), fullPage: true })
  })
}
