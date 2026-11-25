import { expect, test } from '@playwright/test'

for (const width of [1440, 390]) {
  test(`server profile and individual checks at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/admin/login')
    await page.getByLabel('Имя пользователя').fill('console-e2e')
    await page.getByLabel('Пароль').fill('console-e2e-password')
    await page.getByRole('button', { name: 'Войти' }).click()
    await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
    await page.goto('/admin/devices')

    const server = page.getByRole('row').filter({ hasText: 'Лабораторный Agent' })
    await expect(server.getByText('Профиль · Endpoint Platform')).toBeVisible()
    const workstation = page.getByRole('row').filter({ hasText: 'Тестовый компьютер' })
    await expect(workstation.getByText('Профиль · Endpoint Platform')).toHaveCount(0)
    await server.getByRole('link', { name: 'Открыть' }).click()
    await page.getByRole('button', { name: 'Контекст', exact: true }).click()

    const checks = page.getByRole('region', { name: 'Серверные проверки' })
    await expect(checks.getByText('Профиль · Endpoint Platform')).toBeVisible()
    await expect(checks.getByRole('heading', { name: 'Службы' })).toBeVisible()
    await expect(checks.getByRole('heading', { name: 'Тома' })).toBeVisible()
    await expect(checks.getByRole('heading', { name: 'Приложения' })).toBeVisible()
    await expect(checks.getByRole('listitem').filter({ hasText: 'endpoint-platform.service' })).toContainText('В норме')
    await expect(checks.getByRole('listitem').filter({ hasText: '98,6%' })).toContainText('Критично')
    await expect(checks.getByRole('listitem').filter({ hasText: 'Endpoint API' })).toContainText('HTTP 200')
    await expect(page.getByRole('heading', { name: 'Инвентаризация', exact: true })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  })
}
