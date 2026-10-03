import { expect, test } from '@playwright/test'

test.use({ timezoneId: 'Asia/Yekaterinburg' })

for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  test(`foundation filters and rollout timing at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport)
    await page.goto('/admin/login')
    await page.getByLabel('Имя пользователя').fill('console-e2e')
    await page.getByLabel('Пароль').fill('console-e2e-password')
    await page.getByRole('button', { name: 'Войти' }).click()
    await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
    await page.route('**/api/admin/console/session', route => route.fulfill({ json: { username: 'observer', scopes: [], csrf_token: 'test-only' } }))
    await page.route('**/api/admin/console/devices?*', route => {
      const query = new URL(route.request().url()).searchParams
      const known = { id: 'known', device_identifier: 'PC-KNOWN', display_name: 'Известная версия',
        online: true, agent_version: '3.2.83', launcher_version: '3.2.82',
        core_newer_than_foundation: true, ram_bytes: null, context_fresh: false }
      const unknown = { ...known, id: 'unknown', device_identifier: 'PC-UNKNOWN', display_name: 'Без Foundation',
        launcher_version: null, core_newer_than_foundation: false }
      const data = query.get('foundation_unknown') === 'true' ? [unknown]
        : query.has('foundation_outdated') || query.get('core_newer_than_foundation') === 'true' ? [known] : [known, unknown]
      return route.fulfill({ json: { data, total: data.length, limit: 50, offset: 0 } })
    })
    await page.route('**/api/admin/updates/builds?*', route => route.fulfill({ json: { data: [], total: 0 } }))
    await page.route('**/api/admin/updates/rollouts?*', route => route.fulfill({ json: { data: [], total: 0 } }))
    await page.route('**/api/admin/updates/rollouts/rollout-timing?*', route => route.fulfill({ json: {
      id: 'rollout-timing', version: '3.2.83', mode: 'canary', status: 'completed', counts: {},
      created_at: null, started_at: null, completed_at: null, reason: null, targets_total: 1,
      targets: [{ device_id: 'known', device_name: 'PC-KNOWN', status: 'failed', assigned_at: '2026-10-03T08:00:00Z',
        requested_at: '', scheduled_at: null, updated_at: '2026-10-03T08:02:00Z', terminal_at: '2026-10-03T08:02:00Z',
        safe_reason: null, report_status: 'failed', reported_version: '3.2.83',
        safe_code: '<img src=x onerror=alert(1)>', report_created_at: '2026-10-03T08:03:00Z' }],
    } }))
    await page.goto('/admin/devices?search=PC&offset=50')
    await expect(page.getByRole('columnheader', { name: 'Core Agent' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Foundation / Launcher' })).toBeVisible()
    await expect(page.getByText('Core новее Foundation · информационно')).toBeVisible()
    const unknown = page.getByRole('row').filter({ hasText: 'Без Foundation' })
    await expect(unknown.getByText('В сети', { exact: true })).toBeVisible()
    await expect(unknown.getByText('Неизвестна')).toBeVisible()
    await page.getByLabel('Core Agent ниже версии', { exact: true }).fill('3.2.82')
    await page.getByLabel('Foundation ниже версии', { exact: true }).fill('3.2.83')
    await expect(page).toHaveURL(/core_outdated=3.2.82/)
    await expect(page).toHaveURL(/foundation_outdated=3.2.83/)
    expect(new URL(page.url()).searchParams.get('search')).toBe('PC')
    expect(new URL(page.url()).searchParams.has('offset')).toBe(false)
    await expect(page.getByText('Без Foundation')).toHaveCount(0)
    await page.getByLabel('Foundation ниже версии', { exact: true }).fill('')
    await page.getByLabel('Данные Foundation').selectOption('true')
    await expect(page.getByText('Без Foundation')).toBeVisible()
    await page.goto('/admin/updates?open=rollout-timing')
    const dialog = page.getByRole('dialog', { name: 'Развёртывание', exact: true })
    await expect(dialog).toBeVisible()
    await expect(dialog.getByText('Последний отчёт', { exact: true })).toBeVisible()
    await expect(dialog.getByText('<img src=x onerror=alert(1)>', { exact: true })).toBeVisible()
    await expect(dialog.locator('img')).toHaveCount(0)
    await expect(dialog.getByText('3 окт. 2026 г., 13:03')).toBeVisible()
    await expect(dialog.getByText('Invalid Date')).toHaveCount(0)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  })
}

test('administrator can approve enrollment, roll back an update and run a module', async ({ page }) => {
  await page.goto('/admin/login')
  await expect(page.getByRole('heading', { name: 'Вход в консоль' })).toBeVisible()
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  const loginResponse = page.waitForResponse(response => response.url().endsWith('/api/admin/session'))
  const sessionResponse = page.waitForResponse(response => response.url().includes('/api/admin/console/session'))
  await page.getByRole('button', { name: 'Войти' }).click()
  expect((await loginResponse).status()).toBe(201)
  expect((await sessionResponse).status()).toBe(200)
  await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Устройства' }).click()
  await expect(page.getByRole('heading', { name: 'Устройства', exact: true }).first()).toBeVisible()
  await expect(page.getByText('Тестовый компьютер')).toBeVisible()
  await page.getByRole('link', { name: 'Открыть' }).first().click()
  await expect(page.getByRole('heading', { name: 'Тестовый компьютер' })).toBeVisible()
  await expect(page.getByText(/Windows 11.*Агент/)).toBeVisible()
  await page.getByRole('button', { name: 'Контекст' }).click()
  await expect(page.getByText('Свежесть: Актуален')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Обновить данные' })).toBeVisible()
  await page.getByRole('button', { name: 'Обновить данные' }).click()
  await expect(page.getByText(/^Сбор:/)).toBeVisible()
  await page.getByRole('button', { name: 'Изменения' }).click()
  await expect(page.getByRole('heading', { name: 'Изменения', exact: true })).toBeVisible()

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Установка и регистрация' }).click()
  await expect(page.getByRole('heading', { name: 'Установка и регистрация' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Endpoint Agent для Windows' })).toBeVisible()
  await expect(page.getByText('EndpointAgentSetup-3.2.63-x64.exe')).toBeVisible()
  await expect(page.getByText('Только для тестирования')).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('link', { name: 'Скачать установщик' }).click()
  expect((await downloadPromise).suggestedFilename()).toBe('EndpointAgentSetup-3.2.63-x64.exe')
  await page.getByRole('button', { name: 'Кампании' }).click()
  const campaignsBefore = await page.request.get('/api/admin/console/campaigns?limit=50&offset=0')
  expect(campaignsBefore.status()).toBe(200)
  const originalExpiry = (await campaignsBefore.json()).data[0].expires_at as string
  const expectedLocalExpiry = await page.evaluate(iso => {
    const date = new Date(iso)
    const two = (value: number) => String(value).padStart(2, '0')
    return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}T${two(date.getHours())}:${two(date.getMinutes())}`
  }, originalExpiry)
  await page.getByRole('article').filter({ hasText: 'Тестовая ручная кампания' }).getByRole('button', { name: 'Изменить' }).click()
  await expect(page.getByLabel('Действует до')).toHaveValue(expectedLocalExpiry)
  await page.getByLabel('Название').fill('Тестовая кампания Console')
  await page.getByRole('button', { name: 'Сохранить' }).click()
  await expect(page.getByRole('article').filter({ hasText: 'Тестовая кампания Console' })).toBeVisible()
  const campaignsAfter = await page.request.get('/api/admin/console/campaigns?limit=50&offset=0')
  expect(campaignsAfter.status()).toBe(200)
  const savedExpiry = (await campaignsAfter.json()).data[0].expires_at as string
  expect(Date.parse(savedExpiry)).toBe(Date.parse(originalExpiry))
  await page.getByRole('button', { name: 'Запросы регистрации' }).click()
  await expect(page.getByText('Тестовая заявка')).toBeVisible()
  page.once('dialog', dialog => dialog.accept())
  const approvalResponse = page.waitForResponse(response => response.url().endsWith('/approve') && response.request().method() === 'POST')
  await page.getByRole('row').filter({ hasText: 'Тестовая заявка' }).getByRole('button', { name: 'Одобрить' }).click()
  expect((await approvalResponse).status()).toBe(204)
  await expect(page.getByRole('row').filter({ hasText: 'Тестовая заявка' })).toContainText('Одобрен вручную')

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Релизы и обновления' }).click()
  await expect(page.getByRole('heading', { name: 'Релизы и обновления' })).toBeVisible()
  await page.getByRole('navigation', { name: 'Разделы обновлений' }).getByRole('button', { name: 'Развёртывания' }).click()
  await expect(page.getByText('3.2.63 · Канареечное')).toBeVisible()
  await page.getByRole('button', { name: 'Открыть' }).click()
  await expect(page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('heading', { name: 'Устройства · 1' })).toBeVisible()
  await page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('button', { name: 'Закрыть' }).click()
  await page.getByRole('navigation', { name: 'Разделы обновлений' }).getByRole('button', { name: 'История' }).click()
  await expect(page.getByRole('heading', { name: 'История развёртываний' })).toBeVisible()
  await expect(page.getByRole('button', { name: '3.2.63 · Канареечное' })).toBeVisible()
  await page.getByRole('navigation', { name: 'Разделы обновлений' }).getByRole('button', { name: 'Развёртывания' }).click()
  await page.getByRole('button', { name: 'Создать канареечное обновление' }).click()
  await expect(page.getByRole('heading', { name: 'Канареечное обновление' })).toBeVisible()
  const rolloutWizard = page.getByRole('dialog', { name: 'Новое развёртывание' })
  await rolloutWizard.getByLabel('Релиз').selectOption({ label: '3.2.63 · Windows' })
  await rolloutWizard.getByRole('checkbox', { name: /Тестовый компьютер/ }).check()
  await expect(rolloutWizard.getByText('Точный список устройств (1)')).toBeVisible()
  page.once('dialog', dialog => dialog.accept())
  const rolloutResponse = page.waitForResponse(response => response.url().endsWith('/api/admin/updates/rollouts') && response.request().method() === 'POST')
  await rolloutWizard.getByRole('button', { name: 'Создать развёртывание' }).click()
  const createdRollout = await rolloutResponse
  expect(createdRollout.status(), await createdRollout.text()).toBe(201)
  const rolloutId = (await createdRollout.json()).id as string
  await expect(page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('heading', { name: 'Устройства · 1' })).toBeVisible()
  await page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('button', { name: 'Закрыть' }).click()
  expect((await page.request.post(`/__test__/complete-rollout/${rolloutId}`)).status()).toBe(200)
  await page.getByRole('button', { name: 'Обновить' }).click()
  await page.getByRole('article').filter({ hasText: '3.2.63 · Канареечное' }).first().getByRole('button', { name: 'Открыть' }).click()
  await page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('button', { name: 'Создать откат' }).click()
  const rollbackWizard = page.getByRole('dialog', { name: 'Новое развёртывание' })
  await rollbackWizard.getByLabel('Релиз').selectOption({ label: '3.2.62 · Windows' })
  await rollbackWizard.getByLabel('Причина').fill('Проверка отката')
  await rollbackWizard.getByRole('checkbox', { name: /Тестовый компьютер/ }).check()
  page.once('dialog', dialog => dialog.accept())
  const rollbackResponse = page.waitForResponse(response => response.url().endsWith('/rollback') && response.request().method() === 'POST')
  await rollbackWizard.getByRole('button', { name: 'Создать развёртывание' }).click()
  const rollback = await rollbackResponse
  expect(rollback.status(), await rollback.text()).toBe(201)
  await expect(page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('heading', { name: '3.2.62 · Откат' })).toBeVisible()
  await page.getByRole('dialog', { name: 'Развёртывание' }).getByRole('button', { name: 'Закрыть' }).click()

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Модули' }).click()
  await expect(page.getByText('РЕДАКТОР МОДУЛЕЙ')).toBeVisible()
  const capabilityCatalog = page.getByRole('heading', { name: 'Каталог возможностей' }).locator('..')
  const dnsCapability = capabilityCatalog.getByRole('article').filter({ hasText: 'dns.resolve' })
  await expect(dnsCapability.getByRole('heading', { name: 'Разрешение DNS-имени' })).toBeVisible()
  await expect(dnsCapability).toContainText('Риск: Безопасное чтение')
  await expect(dnsCapability).toContainText('Согласие: не требуется')
  await expect(dnsCapability).toContainText('target')
  const draft = page.locator('form').last()
  await draft.getByLabel('Название').fill('Проверка сети')
  await draft.getByLabel('Ключ модуля').fill('network.basic.check')
  await draft.getByRole('button', { name: 'Добавить вход' }).click()
  await draft.getByLabel('Имя', { exact: true }).fill('target')
  await draft.getByRole('button', { name: 'Добавить шаг' }).click()
  await draft.getByRole('combobox', { name: 'Вход', exact: true }).first().selectOption('target')
  await draft.getByRole('combobox', { name: 'family' }).selectOption('literal')
  await draft.getByRole('button', { name: 'Создать черновик' }).click()
  await expect(page.getByRole('status')).toContainText('Черновик создан')
  await page.getByRole('button', { name: 'Проверить модуль' }).click()
  await expect(page.getByRole('status')).toContainText('Проверка: выполнено')
  await expect(page.getByRole('button', { name: 'Принять испытания' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Опубликовать' })).toBeDisabled()
  await page.getByLabel('Совместимое устройство').selectOption({ label: 'Лабораторный Agent' })
  await page.getByLabel('target (строка)').fill('api.example.test')
  const labResponse = page.waitForResponse(response => response.url().includes('/lab-operations/') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Запустить испытание' }).click()
  const lab = await labResponse
  expect(lab.status()).toBe(201)
  const operationId = (await lab.json()).data.operation_id as string
  const simulatedAgent = await page.request.post(`/__test__/complete-module-operation/${operationId}`)
  expect(simulatedAgent.status()).toBe(200)
  await expect(page.getByRole('button', { name: 'Сохранить подтверждение испытания' })).toBeVisible()
  await page.getByRole('button', { name: 'Сохранить подтверждение испытания' }).click()
  await expect(page.getByRole('status')).toContainText('Результат испытания сохранён')
  await expect(page.getByRole('button', { name: 'Принять испытания' })).toBeEnabled()
  await page.getByRole('button', { name: 'Принять испытания' }).click()
  await expect(page.getByRole('status')).toContainText('Принятие испытаний: выполнено')
  page.once('dialog', dialog => dialog.accept())
  await page.getByRole('button', { name: 'Опубликовать' }).click()
  await expect(page.getByRole('status')).toContainText('Публикация: выполнено')

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Устройства' }).click()
  await page.getByRole('row').filter({ hasText: 'Лабораторный Agent' }).getByRole('link', { name: 'Открыть' }).click()
  await page.getByRole('button', { name: 'Модули' }).click()
  await expect(page.getByRole('heading', { name: 'Опубликованные модули' })).toBeVisible()
  await page.getByLabel('target (строка)').fill('api.example.test')
  const runResponse = page.waitForResponse(response => response.url().includes('/module-operations') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Запустить модуль' }).click()
  const run = await runResponse
  expect(run.status()).toBe(201)
  const runId = (await run.json()).data.operation_id as string
  expect((await page.request.post(`/__test__/complete-module-operation/${runId}`)).status()).toBe(200)
  await page.getByRole('button', { name: 'Операции' }).click()
  await page.getByRole('link', { name: 'Открыть журнал операций устройства' }).click()
  await page.getByRole('row').filter({ hasText: 'Лабораторный Agent' }).first().getByRole('button', { name: 'Открыть' }).click()
  const operationDialog = page.getByRole('dialog', { name: 'Операция' })
  await expect(operationDialog.getByRole('heading', { name: 'network.basic.check@1.0.0' })).toBeVisible()
  await expect(operationDialog.locator('.module-steps li')).toContainText('DNS')
  await operationDialog.getByRole('button', { name: 'Закрыть' }).click()

  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Аудит' }).click()
  await expect(page.getByRole('heading', { name: 'Аудит' })).toBeVisible()
  await expect(page.getByText('Вход администратора').first()).toBeVisible()
  await page.getByLabel('Действие').fill('admin_session.created')
  await expect(page.getByText('Вход администратора').first()).toBeVisible()
})

test('primary Console labels remain Russian', async ({ page }) => {
  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()

  const navigation = page.getByRole('navigation', { name: 'Основная навигация' })
  const pages = [
    ['Главная', 'Состояние парка'], ['Устройства', 'Устройства'],
    ['Установка и регистрация', 'Установка и регистрация'],
    ['Релизы и обновления', 'Релизы и обновления'],
    ['Операции', 'Операции'], ['Модули', 'Модули'], ['Аудит', 'Аудит'],
  ] as const
  for (const [name, heading] of pages) {
    await navigation.getByRole('link', { name, exact: true }).click()
    await expect(page.getByRole('heading', { name: heading, exact: true }).first()).toBeVisible()
    const labels = await page.locator('main h1, main h2, main h3, main button, main label').allTextContents()
    for (const label of labels) {
      const value = label.trim()
      if (/^(linux|windows)_amd64$/.test(value)) continue // Platform identifiers in the recipe.
      if (value) expect(value, `English-only label on page ${name}`).toMatch(/[А-Яа-яЁё]/)
    }
  }
})

test('administrator can create a module without input parameters', async ({ page }) => {
  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Модули' }).click()
  const draft = page.locator('form').last()
  await draft.getByLabel('Название').fill('Список адаптеров')
  await draft.getByLabel('Ключ модуля').fill('inventory.adapter.preview')
  await draft.getByRole('checkbox', { name: 'linux_amd64' }).uncheck()
  await draft.getByRole('checkbox', { name: 'windows_amd64' }).check()
  await draft.getByRole('button', { name: 'Добавить шаг' }).click()
  await draft.getByRole('combobox', { name: 'Возможность' }).selectOption('adapter.list')
  await expect(draft.getByRole('heading', { name: 'Входные параметры (0/8)' })).toBeVisible()
  await expect(draft.getByRole('button', { name: 'Создать черновик' })).toBeEnabled()
  const createResponse = page.waitForResponse(response => response.url().endsWith('/api/admin/console/modules/versions') && response.request().method() === 'POST')
  await draft.getByRole('button', { name: 'Создать черновик' }).click()
  expect((await createResponse).status()).toBe(201)
  await expect(page.getByRole('status')).toContainText('Черновик создан')
})
