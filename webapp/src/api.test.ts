import { afterEach, describe, expect, it, vi } from 'vitest'
import { getSession, login } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('ошибки API', () => {
  it('показывает русское сообщение при потере соединения на странице входа', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(login('operator', 'test')).rejects.toThrow('Не удалось связаться с сервером')
  })

  it('показывает русское сообщение при потере соединения во время проверки сеанса', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(getSession()).rejects.toThrow('Не удалось связаться с сервером')
  })

  it('не называет ошибку сервера неверным паролем', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 502 }))
    await expect(login('operator', 'test')).rejects.toThrow('Сервер временно недоступен')
  })
})
