import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { App } from './App'

describe('Консоль', () => {
  it('показывает русскую форму входа', () => {
    render(<MemoryRouter initialEntries={['/admin/login']}><App /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Вход в консоль' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Войти' })).toBeTruthy()
    expect(screen.getByLabelText('Пароль')).toBeTruthy()
  })
})
