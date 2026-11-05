import { useEffect, useState } from 'react'

export function WorktimeLoginMethods({ adHref, allowHelpdesk }: { adHref: string; allowHelpdesk: boolean }) {
  const [enabled, setEnabled] = useState(false)
  useEffect(() => {
    if (!allowHelpdesk) return
    const controller = new AbortController()
    fetch('/api/employee/worktime/login-options', { signal: controller.signal, credentials: 'same-origin', cache: 'no-store' })
      .then(async response => response.ok ? await response.json() as { helpdesk_login_enabled?: boolean } : null)
      .then(value => { if (!controller.signal.aborted) setEnabled(value?.helpdesk_login_enabled === true) })
      .catch(() => { /* The separate AD entry remains available. */ })
    return () => controller.abort()
  }, [allowHelpdesk])
  return <>
    {allowHelpdesk && enabled && <><a className="primary-button wt-login-link" href="/auth/worktime/helpdesk/login">Войти через Helpdesk</a><p className="muted">Если вы уже вошли в Helpdesk, повторный вход не потребуется.</p></>}
    <a className={enabled && allowHelpdesk ? 'wt-login-link' : 'primary-button wt-login-link'} href={adHref}>Войти через AD</a>
  </>
}
