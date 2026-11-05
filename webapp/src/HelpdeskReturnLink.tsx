/** Fixed environment pair; returning never revokes either service's session. */
export function HelpdeskReturnLink() {
  const href = {
    'https://endpoint.sosnadmin.local': 'https://helpdesk.sosnadmin.local/app',
    'https://endpoint-staging.sosnadmin.local': 'https://helpdesk-staging.sosnadmin.local/app',
  }[window.location.origin]
  return href ? <a className="wt-helpdesk-return" href={href}>← Вернуться в Helpdesk</a> : null
}
