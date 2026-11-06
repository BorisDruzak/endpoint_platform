import { request } from './api'

export type SupportPolicy = {
  device_id: string; revision: number; enabled: boolean; expires_at: string | null
  gateway_host: string; gateway_port: number; gateway_host_public_key: string
  tunnel_user: string; remote_port: number; local_port: number
  operator_public_keys: string[]; windows_admin_username: string | null
}
export type SupportStatus = {
  policy: SupportPolicy; component_version: string; installed: boolean; tunnel_connected: boolean
  reported_at: string | null; last_error_code: string | null; host_public_key: string
  access_verified_at: string | null; access_verified_by: string | null
  verification_kind: 'operator_attestation'; revoked_at: string | null; reset_registration_allowed: boolean
}
export type SupportPolicyDraft = {
  enabled: boolean; expires_at: string | null; operator_public_keys: string[]
  windows_admin_username: string | null; reason: string
}
const devicePath = (deviceId: string) => `/api/admin/support-access/devices/${encodeURIComponent(deviceId)}`
export const getSupportAccess = (deviceId: string) => request<SupportStatus>(devicePath(deviceId))
export const saveSupportPolicy = (deviceId: string, body: SupportPolicyDraft) =>
  request<SupportPolicy>(`${devicePath(deviceId)}/policy`, { method: 'PUT', body: JSON.stringify(body) })
export const revokeSupportAccess = (deviceId: string, action: 'revoke' | 'reset-registration', reason: string) =>
  request<void>(`${devicePath(deviceId)}/${action}`, { method: 'POST', body: JSON.stringify({ reason }) })
