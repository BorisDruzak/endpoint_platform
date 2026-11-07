import { request } from './api'

export type SupportPlatform = 'windows_amd64' | 'linux_amd64'
type CommonPolicy = {
  device_id: string; revision: number; enabled: boolean; expires_at: string | null
  gateway_host: string; gateway_port: number; gateway_host_public_key: string
  tunnel_user: string; remote_port: number; local_port: number
  operator_public_keys: string[]
}
type LinuxPrincipal = { platform: 'linux_amd64'; linux_admin_username: string | null; linux_admin_uid: number | null; windows_admin_username?: never }
type WindowsPrincipal = { platform?: never; windows_admin_username: string | null; linux_admin_username?: never; linux_admin_uid?: never }
export type SupportPolicy = CommonPolicy & (LinuxPrincipal | WindowsPrincipal)
export type ConfiguredLinuxPolicy = Pick<CommonPolicy, 'enabled' | 'expires_at' | 'operator_public_keys'> & Omit<LinuxPrincipal, 'platform'>
export type SupportStatus = {
  policy: SupportPolicy; component_version: string; installed: boolean; tunnel_connected: boolean
  reported_at: string | null; last_error_code: string | null; host_public_key: string
  access_verified_at: string | null; access_verified_by: string | null
  verification_kind: 'operator_attestation'; revoked_at: string | null; reset_registration_allowed: boolean
  configured_policy?: ConfiguredLinuxPolicy
}
export type SupportPolicyDraft = {
  enabled: boolean; expires_at: string | null; operator_public_keys: string[]
  reason: string
} & (LinuxPrincipal | WindowsPrincipal)
const devicePath = (deviceId: string, platform: SupportPlatform) => `/api/admin/support-access/${platform === 'linux_amd64' ? 'linux/' : ''}devices/${encodeURIComponent(deviceId)}`
export const getSupportPlatform = (deviceId: string) => request<{ device_id: string; platform: SupportPlatform | null }>(`${devicePath(deviceId, 'windows_amd64')}/platform`)
export const getSupportAccess = (deviceId: string, platform: SupportPlatform) => request<SupportStatus>(devicePath(deviceId, platform))
export const saveSupportPolicy = (deviceId: string, body: SupportPolicyDraft, platform: SupportPlatform) =>
  request<SupportPolicy>(`${devicePath(deviceId, platform)}/policy`, { method: 'PUT', body: JSON.stringify(body) })
export const revokeSupportAccess = (deviceId: string, action: 'revoke' | 'reset-registration' | 'verify-access', reason: string, platform: SupportPlatform) =>
  request<void>(`${devicePath(deviceId, platform)}/${action}`, { method: 'POST', body: JSON.stringify({ reason }) })
