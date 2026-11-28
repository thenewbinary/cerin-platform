import { describe, expect, test } from 'bun:test'
import { Hono } from 'hono'

import { errorHandler } from '@/lib/errors'
import { useIdentity } from '@/lib/test/doubles/identity'

const ADMIN = {
  id: '507f1f77bcf86cd799439011',
  email: 'admin@example.com',
  name: 'Admin',
  username: 'admin',
  avatarURL: '',
  language: 'en-US',
  createdAt: '2026-01-01T00:00:00.000Z',
}
const NON_ADMIN = { ...ADMIN, id: '507f191e810c19729de860ea', email: 'user@example.com' }
const REVOCATION_ADMIN = {
  ...ADMIN,
  id: '507f191e810c19729de860eb',
  email: 'revocation-admin@example.com',
}
const FAILED_LOOKUP_USER = {
  ...ADMIN,
  id: '507f191e810c19729de860ec',
  email: 'failed-lookup@example.com',
}
const TEAM = {
  id: '64b5f1c2e4b0a1d2c3e4f5a6',
  name: 'Cerin Admins',
  avatarUrl: '',
  ownerID: ADMIN.id,
  contactEmails: [ADMIN.email],
  createdAt: '2026-01-01T00:00:00.000Z',
}

let revocationMember = true
let failMembershipLookup = true
let membershipLookups = 0

const AUTHENTICATED_USERS = new Map([
  ['valid-admin-token', ADMIN],
  ['valid-non-admin-token', NON_ADMIN],
  ['revocation-admin-token', REVOCATION_ADMIN],
  ['failed-lookup-token', FAILED_LOOKUP_USER],
])

useIdentity({
  authenticateToken: (token: string) => {
    const user = AUTHENTICATED_USERS.get(token) ?? null

    return Promise.resolve(user ? { user, cacheHit: false, provider: 'cerin' as const } : null)
  },
  getTeamMembership: (userId: string) => {
    membershipLookups++
    if (userId === FAILED_LOOKUP_USER.id && failMembershipLookup) {
      return Promise.reject(new Error('membership lookup unavailable'))
    }
    if (userId === REVOCATION_ADMIN.id) {
      return Promise.resolve(
        revocationMember ? { role: 'ADMINISTRATOR' as const, team: TEAM } : null,
      )
    }

    return Promise.resolve(
      userId === ADMIN.id ? { role: 'ADMINISTRATOR' as const, team: TEAM } : null,
    )
  },
})

const { adminRoutes } = await import('@/routes/admin')

function app() {
  const outer = new Hono()

  outer.onError(errorHandler)
  outer.route('/admin', adminRoutes)

  return outer
}

describe('GET /admin/session', () => {
  test('returns the authenticated admin identity', async () => {
    const response = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=valid-admin-token' },
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ userId: ADMIN.id })
  })

  test('rejects a missing or invalid session', async () => {
    const response = await app().request('/admin/session')

    expect(response.status).toBe(401)
  })

  test('rejects an authenticated user outside the admin team', async () => {
    const response = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=valid-non-admin-token' },
    })

    expect(response.status).toBe(403)
  })

  test('uses current membership on every admin request', async () => {
    revocationMember = true
    const before = membershipLookups
    const granted = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=revocation-admin-token' },
    })

    revocationMember = false
    const revoked = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=revocation-admin-token' },
    })

    revocationMember = true
    const regranted = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=revocation-admin-token' },
    })

    expect([granted.status, revoked.status, regranted.status]).toEqual([200, 403, 200])
    expect(membershipLookups - before).toBe(3)
  })

  test('fails closed when membership lookup errors', async () => {
    failMembershipLookup = true
    const failed = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=failed-lookup-token' },
    })
    const failedBody = (await failed.json()) as { error: { code: string } }

    expect(failed.status).toBe(500)
    expect(failedBody.error.code).toBe('internal_error')

    failMembershipLookup = false
    const next = await app().request('/admin/session', {
      headers: { Cookie: 'cerin_token=failed-lookup-token' },
    })

    expect(next.status).toBe(403)
  })
})
