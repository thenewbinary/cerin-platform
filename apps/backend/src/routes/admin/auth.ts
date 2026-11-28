import { config } from '@/config'
import { collectCookieTokenCandidates } from '@/lib/cookie-auth'
import { AppError } from '@/lib/errors'
import { authenticateToken, getTeamMembership } from '@/lib/identity'

import type { CerinUser } from '@/lib/identity'
import type { MiddlewareHandler } from 'hono'

export type AdminVars = {
  adminAuthSource: 'cerin-token'
  adminUserId?: string
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export const requireAdmin: MiddlewareHandler<{ Variables: AdminVars }> = async (c, next) => {
  // Admin auth is cookie-only, so refuse state changes a cross-site page
  // triggered (CSRF). Browsers always send Sec-Fetch-Site; server-side callers
  // that omit it are unaffected.
  if (!SAFE_METHODS.has(c.req.method) && c.req.header('Sec-Fetch-Site') === 'cross-site') {
    throw new AppError(403, 'forbidden', 'Cross-site admin requests are not allowed')
  }
  const cookieAuth = await authenticateCookieAdmin(c.req.header('Cookie'))

  if (cookieAuth.status === 'ok') {
    c.set('adminAuthSource', 'cerin-token')
    c.set('adminUserId', cookieAuth.user.id)
    await next()

    return
  }
  if (cookieAuth.status === 'not-admin') {
    throw new AppError(403, 'forbidden', `Cerin user ${cookieAuth.user.id} is not an Cerin admin`)
  }
  throw new AppError(401, 'unauthorized', 'Missing Cerin token')
}

type CookieAdminAuthResult =
  | { status: 'ok'; user: CerinUser }
  | { status: 'missing' }
  | { status: 'not-admin'; user: CerinUser }

async function authenticateCookieAdmin(
  cookieHeader: string | undefined,
): Promise<CookieAdminAuthResult> {
  let authenticatedUser: CerinUser | null = null

  for (const token of collectCookieTokenCandidates(cookieHeader, config.admin.cookieNames)) {
    const result = await authenticateToken(token)

    if (!result) continue
    authenticatedUser = result.user
    if (await isAdminUser(result.user.id)) {
      return { status: 'ok', user: result.user }
    }
  }

  return authenticatedUser
    ? { status: 'not-admin', user: authenticatedUser }
    : { status: 'missing' }
}

// Admin = member of the admin team (config.admin.teamId). Unconfigured means
// nobody is an admin, which is the safe end of that choice.
// Admin requests are rare, so read membership live and let grants or
// revocations take effect on the very next request.

async function isAdminUser(userId: string): Promise<boolean> {
  const adminTeamId = config.admin.teamId

  if (!adminTeamId) return false
  const membership = await getTeamMembership(userId, adminTeamId)

  return membership !== null
}
