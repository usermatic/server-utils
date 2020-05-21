
import * as rt from 'runtypes'
import jwt from 'jsonwebtoken'

const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const isUUID = (s: string) => {
  return uuidRe.test(s)
}

const UUID = rt.String.withConstraint((s) => isUUID(s))

export const AuthToken = rt.Record({
  id: UUID
})

export type AuthToken = rt.Static<typeof AuthToken>

export const ReauthenticationMethod = rt.Union(
  rt.Literal('password'),
  rt.Literal('oauth'),
  rt.Literal('mfa')
)

export type ReauthenticationMethod = rt.Static<typeof ReauthenticationMethod>

export const ReauthToken = rt.Record({
  id: UUID,
  login: rt.Boolean,
  userContents: rt.String,
  reauthenticationMethods: rt.Array(ReauthenticationMethod)
})

export type ReauthToken = rt.Static<typeof ReauthToken>

export type VerifyOptions = {
  maxAge?: string,
  clockTimestamp?: number
}

export const verifyJwt = (
  token: string,
  key: string,
  options: VerifyOptions = {}
): string | object => {

  if (typeof(key) !== 'string' || key.length < 27) {
    throw new Error(
      'Insufficient key. Make sure you are using the secret obtained from ' +
      'https://usermatic.io/dashboard'
    )
  }

  return jwt.verify(token, key, { ...options, algorithms: ['HS256'] })
}

export const verifyAuthToken = (
  token: string,
  key: string,
  options: VerifyOptions = {}
): AuthToken => {
  const verified = verifyJwt(token, key, options)
  if (!AuthToken.guard(verified)) {
    throw new Error(`malformed AuthToken: ${ JSON.stringify(verified) }`)
  }
  return verified
}

export type ReauthMethodPredicate = (methods: ReauthenticationMethod[]) => boolean

export const verifyReauthToken = (
  token: string,
  key: string,
  requiredMethods: ReauthMethodPredicate | ReauthenticationMethod[],
  options: VerifyOptions = {}
): ReauthToken => {

  const contents = verifyJwt(token, key, options)
  if (!ReauthToken.guard(contents)) {
    console.error("malformed reauth token", JSON.stringify(contents))
    throw new Error("malformed reauth token")
  }
  if (Array.isArray(requiredMethods)) {
    if (requiredMethods.length == 0) {
      throw new Error("Must supply at least one required re-authentication method")
    }
    const missingMethods = requiredMethods.filter(
      m => !contents.reauthenticationMethods.includes(m)
    )
    if (missingMethods.length > 0) {
      throw new Error(
        'The following required re-authentication methods were missing: '
        + missingMethods.join(', ')
      )
    }
  } else {
    if (!requiredMethods(contents.reauthenticationMethods)) {
      // requiredMethods should usually throw its own more descriptive error.
      throw new Error('required methods predicate failed')
    }
  }

  return contents
}
