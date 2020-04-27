
import { Record, String, Array, Static } from 'runtypes'
import jwt from 'jsonwebtoken'

const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const isUUID = (s: string) => {
  return uuidRe.test(s)
}

const UUID = String.withConstraint((s) => isUUID(s))

export const AuthToken = Record({
  id: UUID
})

export type AuthToken = Static<typeof AuthToken>

const ReauthToken = Record({
  userContents: String,
  reauthenticationMethods: Array(String)
})

export type ReauthToken = Static<typeof ReauthToken>

export const verifyJwt = (token: string, key: string): string | object => {
  if (typeof(key) !== 'string' || key.length < 27) {
    throw new Error(
      'Insufficient key. Make sure you are using the secret obtained from ' +
      'https://usermatic.io/dashboard'
    )
  }

  return jwt.verify(token, key, { algorithms: ['HS256'] })
}

export const verifyAuthToken = (token: string, key: string): AuthToken => {
  const verified = verifyJwt(token, key)
  if (!AuthToken.guard(verified)) {
    throw new Error(`malformed AuthToken: ${ JSON.stringify(verified) }`)
  }
  return verified
}

type ReauthenticationMethod = 'password' | 'mfa'

export const verifyReauthToken =
(token: string, key: string, requiredMethods: ReauthenticationMethod[]): ReauthToken => {

  const contents = verifyJwt(token, key)
  if (!ReauthToken.guard(contents)) {
    console.error("malformed reauth token", JSON.stringify(contents))
    throw new Error("malformed reauth token")
  }
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

  return contents
}
