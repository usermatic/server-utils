
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
  /**
   * The maximum allowable age of the JWT to be verified.
   * Note that this is independent of the expiration time of the JWT.
   * The JWT will be invalid if either its expiration time *or* the maxAge
   * option has elapsed.
   */
  maxAge?: string,
  /**
   * The timestamp to use as the current time, to check both the maxAge
   * and expiration time parameter. If this option is omitted, the current
   * system time is used.
   */
  clockTimestamp?: number
}

/**
 * Verify a JWT with arbitrary contents, using the provided key.
 *
 * Generally, you should use verifyAuthToken or verifyReauthToken to verify
 * the specific type of token that you have, as those methods also verify
 * that the token payload is well-formed, whereas this method only verifies
 * the JWT signature.
 */
export const verifyJwt = (
  /**
   * A signed, encoded JWT.
   */
  token: string,
  /**
   * The key to use to verify the JWT. The key must be a minimum of 27 bytes
   * long, to guard against accidental use of weak or empty keys in your application.
   */
  key: string,
  /**
   * optional, additional verification options.
   */
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

/**
 * Verify an authorization token provided by the client using a key
 * (which is typically the application secret key).
 *
 * If verification fails, an exception is thrown.
 *
 * Verification can fail for the following reasons:
 *
 * 1. JWT verification can fail. This can be due to an invalid signature or an
 * expired token.
 *
 * 2. The contents of the token may not be a valid AuthToken.
 */
export const verifyAuthToken = (
  /**
   * The encoded, signed JWT.
   */
  token: string,
  /**
   * The key to use to verify the JWT. Typically the Usermatic application
   * secret key. The key must be a minimum of 27 bytes long, to guard against
   * accidental use of weak or empty keys in your application.
   */
  key: string,
  /**
   * Optional additional options for verification.
   */
  options: VerifyOptions = {}
): AuthToken => {
  const verified = verifyJwt(token, key, options)
  if (!AuthToken.guard(verified)) {
    throw new Error(`malformed AuthToken: ${ JSON.stringify(verified) }`)
  }
  return verified
}

export type ReauthMethodPredicate = (methods: ReauthenticationMethod[]) => boolean

/**
 * Verify a reauthorization token.
 */
export const verifyReauthToken = (
  /**
   * The encoded reauthorization JWT.
   */
  token: string,
  /**
   * The key to use to verify the JWT. Typically the Usermatic application
   * secret key. The key must be a minimum of 27 bytes long, to guard against
   * accidental use of weak or empty keys in your application.
   */
  key: string,
  /**
   * Either:
   *
   * A list of required reauthentication methods. For instance, to require
   * that the reauthentication token was signed as a result of password
   * re-authentication, pass ['password'] here. If multiple methods are passed,
   * all must be present in the reauthentication token.
   *
   * ...or a function which is passed the list of reauthentication methods
   * in the signed token, which then returns true or false to indicate whether
   * the reauthentication methods were sufficient.
   */
  requiredMethods: ReauthMethodPredicate | ReauthenticationMethod[],
  /**
   * Optional additional options for verification.
   */
  options: VerifyOptions
): ReauthToken => {

  if (!options.maxAge) {
    throw new Error("verifyReauthToken requires a maxAge option")
  }

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
