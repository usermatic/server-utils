
import jwt from 'jsonwebtoken'

export const verifyJwt = (token: string, key: string): string | object => {
  if (typeof(key) !== 'string' || key.length < 27) {
    throw new Error(
      'Insufficient key. Make sure you are using the secret obtained from ' +
      'https://usermatic.io/dashboard'
    )
  }

  return jwt.verify(token, key, { algorithms: ['HS256'] })
}
