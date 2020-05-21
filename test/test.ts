
const jwt = require('jsonwebtoken')

import {
  verifyJwt,
  verifyAuthToken,
  verifyReauthToken,
  ReauthToken
} from '../src/index'

describe('algorithm tests', () => {

  const key = 'fB4KvCrgHH/OpLUQq+e2jWHVzEc'
  const payload = { a: 123 }

  test('default', () => {
    const token = jwt.sign(payload, key)
    expect(verifyJwt(token, key)).toMatchObject({ a: 123 })
  })

  test('default with bad key', () => {
    const token = jwt.sign(payload, key)
    expect(() => {
      verifyJwt(token, '')
    }).toThrow(/Insufficient key/)
    expect(() => {
      verifyJwt(token, 'abc')
    }).toThrow(/Insufficient key/)
  })

  test('hs256', () => {
    const token = jwt.sign(payload, key, { algorithm: 'HS256' })
    expect(verifyJwt(token, key)).toMatchObject({ a: 123 })
  })

  test('hs384', () => {
    const token = jwt.sign(payload, key, { algorithm: 'HS384' })
    expect(() => {
      verifyJwt(token, key)
    }).toThrow(/invalid algorithm/)
  })

  test('none', () => {
    const token = jwt.sign(payload, '', { algorithm: 'none' })
    expect(() => {
      verifyJwt(token, '')
    }).toThrow(/Insufficient key/)

    expect(() => {
      verifyJwt(token, key)
    }).toThrow(/jwt signature is required/)
  })

})

describe('authtoken tests', () => {
  const key = 'fB4KvCrgHH/OpLUQq+e2jWHVzEc'
  const id = '51fcefc7-45cb-4ae5-9945-9b39817c6b24'
  const iat = 1588011836
  const payload = { id, iat }

  test('test maxAge', () => {
    const token = jwt.sign(payload, key)
    const verified1 = verifyAuthToken(token, key, { maxAge: '60s', clockTimestamp: iat })
    expect(verified1.id).toBe(id)

    const verified2 = verifyAuthToken(token, key, { maxAge: '60s', clockTimestamp: iat + 59 })
    expect(verified2.id).toBe(id)

    expect(() => {
      verifyAuthToken(token, key, { maxAge: '60s', clockTimestamp: iat + 60 })
    }).toThrow(/maxAge exceeded/)
  })

  test('test return type', () => {
    const token = jwt.sign(payload, key)
    const verified = verifyAuthToken(token, key)
    // this is more about verifying that the id field exists on the return
    // type.
    expect(verified.id).toBe(id)
  })

  test('test type guard', () => {
    const badId = 'not a real id'
    const token = jwt.sign({ id: badId }, key)

    expect(() => {
      verifyAuthToken(token, key)
    }).toThrow(/malformed AuthToken/)
  })
})

describe('reauthtoken tests', () => {
  const key = 'fB4KvCrgHH/OpLUQq+e2jWHVzEc'
  const operation = 'delete'
  const id = '51fcefc7-45cb-4ae5-9945-9b39817c6b24'
  const userPayload = { operation, id }

  test('test maxAge', () => {
    const iat = 1588011836
    const payload = {
      id,
      login: false,
      userContents: JSON.stringify(userPayload),
      reauthenticationMethods: ['password'],
      iat
    }
    const token = jwt.sign(payload, key)
    const verified = verifyReauthToken(token, key, ['password'], { maxAge: '60s', clockTimestamp: iat + 10 })
    expect(JSON.parse(verified.userContents)).toMatchObject(userPayload)

    expect(() => {
      verifyReauthToken(token, key, ['password'], { maxAge: '60s', clockTimestamp: iat + 60 })
    }).toThrow(/maxAge exceeded/)
  })

  test('test 1 methods required', () => {
    const payload = {
      id,
      login: false,
      userContents: JSON.stringify(userPayload),
      reauthenticationMethods: ['password']
    }
    const token = jwt.sign(payload, key)
    expect(() => {
      verifyReauthToken(token, key, [])
    }).toThrow(/Must supply at least one.*method/)
  })

  test('test methods present', () => {
    const payload = {
      id,
      login: false,
      userContents: JSON.stringify(userPayload),
      reauthenticationMethods: ['password']
    }
    const token = jwt.sign(payload, key)
    const verified = verifyReauthToken(token, key, ['password'])
    expect(JSON.parse(verified.userContents)).toMatchObject(userPayload)
  })

  test('test methods missing', () => {
    const payload = {
      id,
      login: false,
      userContents: JSON.stringify(userPayload),
      reauthenticationMethods: ['password']
    }
    const token = jwt.sign(payload, key)
    expect(() => {
      verifyReauthToken(token, key, ['mfa'])
    }).toThrow(/The following required re-authentication methods were missing: mfa/)
  })

  test('test methods predicate', () => {
    const payload: ReauthToken = {
      id,
      login: false,
      userContents: JSON.stringify(userPayload),
      reauthenticationMethods: ['mfa']
    }
    const token = jwt.sign(payload, key)

    verifyReauthToken(token, key, (methods) => {
      return methods.includes('password') || methods.includes('mfa')
    })

    expect(() => {
      verifyReauthToken(token, key, (methods) => {
        if (methods.includes('mfa')) {
          throw new Error("disallowed reauthentictation method mfa")
        } else {
          return true
        }
      })
    }).toThrow(/disallowed reauthentictation method mfa/)
  })
})
