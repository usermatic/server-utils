
const jwt = require('jsonwebtoken')

import { verifyJwt } from '../src/index'

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
