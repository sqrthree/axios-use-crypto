const crypto = require('crypto')
const axios = require('axios')
const test = require('ava')

const { useCrypto, generateSecret } = require('./dist/index.umd')

const mockAdapter = (config) => {
  return new Promise((resolve) => {
    const response = {
      data: config.data,
      status: 200,
      statusText: 'OK',
      headers: config.headers,
      config: config,
      request: null,
    }

    resolve(response)
  })
}

test('should return a random secret', (t) => {
  const secret = generateSecret()

  t.truthy(secret)
  t.is(secret.length, 64)
})

test('should throw an error without secret option', (t) => {
  const request = axios.create({
    adapter: mockAdapter,
  })

  t.throws(
    () => {
      request.interceptors.request.use(useCrypto({}))
    },
    {
      message: 'secret is required.',
    }
  )
})

test('should return cipher text in GET request', async (t) => {
  const request = axios.create({
    adapter: mockAdapter,
  })

  request.interceptors.request.use(
    useCrypto({
      secret: 'secret',
    })
  )

  const { config } = await request.get('/', {
    params: {
      key: 'key',
      a: 1,
    },
  })

  t.truthy(config.params.cipherText)
})

test('should return cipher text in POST request', async (t) => {
  const request = axios.create({
    adapter: mockAdapter,
  })

  request.interceptors.request.use(
    useCrypto({
      secret: 'secret',
    })
  )

  const { data } = await request.post('/', {
    key: 'key',
    a: 1,
  })

  t.truthy(data.cipherText)
})
