const jwt = require('jsonwebtoken')
const { createCipher, createDecipher } = require('crypto')

const encrypt_algorithm = 'aes192'
const encrypt_password = 'hoge'
const jwt_secret = 'fuga'

const createJWT = (obj) =>
  jwt.sign(
    encrypting(
      encrypt_algorithm,
      encrypt_password,
      JSON.stringify(obj)
    ),
    jwt_secret
  )

const verifyJWT = (token) =>
  token &&
  JSON.parse(
    decrypting(
      encrypt_algorithm,
      encrypt_password,
      jwt.verify(
        token,
        jwt_secret
      )
    )
  )


const encrypting = (algorithm, password, message, opts = {}) => {
  let result
  const inputEncoding = opts.inputEncoding || 'utf8'
  const outputEncoding = opts.outputEncoding || 'hex'

  const cipher = createCipher(algorithm, password)
  result = cipher.update(message, inputEncoding, outputEncoding)
  result += cipher.final(outputEncoding)
  return result
}

const decrypting = (algorithm, password, encrypted, opts = {}) => {
  let result
  const inputEncoding = opts.inputEncoding || 'hex'
  const outputEncoding = opts.outputEncoding || 'utf8'

  const decipher = createDecipher(algorithm, password)
  result = decipher.update(encrypted, inputEncoding, outputEncoding)
  result += decipher.final(outputEncoding)
  return result
}

module.exports = { createJWT, verifyJWT }