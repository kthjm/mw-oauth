const uuid = require('uuid')
const { generate } = require('oauth-signature')

const oauthAuthorization = (url, method, oauth_consumer_key, oauth_consumer_secret, { oauth_token_secret, params } = {}) => {
  const parameters = Object.assign({ oauth_consumer_key }, baseParams(), params)
  const oauth_signature = generate(method, url, parameters, oauth_consumer_secret, oauth_token_secret)
  return `OAuth ${concatParams(parameters, oauth_signature)}`
}

const baseParams = () => ({
  oauth_nonce: uuid().replace(/-/g, ''),
  oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
  oauth_signature_method: 'HMAC-SHA1',
  oauth_version: '1.0'
})

const concatParams = (parameters, oauth_signature) =>
  Object.entries(Object.assign({}, parameters, { oauth_signature }))
  .map(([key,value]) => `${key}="${value}"`)
  .join(',')

// just comparing so not use.
const rfc3986 = {
  'oauth-1.0a': (str) =>
    encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\*/g, "%2A")
    .replace(/\'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29"),

  'request/oauth-sign': (str) =>
    encodeURIComponent(str)
    .replace(/!/g,'%21')
    .replace(/\*/g,'%2A')
    .replace(/\(/g,'%28')
    .replace(/\)/g,'%29')
    .replace(/'/g,'%27'),

  'oauth-signature': (str) =>
    encodeURIComponent(decoded)
    .replace(/[!'()]/g, escape)
    .replace(/\*/g, "%2A")
}

module.exports = oauthAuthorization