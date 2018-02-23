const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const rp = require('request-promise-native')
const qs = require('querystring')
const { createJWT, verifyJWT } = require('./JWT.js')

const PORT = 7005
const BASE = 'https://www.tumblr.com/oauth'
const REQUEST_TOKEN_URL = `${BASE}/request_token`
const AUTHORIZE_URL = `${BASE}/authorize`
const ACCESS_TOKEN_URL = `${BASE}/access_token`
const { CONSUMER_KEY: consumer_key, CONSUMER_SECRET: consumer_secret } = process.env
const CALLBACK_PATH = '/auth/callback'

const router = new Router()
.get('/auth/request', (ctx) =>
  rp({
    url: REQUEST_TOKEN_URL,
    method: 'POST',
    oauth: {
      consumer_key,
      consumer_secret,
      callback: `http://localhost:${PORT}${CALLBACK_PATH}`
    }
  })
  .then(querystring => qs.parse(querystring))
  .then(({ oauth_token, oauth_token_secret, oauth_callback_confirmed }) => {
    ctx.cookies.set('rp:sess', oauth_token_secret, { overwrite: true, signed: false })
    ctx.redirect(`${AUTHORIZE_URL}?oauth_token=${oauth_token}`)
  })
)
.get(CALLBACK_PATH, (ctx) =>
  rp({
    url: ACCESS_TOKEN_URL,
    method: 'POST',
    oauth: {
      consumer_key,
      consumer_secret,
      token: ctx.query.oauth_token,
      token_secret: ctx.cookies.get('rp:sess'),
      verifier: ctx.query.oauth_verifier
    }
  })
  .then(querystring => qs.parse(querystring))
  .then(({ oauth_token: token, oauth_token_secret: token_secret }) => {
    const jwt = createJWT({ token, token_secret })
    ctx.cookies.set('rp:jwt', jwt, { overwrite: true, signed: false })
    ctx.redirect('/')
  })
)

router.get('/', (ctx) => {
  const { token, token_secret } = verifyJWT(ctx.cookies.get('rp:jwt')) || {}
  ctx.body = JSON.stringify({ token, token_secret }, null, 2)
})

const app = new Koa()

app.keys = ['rp']

app
.use(logger())
.use(router.routes())
.use(router.allowedMethods())
.listen(PORT, () => console.log(`has listen > ${PORT}`))