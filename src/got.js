const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const got = require('got')
const qs = require('querystring')
const createAuthorization = require('./createAuthorization.js')
const { createJWT, verifyJWT } = require('./JWT.js')

const PORT = 7000
const BASE = `https://www.tumblr.com/oauth`
const REQUEST_TOKEN_URL = `${BASE}/request_token`
const AUTHORIZE_URL = `${BASE}/authorize`
const ACCESS_TOKEN_URL = `${BASE}/access_token`
const { CONSUMER_KEY, CONSUMER_SECRET } = process.env

const router = new Router()

router.get('/auth/request', (ctx) => {

  const url = REQUEST_TOKEN_URL
  const method = 'POST'

  return got(url, {
    method,
    headers: {
      Authorization: createAuthorization(
        url,
        method,
        CONSUMER_KEY,
        CONSUMER_SECRET
      )
    }
  })
  .then(({ body }) => qs.parse(body))
  .then(({ oauth_token, oauth_token_secret, oauth_callback_confirmed }) => {
    ctx.cookies.set('got:sess', oauth_token_secret, { overwrite: true, signed: false })
    ctx.redirect(`${AUTHORIZE_URL}?oauth_token=${oauth_token}`)
  })
})

router.get('/auth/callback', (ctx) => {

  const url = ACCESS_TOKEN_URL
  const method = 'POST'
  const oauth_token_secret = ctx.cookies.get('got:sess')
  const { oauth_token, oauth_verifier } = ctx.query

  return got(url, {
    method,
    headers: {
      Authorization: createAuthorization(
        url,
        method,
        CONSUMER_KEY,
        CONSUMER_SECRET,
        { oauth_token_secret, params: { oauth_token, oauth_verifier } }
      )
    }
  })
  .then(({ body }) => qs.parse(body))
  .then(({ oauth_token: token, oauth_token_secret: token_secret }) => {
    const jwt = createJWT({ token, token_secret })
    ctx.cookies.set('got:jwt', jwt, { overwrite: true, signed: false })
    ctx.redirect('/')
  })
})

router.get('/', (ctx) => {
  const { token, token_secret } = verifyJWT(ctx.cookies.get('got:jwt')) || {}
  ctx.body = JSON.stringify({ token, token_secret }, null, 2)
})

const app = new Koa()

app.keys = ['got']

app
.use(logger())
.use(router.routes())
.use(router.allowedMethods())
.listen(PORT, () => console.log('has listen'))