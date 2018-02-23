const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const fetch = require('node-fetch')
const qs = require('querystring')
const opn = require('opn')
const oauthAuthorization = require('./oauthAuthorization.js')
const { createJWT, verifyJWT } = require('./jwt.js')

const PORT = 7001
const { CONSUMER_KEY, CONSUMER_SECRET } = process.env
const REQUEST_PATH = '/auth/request'
const CALLBACK_PATH = '/auth/callback'

const BASE = `https://www.tumblr.com/oauth`
const REQUEST_TOKEN_URL = `${BASE}/request_token`
const AUTHORIZE_URL = `${BASE}/authorize`
const ACCESS_TOKEN_URL = `${BASE}/access_token`

const router = new Router()
.get(
  REQUEST_PATH,
  (ctx) => {

    const url = REQUEST_TOKEN_URL
    const method = 'POST'
    const oauth_callback = `http://localhost:${PORT}${CALLBACK_PATH}`

    return fetch(url, {
      method,
      headers: {
        Authorization: oauthAuthorization(
          url,
          method,
          CONSUMER_KEY,
          CONSUMER_SECRET,
          { params: { oauth_callback } }
        )
      }
    })
    .then(res => res.text())
    .then(querystring => qs.parse(querystring))
    .then(({ oauth_token, oauth_token_secret, oauth_callback_confirmed }) => {
      ctx.cookies.set('fetch:sess', oauth_token_secret, { overwrite: true, signed: false })
      ctx.redirect(`${AUTHORIZE_URL}?oauth_token=${oauth_token}`)
    })
  }
)
.get(
  CALLBACK_PATH,
  (ctx) => {

    const url = ACCESS_TOKEN_URL
    const method = 'POST'
    const oauth_token_secret = ctx.cookies.get('fetch:sess')
    const { oauth_token, oauth_verifier } = ctx.query

    return fetch(url, {
      method,
      headers: {
        Authorization: oauthAuthorization(
          url,
          method,
          CONSUMER_KEY,
          CONSUMER_SECRET,
          { oauth_token_secret, params: { oauth_token, oauth_verifier } }
        )
      }
    })
    .then(res => res.text())
    .then(querystring => qs.parse(querystring))
    .then(({ oauth_token: token, oauth_token_secret: token_secret }) => {
      const jwt = createJWT({ token, token_secret })
      ctx.cookies.set('fetch:jwt', jwt, { overwrite: true, signed: false })
      ctx.redirect('/')
    })
  }
)
.get(
  '/',
  (ctx) => {
    const { token, token_secret } = verifyJWT(ctx.cookies.get('fetch:jwt')) || {}
    ctx.body = JSON.stringify({ token, token_secret }, null, 2)
  }
)

const app = new Koa()

app.keys = ['fetch']

app
.use(logger())
.use(router.routes())
.use(router.allowedMethods())
.listen(PORT, () => opn(`http://localhost:${PORT}${REQUEST_PATH}`))