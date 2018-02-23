const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const bodyparser = require('koa-bodyparser')
const session = require('koa-session')
const passport = require('koa-passport')
const OAuthStrategy = require('passport-oauth1')
const opn = require('opn')
const { createJWT, verifyJWT } = require('./jwt.js')

const PORT = 7005
const { CONSUMER_KEY: consumerKey, CONSUMER_SECRET: consumerSecret } = process.env
const REQUEST_PATH = '/auth/request'
const CALLBACK_PATH = '/auth/callback'

const BASE = 'https://www.tumblr.com/oauth'

passport.deserializeUser((session_cookie, done) => done(null, session_cookie))

passport.serializeUser((session_cookie, done) => done(null, session_cookie))

passport.use(
  'tumblr',
  new OAuthStrategy(
    {
      consumerKey,
      consumerSecret,
      signatureMethod: 'HMAC-SHA1',
      requestTokenURL: `${BASE}/request_token`,
      userAuthorizationURL: `${BASE}/authorize`,
      accessTokenURL: `${BASE}/access_token`,
      callbackURL: `http://localhost:${PORT}${CALLBACK_PATH}`
    },
    (token, token_secret, profile, done) => done(null, { token, token_secret })
  )
)

const successRedirect = '/auth/redirected'
const failureRedirect = '/auth/failured'
const router = new Router()
.get(
  REQUEST_PATH,
  passport.authenticate('tumblr')
)
.get(
  CALLBACK_PATH,
  passport.authenticate('tumblr', { successRedirect, failureRedirect })
)
.get(
  successRedirect,
  (ctx) => {
    const { token, token_secret } = ctx.state.user
    const jwt = createJWT({ token, token_secret })
    ctx.cookies.set('passport:jwt', jwt, { overwrite: true, signed: false })
    ctx.redirect('/')
  }
)
.get(
  failureRedirect,
  (ctx) => {
    ctx.body = 'failure'
  }
)
.get(
  '/',
  (ctx) => {
    const { token, token_secret } = verifyJWT(ctx.cookies.get('passport:jwt')) || {}
    ctx.body = JSON.stringify({ token, token_secret }, null, 2)
  }
)

const app = new Koa()

app.proxy = true
app.keys = ['passport']

app
.use(logger())
.use(bodyparser())
.use(session({ key: 'passport:sess', maxAge: 'session', signed: false }, app))
.use(passport.initialize())
.use(passport.session())
.use(router.routes())
.use(router.allowedMethods())
.listen(PORT, () => opn(`http://localhost:${PORT}${REQUEST_PATH}`))