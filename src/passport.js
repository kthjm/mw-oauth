const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const bodyparser = require('koa-bodyparser')
const session = require('koa-session')
const passport = require('koa-passport')
const OAuthStrategy = require('passport-oauth1')
const { createJWT, verifyJWT } = require('./JWT.js')

const PORT = 7000
const BASE = 'https://www.tumblr.com/oauth'
const { CONSUMER_KEY: consumerKey, CONSUMER_SECRET: consumerSecret } = process.env

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
      callbackURL: `http://localhost:${PORT}/auth/callback`
    },
    (token, token_secret, profile, done) => done(null, { token, token_secret })
  )
)

const router = new Router()
const successRedirect = '/auth/redirected'
const failureRedirect = '/auth/failured'

router.get('/auth/request', passport.authenticate('tumblr'))

router.get('/auth/callback', passport.authenticate('tumblr', { successRedirect, failureRedirect }))

router.get(successRedirect, (ctx) => {
  const { token, token_secret } = ctx.state.user
  const jwt = createJWT({ token, token_secret })
  ctx.cookies.set('passport:jwt', jwt, { overwrite: true, signed: false })
  ctx.redirect('/')
})

router.get(failureRedirect, (ctx) => {
  ctx.body = 'failure'
})

router.get('/', (ctx) => {
  const { token, token_secret } = verifyJWT(ctx.cookies.get('passport:jwt')) || {}
  ctx.body = JSON.stringify({ token, token_secret }, null, 2)
})

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
.listen(PORT, () => console.log('has listen'))