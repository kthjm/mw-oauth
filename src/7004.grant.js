const Koa = require('koa')
const Router = require('koa-router')
const logger = require('koa-logger')
const session = require('koa-session')
const mount = require('koa-mount')
const Grant = require('grant-koa')
const opn = require('opn')
const { createJWT, verifyJWT } = require('./jwt.js')

const PORT = 7004
const GRANT_CALLBACK_PATH = '/connected/tumblr'

const grant = new Grant({
  server: {
    protocol: 'http',
    host: `localhost:${PORT}`
  },
  tumblr: {
    key: process.env.CONSUMER_KEY,
    secret: process.env.CONSUMER_SECRET,
    callback: GRANT_CALLBACK_PATH
  }
})

const router = new Router()
.get(
  GRANT_CALLBACK_PATH,
  (ctx) => {
    const { access_token: token, access_secret: token_secret } = ctx.query
    const jwt = createJWT({ token, token_secret })
    ctx.cookies.set('grant:jwt', jwt, { overwrite: true, signed: false })
    ctx.redirect('/')
  }
)
.get(
  '/',
  (ctx) => {
    const { token, token_secret } = verifyJWT(ctx.cookies.get('grant:jwt')) || {}
    ctx.body = JSON.stringify({ token, token_secret }, null, 2)
  }
)

const app = new Koa()

app.keys = ['grant']

app
.use(logger())
.use(session({ key: 'grant:sess', maxAge: 'session', signed: false }, app))
.use(mount(grant))
.use(router.routes())
.use(router.allowedMethods())
.listen(PORT, () => opn(`http://localhost:${PORT}/connect/tumblr`))