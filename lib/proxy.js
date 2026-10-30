/**
 * 反代本体：TLS 终止 + HTTP Basic 认证 + Host/Origin 改写 + 会话 cookie 注入 + WS 直通。
 *
 * 与 独立进程版的 `server.js` 是同一套设计（那是独立进程版本，
 * 这是插件版本），差别只在于：
 *   - 配置来自插件行（`config:`）而不是 config.json；
 *   - 证书缺失时自动现签一张自签证书（见 lib/cert.js），不要求机器上有 openssl；
 *   - 生命周期交给 Cordis：`start()` 返回的 stop 会关掉监听与所有在途连接。
 *
 * 为什么必须是「HTTP 反代」而不是端口转发（两者差别就是它的全部价值）：
 *   1. DSH GUI 的 /api 信任栅栏要求 `Host` 是回环或显式 trusted-host，且 `Origin`
 *      必须与之同源 —— 所以 `Host` / 本站点来源的 `Origin` 要改写为回环 authority，
 *      而**外来的 Origin 原样透传**，跨站请求依旧被 GUI 拒掉；
 *   2. 浏览器会话是 authority 绑定的签名 cookie —— 代理用凭证文件里的密钥
 *      每请求现签一枚注入，因此不需要重启 GUI、也不需要抄启动 token。
 */

import { X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer as createHttpsServer } from 'node:https'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import { connect as netConnect } from 'node:net'

import { mintCookie, PasswordFile } from './credentials.js'
import { COOKIE_NAME, clearCookieHeader, parseCookieHeader, setCookieHeader } from './cookie-store.js'

/** 只在单跳内有效的头，不能透传。 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/* ---------------------------------------------------------------- helpers ---- */

function parseBasic(headerValue) {
  if (typeof headerValue !== 'string' || !headerValue.toLowerCase().startsWith('basic ')) return undefined
  let decoded
  try {
    decoded = Buffer.from(headerValue.slice(6).trim(), 'base64').toString('utf8')
  } catch {
    return undefined
  }
  const at = decoded.indexOf(':')
  if (at < 0) return undefined
  return { user: decoded.slice(0, at), password: decoded.slice(at + 1) }
}

export function isLoopback(address) {
  return (
    address === '127.0.0.1' ||
    address === '::1' ||
    address === '::ffff:127.0.0.1' ||
    (typeof address === 'string' && address.startsWith('127.'))
  )
}

/**
 * 丢弃不该上游的 cookie：
 *   · `dsh-auth-*`  —— DSH 自己的会话 cookie，一律由代理现签
 *   · `mira-proxy-auth` —— 代理自己的认证 cookie，上游不认识它，没必要带过去
 */
export function stripSessionCookies(cookieHeader) {
  if (typeof cookieHeader !== 'string') return ''
  const kept = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part !== '' && !part.startsWith('dsh-auth-') && !part.startsWith(COOKIE_NAME + '='))
  return kept.length === 0 ? '' : `${kept.join('; ')}; `
}

function clientOrigin(headers, protocol = 'https') {
  const host = headers.host
  if (typeof host !== 'string' || host === '') return undefined
  return `${protocol}://${host}`
}

/**
 * 构造发往上游的头集合。
 *
 * `Host` 换成回环 authority（信任栅栏要求）；`Origin` 只在属于本站点时改写，
 * 外来 Origin 原样透传（于是跨站请求仍被 GUI 拒掉，这正是想要的行为）；
 * 客户端自带的会话 cookie 换成现签的一枚；Basic 凭据与逐跳头丢掉。
 */
export function upstreamHeaders(headers, state, { websocket = false } = {}) {
  const out = {}
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (lower === 'host' || lower === 'authorization' || lower === 'cookie') continue
    if (lower === 'origin') continue
    if (!websocket && HOP_BY_HOP.has(lower)) continue
    if (value === undefined) continue
    out[lower] = value
  }

  const authority = `${state.config.upstream.host}:${String(state.config.upstream.port)}`
  out.host = authority

  const session = mintCookie(authority, state.secret.get(), state.config.cookies.maxAgeDays)
  out.cookie = `${stripSessionCookies(headers.cookie)}${session.name}=${session.value}`

  if (headers.origin !== undefined) {
    try {
      const origin = new URL(headers.origin)
      out.origin = origin.port === String(state.config.listen.port) ? `http://${authority}` : headers.origin
    } catch {
      out.origin = headers.origin
    }
  }

  const remote = state.remoteAddress
  if (remote !== undefined) {
    out['x-forwarded-for'] =
      headers['x-forwarded-for'] === undefined ? remote : `${headers['x-forwarded-for']}, ${remote}`
  }
  out['x-forwarded-proto'] = state.protocol
  out['x-forwarded-host'] = typeof headers.host === 'string' ? headers.host : ''
  return out
}

function rewriteLocation(value, state) {
  if (typeof value !== 'string') return value
  const upstreamOrigin = `http://${state.config.upstream.host}:${String(state.config.upstream.port)}`
  if (!value.startsWith(upstreamOrigin)) return value
  const origin = clientOrigin(state.clientHeaders, state.protocol ?? 'https')
  return origin === undefined ? value : `${origin}${value.slice(upstreamOrigin.length)}`
}

/* ----------------------------------------------------------------- server ---- */

/**
 * 建好（但还没 listen 的）反代服务器。
 *
 * @param {object} state `{ config, logger, secret, version }`
 * @returns {{server: import('node:https').Server, sockets: Set, protocol: string}}
 */
export function createProxyServer(state) {
  const { config, logger } = state
  const sockets = new Set()
  // 功能点3：http / 自签名 https 由配置开关决定。**不静默降级** —— 想用 http 必须显式关掉。
  const tlsEnabled = config.tls?.enabled !== false
  state.protocol = tlsEnabled ? 'https' : 'http'
  state.tlsEnabled = tlsEnabled
  const authority = `${config.upstream.host}:${String(config.upstream.port)}`
  state.authority = authority
  const tlsOptions = tlsEnabled
    ? { cert: readFileSync(config.tls.certFile), key: readFileSync(config.tls.keyFile), minVersion: 'TLSv1.2' }
    : null

  const passwords = new PasswordFile(config.auth.htpasswdFile, config.auth.users)
  state.passwords = passwords

  const secureCookies = tlsEnabled
  const cookieMaxAgeSeconds = Math.floor(config.cookies.maxAgeDays * 24 * 60 * 60)

  function issueCookie(user, stamp) {
    const issued = state.cookies.issue(user, authority, stamp)
    return setCookieHeader(issued.value, { maxAgeSeconds: cookieMaxAgeSeconds, secure: secureCookies })
  }

  /**
   * 认证结果 { user?, via?, setCookie?, clearCookie? }。
   *
   * 顺序：先看代理自有 cookie（便宜、不打扰用户），再退到 HTTP Basic。
   * Basic 永远权威 —— 口令当面验过，比 cookie 强。
   * 口令变了（stamp 不符）→ 撤销该用户的记录并给 401 + 清 cookie（功能点6「改密即全失效」）。
   */
  function authenticate(req) {
    const stamp = passwords.passwordStamp()
    const raw = parseCookieHeader(req.headers.cookie)[COOKIE_NAME]
    let stale = null
    if (raw) {
      const verdict = state.cookies.verify(raw, { authority, passwordStamp: stamp })
      if (verdict.ok) {
        const renewed = state.cookies.renewIfNeeded(verdict.record, stamp)
        return {
          user: verdict.user,
          via: 'cookie',
          setCookie: renewed ? setCookieHeader(renewed.value, { maxAgeSeconds: cookieMaxAgeSeconds, secure: secureCookies }) : undefined,
        }
      }
      if (verdict.reason === 'stamp' && verdict.user) {
        state.cookies.revoke(verdict.user, authority)
        stale = verdict
        logger.write(`info cookie-revoked ${verdict.user} 口令已变更，旧 cookie 作废`)
      } else if (verdict.reason !== 'expired') {
        logger.write(`info cookie-rejected ${String(verdict.reason)}`)
      }
    }

    const basic = parseBasic(req.headers.authorization)
    if (basic === undefined) {
      return stale ? { clearCookie: true } : {}
    }
    if (!passwords.verify(basic.user, basic.password)) {
      return stale ? { clearCookie: true } : {}
    }

    // Basic 通过：确保这个用户有一枚新鲜的 cookie（没有 / 口令变了 / 快到期 → 重新签发）
    const record = state.cookies.records.get(basic.user + '@' + authority)
    const needsIssue = !record || record.stamp !== stamp || record.expiresAt - Date.now() < config.cookies.renewWithinDays * 24 * 60 * 60 * 1000
    return {
      user: basic.user,
      via: 'basic',
      setCookie: needsIssue ? issueCookie(basic.user, stamp) : undefined,
    }
  }

  function deny(res, code = 401, extraHeaders = {}) {
    const headers = {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      // 拒绝响应不保持长连接：它们不该占住 socket（也便于 stop() 干净收尾）
      connection: 'close',
      ...extraHeaders,
    }
    if (code === 401) headers['www-authenticate'] = `Basic realm="${config.auth.realm}", charset="UTF-8"`
    res.writeHead(code, headers)
    res.end(code === 401 ? 'authentication required\n' : 'not found\n')
  }

  function healthBody(req, remote, user) {
    let certInfo = null
    try {
      const cert = new X509Certificate(readFileSync(config.tls.certFile))
      certInfo = { subject: cert.subject, validTo: cert.validTo }
    } catch {
      certInfo = null
    }
    return JSON.stringify(
      {
        ok: true,
        plugin: 'mira_proxy',
        version: state.version,
        user: user ?? null,
        listen: `${config.listen.host}:${String(config.listen.port)}`,
        upstream: `http://${config.upstream.host}:${String(config.upstream.port)}`,
        accounts: passwords.count(),
        htpasswdFile: config.auth.htpasswdFile,
        cert: certInfo,
        serverTime: new Date().toISOString(),
        remote,
      },
      null,
      2,
    )
  }

  const handler = (req, res) => {
    const started = Date.now()
    const remote = req.socket.remoteAddress
    const method = req.method ?? 'GET'
    const url = req.url ?? '/'

    // 健康检查：默认只允许回环，免得把账号数/证书信息发给整个局域网
    if (url === '/__proxy/health' || url === '/__proxy/health/') {
      if (config.health.loopbackOnly && !isLoopback(remote)) {
        logger.write(`403 health ${String(remote)} ${method} ${url}`)
        deny(res, 403)
        return
      }
      const health = authenticate(req) ?? {}
      if (!config.health.loopbackOnly && !health.user) {
        logger.write(`401 health ${String(remote)} ${method} ${url} user=-`)
        deny(res, 401)
        return
      }
      const user = health.user
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        connection: 'close',
      })
      res.end(`${healthBody(req, remote, user)}\n`)
      return
    }

    const auth = authenticate(req) ?? {}
    if (!auth.user) {
      logger.write(`401 auth ${String(remote)} ${method} ${url} user=-`)
      deny(res, 401, auth.clearCookie ? { 'set-cookie': clearCookieHeader({ secure: secureCookies }) } : {})
      return
    }
    const user = auth.user

    let headers
    try {
      headers = upstreamHeaders(req.headers, { ...state, remoteAddress: remote, clientHeaders: req.headers })
    } catch (error) {
      logger.write(`500 session-cookie ${user} ${String(remote)} ${method} ${url} ${error.message}`)
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`cannot mint the upstream session cookie: ${error.message}\n`)
      return
    }

    const upstream = httpRequest(
      {
        host: config.upstream.host,
        port: config.upstream.port,
        method,
        path: url,
        headers,
      },
      (upstreamRes) => {
        const responseHeaders = {}
        for (const [name, value] of Object.entries(upstreamRes.headers)) {
          const lower = name.toLowerCase()
          if (HOP_BY_HOP.has(lower)) continue
          // 必须带上 protocol：http 模式下把 Location 改写成 https:// 会让浏览器
          // 去敲一个根本没监听的端口（原实现丢了这个字段，`?? 'https'` 永远兜底成 https）。
          responseHeaders[lower] = lower === 'location'
            ? rewriteLocation(value, { config, protocol: state.protocol, clientHeaders: req.headers })
            : value
        }
        if (auth.setCookie) {
          const existing = responseHeaders['set-cookie']
          responseHeaders['set-cookie'] = existing === undefined
            ? [auth.setCookie]
            : (Array.isArray(existing) ? [...existing, auth.setCookie] : [existing, auth.setCookie])
        }
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, responseHeaders)
        upstreamRes.pipe(res)
        upstreamRes.on('end', () => {
          logger.write(`${String(upstreamRes.statusCode)} ${user} ${String(remote)} ${method} ${url} ${String(Date.now() - started)}ms`)
        })
      },
    )

    upstream.on('error', (error) => {
      logger.write(`502 upstream ${user} ${String(remote)} ${method} ${url} ${error.message}`)
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
        res.end(
          `upstream ${config.upstream.host}:${String(config.upstream.port)} unavailable: ${error.message}\n` +
            '（DSH Web GUI 没在跑？上游地址可在插件配置里改 upstreamPort）\n',
        )
      } else {
        res.destroy()
      }
    })

    req.on('aborted', () => {
      upstream.destroy()
    })
    req.pipe(upstream)
  }

  const server = tlsEnabled
    ? createHttpsServer({ ...tlsOptions, ALPNProtocols: ['http/1.1'] }, handler)
    : createHttpServer(handler)

  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })

  // WebSocket / 其它 Upgrade：认证后改写字手，再退化成裸字节隧道。
  server.on('upgrade', (req, socket, head) => {
    const remote = req.socket.remoteAddress
    const url = req.url ?? '/'
    const wsAuth = authenticate(req) ?? {}
    const user = wsAuth.user
    if (!user) {
      logger.write(`401 auth-ws ${String(remote)} ${url} user=-`)
      socket.write(
        `HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="${config.auth.realm}", charset="UTF-8"\r\nConnection: close\r\n\r\n`,
      )
      socket.destroy()
      return
    }

    let headers
    try {
      headers = upstreamHeaders(req.headers, { ...state, remoteAddress: remote, clientHeaders: req.headers }, { websocket: true })
    } catch (error) {
      logger.write(`500 session-cookie-ws ${user} ${String(remote)} ${url} ${error.message}`)
      socket.destroy()
      return
    }

    const upstream = netConnect(config.upstream.port, config.upstream.host, () => {
      const lines = [`${req.method ?? 'GET'} ${url} HTTP/1.1`]
      for (const [name, value] of Object.entries(headers)) {
        for (const item of Array.isArray(value) ? value : [value]) lines.push(`${name}: ${String(item)}`)
      }
      lines.push('', '')
      upstream.write(lines.join('\r\n'))
      if (head !== undefined && head.length > 0) upstream.write(head)
      upstream.pipe(socket)
      socket.pipe(upstream)
      logger.write(`101 ws ${user} ${String(remote)} ${url}`)
    })

    upstream.on('error', (error) => {
      logger.write(`502 upstream-ws ${user} ${String(remote)} ${url} ${error.message}`)
      socket.destroy()
    })
    socket.on('error', () => upstream.destroy())
    socket.on('close', () => upstream.destroy())
  })

  server.on('clientError', (error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
  })

  // 长连接（SSE / 模型流式输出）不能被超时切断。
  // 但这只需要放宽**响应**侧；requestTimeout 管的是「收完整个请求」的时限，
  // 设成 0 等于关掉防护 —— 于是一个慢速发 body 的连接可以永久占住 socket。
  server.requestTimeout = 300000
  server.headersTimeout = 120000
  server.keepAliveTimeout = 75000

  state.sockets = sockets
  state.server = server
  return server
}

/**
 * 起服务并返回 stop()。监听失败（端口被占等）会 reject，由插件加载日志暴露。
 */
export function startProxy(state) {
  const server = createProxyServer(state)
  const sockets = state.sockets
  const debug = process.env.MIRA_PROXY_DEBUG === '1'
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener('listening', onListening)
      if (debug) console.log(`[dbg] startProxy :${state.config.listen.port} 失败 ${error.code}`)
      reject(error)
    }
    const onListening = () => {
      server.removeListener('error', onError)
      state.started = true
      if (debug) console.log(`[dbg] startProxy :${state.config.listen.port} 已监听`)
      resolve(async () => {
        if (debug) console.log(`[dbg] stopProxy :${state.config.listen.port} 开始（sockets=${String(sockets.size)}）`)
        // 先断开自己跟踪的连接（含 WebSocket 隧道）。
        for (const socket of sockets) socket.destroy()
        sockets.clear()

        // 等一个优雅的 close 回调；某些「已 destroy 但仍被 Node 计入连接数」的
        // keep-alive socket 会让回调永远不来，那就强行关连接再等一次。
        // 全程有界，保证 stop() 返回后端口一定已被释放（否则重启会 EADDRINUSE）。
        const waitClose = (ms) =>
          new Promise((done) => {
            let settled = false
            const finish = () => {
              if (settled) return
              settled = true
              clearTimeout(timer)
              done()
            }
            const timer = setTimeout(finish, ms)
            timer.unref?.()
            server.close(finish)
          })

        await waitClose(400)
        // close() 后 listening 立刻为 false，端口已释放；剩下的只是清理残留连接。
        server.closeIdleConnections?.()
        if (server._connections > 0) {
          if (debug) console.log(`[dbg] stopProxy :${state.config.listen.port} 残留连接，强制关闭`)
          server.closeAllConnections?.()
        }
        if (debug) console.log(`[dbg] stopProxy :${state.config.listen.port} 结束`)
        return undefined
      })
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(state.config.listen.port, state.config.listen.host)
  })
}
