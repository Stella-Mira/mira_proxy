/**
 * mira_proxy 自检：node test/smoke.mjs
 *
 * 全过 → 退出码 0，末行 `==== ALL PASS（N 项断言）====`；失败逐行 `[FAIL] 编号 说明`，退出码 1。
 *
 * 覆盖 tool_shared/PLAN.md §1.6 的 F1–F6：
 *   F2 端口被占 → 诊断给出「谁占着 + 怎么换端口」，不静默降级
 *   F3 证书缺失 → 自动现签，并给出路径与 SHA256 指纹
 *   F4 改密码后旧 cookie → 401，记录被清，日志一行 info
 *   F5 剩余不足 renewWithinDays → 自动续期（expiresAt 前移）
 *   F6 凭据文件 600；工具输出与日志里没有 cookie 值
 * 另加：配置归一（新旧键）、非法值拒绝启动、明文口令拒绝、**真起一个 http 反代**跑端到端
 * （401 → Basic+Set-Cookie → 仅 cookie 通过 → 改密失效 → 续期 → 上游只收到 dsh-auth-*）。
 *
 * 端到端用 `tls.enabled=false` 的明文模式，监听 127.0.0.1:0（系统分配端口），
 * 上游是同进程里的假 HTTP 服务 —— 自检不需要真 GUI、不需要证书信任、不碰任何真实配置。
 */

import { createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

let passed = 0
const failures = []
let current = '(未命名)'

function check(ok, message) {
  if (ok) { passed++; return true }
  failures.push('[' + current + '] ' + message)
  return false
}

function eq(actual, expected, message) {
  return check(JSON.stringify(actual) === JSON.stringify(expected),
    message + '（期望 ' + JSON.stringify(expected) + '，实得 ' + JSON.stringify(actual) + '）')
}

async function test(id, name, fn) {
  current = id + ' ' + name
  try { await fn() } catch (error) {
    failures.push('[' + current + '] 抛异常：' + (error && error.stack ? error.stack.split('\n').slice(0, 3).join(' | ') : String(error)))
  }
}

const TMP = mkdtempSync(join(tmpdir(), 'mira-proxy-smoke-'))
process.env.DSH_HOME = TMP
const BASE = join(TMP, 'mira_config', 'mira_proxy')

const logLines = []
const logger = {
  info: (m) => logLines.push('I ' + m),
  warn: (m) => logLines.push('W ' + m),
  error: (m) => logLines.push('E ' + m),
  debug: () => {},
  write: (m) => logLines.push('L ' + m),
}

const { normalizeConfig } = await import('../lib/config.js')
const { describePortHolder, explainListenFailure, certFingerprint, explainCertFailure } = await import('../lib/diagnostics.js')
const { ensureCertificate } = await import('../lib/cert.js')
const { CookieStore, COOKIE_NAME } = await import('../lib/cookie-store.js')
const { hashPassword } = await import('../lib/apr1.js')
const { CredentialSecret } = await import('../lib/credentials.js')
const { startProxy } = await import('../lib/proxy.js')
const { b64url } = await import('../lib/credentials.js')

/* ── 配置归一 ───────────────────────────────────────────── */

await test('F7', '配置归一：新嵌套键优先，旧扁平键映射并点名', async () => {
  const nested = normalizeConfig({ listen: { host: '127.0.0.1', port: 9000 }, tls: { enabled: false } }, { baseDir: BASE })
  eq(nested.ok, true, '合法配置应通过')
  eq(nested.config.listen.port, 9000, '嵌套键生效')
  eq(nested.config.tls.enabled, false, 'tls.enabled=false 应生效')

  const legacy = normalizeConfig({ listenHost: '0.0.0.0', listenPort: 8543, certDays: 365, upstreamPort: 4000 }, { baseDir: BASE })
  eq(legacy.ok, true, '旧键配置也应通过')
  eq(legacy.config.listen.port, 8543, 'listenPort 应映射')
  eq(legacy.config.upstream.port, 4000, 'upstreamPort 应映射')
  check(legacy.deprecated.includes('listenPort → listen.port'), '应点名 listenPort：' + JSON.stringify(legacy.deprecated))

  const mixed = normalizeConfig({ listenPort: 1111, listen: { port: 2222 } }, { baseDir: BASE })
  eq(mixed.config.listen.port, 2222, '新键优先于旧键')
})

await test('F7b', '非法配置直接拒绝（不猜、不降级）', async () => {
  const badPort = normalizeConfig({ listen: { port: 99999 } }, { baseDir: BASE })
  eq(badPort.ok, false, '端口越界应拒绝')
  eq(badPort.error.code, 'config/invalid', '错误码应是 config/invalid')

  const badRenew = normalizeConfig({ cookies: { maxAgeDays: 10, renewWithinDays: 10 } }, { baseDir: BASE })
  eq(badRenew.ok, false, 'renewWithinDays ≥ maxAgeDays 应拒绝')

  const plain = normalizeConfig({ auth: { users: { alice: 'secret' } } }, { baseDir: BASE })
  eq(plain.ok, false, '明文口令必须拒绝')
  check(String(plain.error.hint).includes('$apr1$'), 'hint 要说明用哈希：' + plain.error.hint)

  const multi = normalizeConfig({ auth: { users: { a: '$apr1$a', b: '$apr1$b' } } }, { baseDir: BASE })
  eq(multi.ok, true, '多账号不应直接拒绝（会破坏现有配置）')
  check(multi.warnings.some((w) => w.includes('不支持真多用户')), '多账号要给 warn：' + JSON.stringify(multi.warnings))
})

/* ── F2 端口占用诊断 ────────────────────────────────────── */

await test('F2', '端口被占：诊断给出占用者与「怎么换端口」', async () => {
  const fakeExec = (cmd) => {
    if (cmd === 'ss') {
      return 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
        + 'LISTEN 0 511 0.0.0.0:8543 0.0.0.0:* users:(("node",pid=4242,fd=23))\n'
    }
    throw new Error('no lsof')
  }
  const holder = describePortHolder(8543, { exec: fakeExec })
  eq(holder.found, true, '应查到占用者')
  check(holder.lines[0].includes('pid=4242'), '应报出 pid：' + JSON.stringify(holder.lines))
  check(holder.hint.includes('listen.port'), 'hint 要指出改哪个配置项：' + holder.hint)

  const explained = explainListenFailure({ code: 'EADDRINUSE' }, { listen: { host: '0.0.0.0', port: 8543 } }, { exec: fakeExec })
  eq(explained.code, 'EADDRINUSE', '应保留系统错误码')
  check(explained.hint.includes('8543'), 'hint 里要有端口号')
  check(!/降级/.test(explained.message), '不允许在诊断里提到静默降级')

  const noTools = describePortHolder(8543, { exec: () => { throw new Error('command not found') } })
  eq(noTools.found, false, '查不到要如实说查不到')
  check(noTools.hint.includes('ss -ltnp'), '查不到时给手动排查命令：' + noTools.hint)

  eq(explainListenFailure({ code: 'EACCES' }, { listen: { host: '0.0.0.0', port: 80 } }).hint.includes('1024'), true, 'EACCES 要给「换 1024 以上」')
  eq(explainListenFailure({ code: 'EADDRNOTAVAIL' }, { listen: { host: '10.9.9.9', port: 8543 } }).code, 'EADDRNOTAVAIL', 'EADDRNOTAVAIL 应保留')
})

/* ── F3 证书现签 + 指纹 ─────────────────────────────────── */

await test('F3', '证书缺失自动现签，给出路径与 SHA256 指纹；失败不降级', async () => {
  const dir = join(BASE, 'data')
  mkdirSync(dir, { recursive: true })
  const certFile = join(dir, 'proxy-cert.pem')
  const keyFile = join(dir, 'proxy-key.pem')
  const cert = ensureCertificate({ certFile, keyFile, commonName: 'localhost', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1'], days: 30 })
  eq(cert.generated, true, '首次应现签')
  check(statSync(certFile).size > 0, '证书文件应落盘')
  const fp = certFingerprint(certFile)
  eq(fp.ok, true, '指纹应能算出来')
  check(String(fp.fingerprint).startsWith('SHA256 '), '指纹格式应为 SHA256 xx:xx：' + fp.fingerprint)
  const again = ensureCertificate({ certFile, keyFile, commonName: 'localhost', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1'], days: 30 })
  eq(again.generated, false, '已有证书不应重复现签')

  const explained = explainCertFailure(new Error('EACCES: mkdir'), { tls: { certFile, keyFile } })
  check(explained.hint.includes('不会静默降级'), '必须明说不会静默降级：' + explained.hint)
})

await test('F3b', '已过期的自签证书会被重签（不会一直拿过期证书对外服务）', async () => {
  const dir = join(BASE, 'case-f3b')
  const certFile = join(dir, 'proxy-cert.pem')
  const keyFile = join(dir, 'proxy-key.pem')
  const made = ensureCertificate({ certFile, keyFile, commonName: 'localhost', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1'], days: -1 })
  eq(made.generated, true, '先造一张已过期证书')
  eq(certFingerprint(certFile).ok, true, '过期证书本身仍可解析')
  const again = ensureCertificate({ certFile, keyFile, commonName: 'localhost', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1'], days: 30 })
  eq(again.generated, true, '过期后应重签：' + JSON.stringify(again))
  const fp = certFingerprint(certFile)
  eq(fp.ok, true, '重签后应能解析')
  check(new Date(fp.validTo).getTime() > Date.now(), '重签后的证书必须未过期：' + fp.validTo)
})

/* ── F4/F5/F6 cookie 语义（纯模块） ──────────────────────── */

function makeStore(dir, options = {}) {
  return new CookieStore({
    baseDir: dir,
    ...options,
    logger,
    now: options.now ?? (() => Date.now()),
  }).load()
}

await test('F4', '改密码：旧 cookie 因 stamp 不符失效，记录被清', async () => {
  const dir = join(BASE, 'case-f4')
  mkdirSync(dir, { recursive: true })
  const store = makeStore(dir, { maxAgeDays: 30, renewWithinDays: 7 })
  const issued = store.issue('alice', '127.0.0.1:3080', 'stamp-old')
  eq(store.verify(issued.value, { authority: '127.0.0.1:3080', passwordStamp: 'stamp-old' }).ok, true, '同口令应通过')

  const wrong = store.verify(issued.value, { authority: '127.0.0.1:3080', passwordStamp: 'stamp-new' })
  eq(wrong.ok, false, '改密后应失效')
  eq(wrong.reason, 'stamp', '失效原因应是 stamp')
  eq(wrong.user, 'alice', '要能报出是哪个用户（好清记录）')

  const removed = store.revoke(wrong.user, '127.0.0.1:3080')
  eq(removed, 1, '应清掉 1 条记录')
  const after = store.verify(issued.value, { authority: '127.0.0.1:3080', passwordStamp: 'stamp-new' })
  eq(after.reason, 'revoked', '清记录后应为 revoked')
})

await test('F4b', 'revokeAll：generation 变化让所有旧 cookie 失效', async () => {
  const dir = join(BASE, 'case-f4b')
  mkdirSync(dir, { recursive: true })
  const store = makeStore(dir)
  const a = store.issue('alice', 'auth1', 's')
  const b = store.issue('bob', 'auth1', 's')
  eq(store.status().count, 2, '应有 2 条记录')
  const removed = store.revokeAll('改密')
  eq(removed, 2, '应清掉 2 条')
  eq(store.verify(a.value, { authority: 'auth1', passwordStamp: 's' }).reason, 'revoked', 'a 应失效')
  eq(store.verify(b.value, { authority: 'auth1', passwordStamp: 's' }).reason, 'revoked', 'b 应失效')
})

await test('F5', '剩余不足 renewWithinDays → 续期，到期时间前移', async () => {
  let clock = Date.now()
  const dir = join(BASE, 'case-f5')
  mkdirSync(dir, { recursive: true })
  const store = new CookieStore({ baseDir: dir, maxAgeDays: 30, renewWithinDays: 7, logger, now: () => clock }).load()
  const issued = store.issue('alice', 'auth1', 's')
  const record = store.records.get('alice@auth1')

  // 剩余 20 天：不该续
  clock = issued.expiresAt - 20 * 86400_000
  eq(store.renewIfNeeded(record, 's'), null, '剩余 20 天不应续期')

  // 剩余 2 天：该续
  clock = issued.expiresAt - 2 * 86400_000
  const renewed = store.renewIfNeeded(record, 's')
  check(renewed !== null, '剩余 2 天应续期')
  check(renewed.expiresAt > issued.expiresAt, '新到期时间应前移：' + new Date(renewed.expiresAt).toISOString())
  eq(store.verify(renewed.value, { authority: 'auth1', passwordStamp: 's' }).ok, true, '新 cookie 应可用')
  check(logLines.some((l) => l.includes('已续期 cookie')), '续期应打一行 info')
})

await test('F5b', '并发续期：同一枚旧 cookie 的两个请求必须拿到同一枚新 cookie', async () => {
  let clock = Date.now()
  const dir = join(BASE, 'case-f5b')
  mkdirSync(dir, { recursive: true })
  const store = new CookieStore({ baseDir: dir, maxAgeDays: 30, renewWithinDays: 7, logger, now: () => clock }).load()
  const issued = store.issue('alice', 'auth1', 's')
  const stale = store.records.get('alice@auth1')
  clock = issued.expiresAt - 2 * 86400_000
  const first = store.renewIfNeeded(stale, 's')
  // 第二个并发请求：它校验时用的还是同一枚旧记录（旧代码会再签一枚并覆盖前一枚）
  const second = store.renewIfNeeded(stale, 's')
  check(first !== null && second !== null, '两个请求都应拿到续期结果')
  eq(first.value, second.value, '后一次的续期不能覆盖前一次已下发的 cookie')
  eq(store.verify(first.value, { authority: 'auth1', passwordStamp: 's' }).ok, true,
    '第一个响应发出去的 cookie 必须仍然可用')
  eq(store.status().count, 1, '同一用户+authority 只应有一条记录')
})

await test('F6', 'cookie 与密钥文件 600；status 不返回 cookie 值', async () => {
  const dir = join(BASE, 'case-f6')
  mkdirSync(dir, { recursive: true })
  const store = makeStore(dir)
  const issued = store.issue('alice', 'auth1', 's')
  eq(statSync(store.file).mode & 0o777, 0o600, 'cookies.json 应为 600')
  eq(statSync(store.secretFile).mode & 0o777, 0o600, 'cookie-secret.key 应为 600')
  const status = JSON.stringify(store.status())
  check(!status.includes(issued.value), 'status 里不能出现 cookie 值')
  check(!status.includes(store.secret.toString('base64')), 'status 里不能出现密钥')
  eq(JSON.parse(status).count, 1, 'status 应报告条数')
})

/* ── 端到端：真起一个 http 反代 ────────────────────────── */

await test('F1/E2E', '端到端：401 → Basic+Set-Cookie → 仅 cookie 通过 → 改密失效 → 续期', async () => {
  const baseDir = join(BASE, 'case-e2e')
  mkdirSync(join(baseDir, 'data'), { recursive: true })

  // 假上游：把收到的 cookie 回显出来，便于断言「代理自己的 cookie 没被转发」
  const upstream = createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: 'http://127.0.0.1:' + String(upstreamPort) + '/login' })
      res.end()
      return
    }
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'upstream-cookie=keep-me' })
    res.end(JSON.stringify({ ok: true, url: req.url, cookie: req.headers.cookie ?? '' }))
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port

  // 口令表（真 apr1 hash）
  const htpasswdFile = join(baseDir, 'data', 'webapps.htpasswd')
  writeFileSync(htpasswdFile, 'alice:' + hashPassword('secret') + '\n', 'utf8')

  // DSH 会话签名密钥（给上游现签 dsh-auth-* 用）
  const credentialsFile = join(baseDir, '.credentials.yaml')
  writeFileSync(credentialsFile, 'client-connection/browser-session:\n  secret: ' + b64url(randomBytes(32)) + '\n', 'utf8')

  const normalized = normalizeConfig({
    tls: { enabled: false },
    listen: { host: '127.0.0.1', port: 1 },
    upstream: { host: '127.0.0.1', port: upstreamPort },
    auth: { htpasswdFile },
    cookies: { maxAgeDays: 30, renewWithinDays: 7 },
    health: { loopbackOnly: true },
  }, { baseDir })
  eq(normalized.ok, true, '配置应合法：' + JSON.stringify(normalized.error))
  const config = normalized.config
  config.listen.port = 0 // 让系统分配，避免测试抢端口
  config.tls.certFile = join(baseDir, 'data', 'unused.pem')
  config.tls.keyFile = join(baseDir, 'data', 'unused-key.pem')

  const store = new CookieStore({
    baseDir: config.baseDir,
    cookiesFile: config.cookiesFile,
    secretFile: config.cookieSecretFile,
    maxAgeDays: config.cookies.maxAgeDays,
    renewWithinDays: config.cookies.renewWithinDays,
    logger,
  }).load()

  const state = {
    config,
    logger,
    version: 'smoke',
    cookies: store,
    secret: new CredentialSecret(credentialsFile, config.auth.credentialsKeyId),
  }

  const stop = await startProxy(state)
  const port = state.server.address().port
  check(port > 0, '应真的监听起来')

  const call = (headers = {}, path = '/') => new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'GET', headers, timeout: 3000 }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
    })
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.end()
  })

  // 1. 没认证 → 401 + WWW-Authenticate
  const anonymous = await call()
  eq(anonymous.status, 401, '未认证应 401')
  check(String(anonymous.headers['www-authenticate']).includes('Basic'), '401 要带 WWW-Authenticate')
  check(!anonymous.headers['set-cookie'], '未认证不应发 cookie')

  // 2. Basic → 200 + 我们自己的 Set-Cookie
  const basic = Buffer.from('alice:secret').toString('base64')
  const authed = await call({ authorization: 'Basic ' + basic })
  eq(authed.status, 200, 'Basic 正确应 200')
  const setCookies = [].concat(authed.headers['set-cookie'] ?? [])
  const ours = setCookies.find((c) => c.startsWith(COOKIE_NAME + '='))
  check(ours !== undefined, '应下发 ' + COOKIE_NAME + ' cookie：' + JSON.stringify(setCookies))
  check(ours.includes('HttpOnly'), 'cookie 应 HttpOnly')
  check(setCookies.some((c) => c.startsWith('upstream-cookie=')), '上游的 Set-Cookie 不能被吞掉')
  const cookieValue = ours.split(';')[0]
  eq(store.status().count, 1, '应落盘 1 条 cookie 记录')

  // 3. 只带 cookie（不带 Basic）→ 200
  const cookieOnly = await call({ cookie: cookieValue })
  eq(cookieOnly.status, 200, '仅 cookie 应通过：' + cookieOnly.status)

  // 4. 上游只应看到 dsh-auth-*，不应看到我们的 cookie
  const payload = JSON.parse(cookieOnly.body)
  check(String(payload.cookie).includes('dsh-auth-'), '上游应收到现签的 dsh-auth-*：' + payload.cookie)
  check(!String(payload.cookie).includes(COOKIE_NAME), '代理自己的 cookie 不应转发给上游：' + payload.cookie)
  check(String(payload.cookie).includes('upstream-cookie') === false, '上游不该收到它自己发的 cookie')

  // 5. 健康检查（回环可访问）
  const health = await call({}, '/__proxy/health')
  eq(health.status, 200, '健康检查应 200')
  check(JSON.parse(health.body).plugin === 'mira_proxy', '健康检查应报告插件名')
  check(!health.body.includes(cookieValue.split('=')[1]), '健康检查不能泄漏 cookie 值')

  // 5b. Location 改写只能用**实际入口协议**：http 模式下改写成 https:// 等于把人送去死端口
  const redirect = await call({ authorization: 'Basic ' + basic }, '/redirect')
  eq(redirect.status, 302, '应原样转发 302')
  eq(redirect.headers.location, 'http://127.0.0.1:' + String(port) + '/login',
    'Location 应改写成 http 入口，而不是没监听的 https：' + String(redirect.headers.location))
  check(state.server.requestTimeout > 0, 'requestTimeout 不能是 0（否则慢速 body 可永久占住 socket）')

  // 6. 改密 → 仅 cookie 变 401，且记录被清
  writeFileSync(htpasswdFile, 'alice:' + hashPassword('secret2') + '\n', 'utf8')
  const stale = await call({ cookie: cookieValue })
  eq(stale.status, 401, '改密后旧 cookie 应 401')
  const cleared = [].concat(stale.headers['set-cookie'] ?? []).find((c) => c.startsWith(COOKIE_NAME + '='))
  check(cleared !== undefined && /Max-Age=0/.test(cleared), '应下发清除 cookie 的响应')
  eq(store.status().count, 0, '记录应被清掉')
  check(logLines.some((l) => l.includes('cookie-revoked')), '应打一行 info 说明作废原因')

  // 7. 新口令 Basic → 200，并重新下发 cookie
  const basic2 = Buffer.from('alice:secret2').toString('base64')
  const reAuth = await call({ authorization: 'Basic ' + basic2 })
  eq(reAuth.status, 200, '新口令应 200')
  const reIssued = [].concat(reAuth.headers['set-cookie'] ?? []).find((c) => c.startsWith(COOKIE_NAME + '='))
  check(reIssued !== undefined, '应重新下发 cookie')

  // 8. 续期：把记录改成「剩 2 天」再 Basic
  const record = store.records.get('alice@127.0.0.1:' + String(upstreamPort))
  check(record !== undefined, '应能找到记录')
  const oldExpiry = record.expiresAt
  record.expiresAt = Date.now() + 2 * 86400_000
  const renewRes = await call({ authorization: 'Basic ' + basic2 })
  eq(renewRes.status, 200, '续期请求应 200')
  const renewedCookie = [].concat(renewRes.headers['set-cookie'] ?? []).find((c) => c.startsWith(COOKIE_NAME + '='))
  check(renewedCookie !== undefined, '应在响应里续期')
  check(store.records.get('alice@127.0.0.1:' + String(upstreamPort)).expiresAt > oldExpiry - 25 * 86400_000,
    'records 里应有新的到期时间')

  await stop()
  await new Promise((resolve) => upstream.close(resolve))
  eq(statSync(store.file).mode & 0o777, 0o600, 'cookies.json 应 600')
})

/* ── 收尾 ───────────────────────────────────────────────── */

rmSync(TMP, { recursive: true, force: true })
console.log('通过 ' + passed + ' 项断言')
if (failures.length) {
  for (const f of failures) console.log('[FAIL] ' + f)
  console.log('\n==== FAIL（' + failures.length + ' 项失败）====')
  process.exit(1)
}
console.log('\n==== ALL PASS（' + passed + ' 项断言）====')
process.exit(0)
