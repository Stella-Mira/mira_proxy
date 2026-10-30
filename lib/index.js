/**
 * mira_proxy — DSH 主机端插件（内置反向代理）
 *
 * 职责：随插件加载起一个反向代理，把**只监听回环**的 DSH Web GUI（默认 127.0.0.1:3080）
 * 变成局域网可访问的入口：
 *
 *   浏览器 https://<本机IP>:8543 ──TLS + Basic + 代理会话 cookie──▶ http://127.0.0.1:3080
 *
 * 与本仓旧版（0.1.1）的差别，都是任务书 v2 的要求：
 *   · 数据目录改成 `$DSH_HOME/mira_config/mira_proxy/`（约定1）；旧目录只提示迁移，不自动搬
 *   · 配置归一（新嵌套键优先，旧扁平键映射并点名），非法值直接拒绝启动而不是猜
 *   · 新增代理自有会话 cookie：HMAC 签名、绑定 authority、30 天、可撤销、可滚续、600 落盘（功能点5/6）
 *   · http / 自签名 https 由 `tls.enabled` 显式开关；**失败绝不静默降级**
 *   · 启动失败给出「谁占着端口 / 怎么换端口」；证书给出指纹与到期时间（功能点8）
 *   · 新增只读工具 `mira_proxy_status`
 *
 * 仅依赖 Node 内置能力（node:http/https/net/tls/crypto/fs/child_process）。
 */

import { readFileSync } from 'node:fs'
import { hostname, networkInterfaces } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { claimInstance, ensureDir, fail, nowIso, toError } from './kit.mjs'
import { normalizeConfig } from './config.js'
import { ensureCertificate, localIPv4Addresses } from './cert.js'
import { CookieStore } from './cookie-store.js'
import { CredentialSecret, defaultCredentialsPath } from './credentials.js'
import { certFingerprint, explainCertFailure, explainListenFailure } from './diagnostics.js'
import { Logger } from './logger.js'
import { startProxy } from './proxy.js'
import { registerTools } from './tools.js'

export const name = 'mira_proxy'
/** 只读 status 工具要挂到 tools 上。代理本身不需要其它服务。 */
export const inject = ['tools']

const INSTANCE_ID = 'mira_proxy'
const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function readVersion() {
  try {
    return JSON.parse(readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8')).version ?? '0.0.0'
  } catch {
    return '0.0.0'
  }
}

/** 本机各网卡 IPv4（不含回环），用来在日志里直接给出可访问的入口地址。 */
function lanAddresses() {
  const found = []
  try {
    for (const list of Object.values(networkInterfaces())) {
      for (const item of list ?? []) {
        if (item.family === 'IPv4' && item.internal === false) found.push(item.address)
      }
    }
  } catch { /* 取不到就不提示 */ }
  return found
}

export function apply(ctx, rawConfig) {
  const loggerCtx = ctx.logger || null
  const normalized = normalizeConfig(rawConfig ?? {})
  if (!normalized.ok) {
    // 配置非法：不猜、不降级，直接不起来并说清楚
    loggerCtx?.warn?.('[mira_proxy] 配置非法，未启动：' + normalized.error.message + '（' + normalized.error.hint + '）')
    return normalized
  }
  const { config, deprecated, warnings } = normalized
  if (config.enabled === false) {
    loggerCtx?.info?.('[mira_proxy] 已在配置中禁用（enabled: false），未监听')
    return { ok: true, disabled: true }
  }

  const claim = claimInstance(INSTANCE_ID)
  if (!claim.ok) {
    loggerCtx?.warn?.('[mira_proxy] 已经有一个实例在跑（pid=' + (claim.holder?.pid ?? '?') + '），本次加载被拒绝：'
      + '两个实例会抢同一个端口，第二个必然 EADDRINUSE。检查 profile 是不是挂了两遍')
    return fail('plugin/instance', 'mira_proxy 已有实例在跑，重复加载被拒绝',
      '检查 profile 的 cordis patch 是否把 mira_proxy 挂了两遍；一个进程只允许一个实例')
  }

  ensureDir(config.baseDir)
  const version = readVersion()
  const logger = new Logger(config.log.file, config.log.maxBytes, loggerCtx)
  logger.info('加载 v' + version + '：listen ' + (config.tls.enabled ? 'https://' : 'http://')
    + config.listen.host + ':' + String(config.listen.port) + ' -> http://'
    + config.upstream.host + ':' + String(config.upstream.port) + '，baseDir=' + config.baseDir)

  for (const item of deprecated) logger.warn('配置里用了旧键（已映射）：' + item + '，建议改成新结构（见 README「配置」）')
  for (const item of warnings) logger.warn(item)

  const runtime = {
    ok: true,
    version,
    config,
    logger,
    deprecated,
    warnings,
    started: false,
    lastError: null,
    cert: null,
    cookies: null,
    secret: null,
    stop: null,
    status() {
      const cert = runtime.cert
      return {
        ok: true,
        schemaVersion: 2,
        version: runtime.version,
        baseDir: config.baseDir,
        protocol: config.tls.enabled ? 'https' : 'http',
        listen: { host: config.listen.host, port: config.listen.port },
        upstream: { host: config.upstream.host, port: config.upstream.port },
        started: runtime.started,
        disabled: false,
        accounts: {
          count: runtime.passwords ? runtime.passwords.count() : 0,
          names: runtime.passwords ? [...new Set([...runtime.passwords.inline.keys(), ...runtime.passwords.users.keys()])] : [],
          htpasswdFile: config.auth.htpasswdFile,
          multiUser: Object.keys(config.auth.users).length > 1,
        },
        tls: {
          enabled: config.tls.enabled,
          certFile: config.tls.certFile,
          generated: cert?.generated ?? null,
          fingerprint: cert?.fingerprint ?? null,
          subject: cert?.subject ?? null,
          validTo: cert?.validTo ?? null,
        },
        cookies: runtime.cookies ? runtime.cookies.status() : null,
        logFile: config.log.file,
        deprecated,
        warnings,
        lastError: runtime.lastError,
        entryUrls: runtime.started
          ? [
            (config.tls.enabled ? 'https' : 'http') + '://localhost:' + String(config.listen.port),
            ...lanAddresses().map((ip) => (config.tls.enabled ? 'https' : 'http') + '://' + ip + ':' + String(config.listen.port)),
          ]
          : [],
      }
    },
  }

  const disposeTools = registerTools(ctx, () => runtime)

  // ── TLS：没有证书就现签；现签失败就**不启动**（不静默降级 http）
  if (config.tls.enabled) {
    try {
      const cert = ensureCertificate({
        certFile: config.tls.certFile,
        keyFile: config.tls.keyFile,
        commonName: config.tls.commonName || hostname(),
        dnsNames: ['localhost', hostname(), hostname().toLowerCase()].filter(Boolean),
        ipAddresses: localIPv4Addresses(),
        days: config.tls.certDays,
      })
      const fingerprint = certFingerprint(config.tls.certFile)
      runtime.cert = {
        generated: cert.generated,
        fingerprint: fingerprint.ok ? fingerprint.fingerprint : null,
        subject: fingerprint.ok ? fingerprint.subject : null,
        validTo: fingerprint.ok ? fingerprint.validTo : null,
      }
      if (cert.generated) {
        logger.info('已生成自签证书：' + config.tls.certFile
          + '（SAN: ' + cert.sans.join(', ') + '；有效期至 ' + (cert.expires?.toISOString?.() ?? '?') + '）')
      } else if (cert.expired) {
        logger.warn('现有证书已过期或将过期（到期 ' + (cert.expires?.toISOString?.() ?? '?') + '）：'
          + '它不是本插件生成的，因此不会自动覆盖。请自行更新 ' + config.tls.certFile + ' 与 ' + config.tls.keyFile)
      }
      logger.info('证书指纹 ' + (runtime.cert.fingerprint ?? '(读不出)')
        + '，到期 ' + (runtime.cert.validTo ?? '?') + '')
    } catch (error) {
      const explained = explainCertFailure(error, config)
      runtime.lastError = { code: 'tls/cert-failed', message: explained.message, hint: explained.hint, at: nowIso() }
      logger.error(explained.message + '。' + explained.hint)
      try { disposeTools() } catch { /* noop */ }
      claim.release()
      return fail('tls/cert-failed', explained.message, explained.hint)
    }
  } else {
    logger.warn('⚠ tls.enabled=false：入口走明文 http，口令与内容在网络上是明文。只建议在完全可信的内网这么用')
  }

  // ── 上游会话 cookie 的签名密钥（给 DSH 现签 dsh-auth-*）
  const credentialsFile = config.auth.credentialsFile === '' ? defaultCredentialsPath() : config.auth.credentialsFile
  const secret = new CredentialSecret(credentialsFile, config.auth.credentialsKeyId)
  try {
    secret.get()
    runtime.secret = secret
    logger.info('上游会话签名密钥已就绪：' + credentialsFile)
  } catch (error) {
    const message = '无法读取 DSH 会话签名密钥（' + credentialsFile + '）：' + (error?.message ?? String(error))
    const hint = '代理拿不到合法 cookie，转发了也没用。先在宿主上正常启动一次 dsh web 生成该文件；不会静默降级。'
    runtime.lastError = { code: 'creds/missing', message, hint, at: nowIso() }
    logger.error(message + '。' + hint)
    try { disposeTools() } catch { /* noop */ }
    claim.release()
    return fail('creds/missing', message, hint)
  }

  // ── 代理自有 cookie（可撤销 / 可续期 / 600 落盘）
  const cookies = new CookieStore({
    baseDir: config.baseDir,
    cookiesFile: config.cookiesFile,
    secretFile: config.cookieSecretFile,
    maxAgeDays: config.cookies.maxAgeDays,
    renewWithinDays: config.cookies.renewWithinDays,
    logger,
  })
  try {
    cookies.load()
  } catch (error) {
    const normalizedError = toError(error, 'creds/invalid').error
    runtime.lastError = { ...normalizedError, at: nowIso() }
    logger.error('代理 cookie 存储不可用：' + normalizedError.message)
    try { disposeTools() } catch { /* noop */ }
    claim.release()
    return fail(normalizedError.code, normalizedError.message, normalizedError.hint)
  }
  if (cookies.fatalError) {
    const normalizedError = toError(cookies.fatalError).error
    runtime.lastError = { ...normalizedError, at: nowIso() }
    logger.error(normalizedError.message + '。' + (normalizedError.hint ?? ''))
    try { disposeTools() } catch { /* noop */ }
    claim.release()
    return fail(normalizedError.code, normalizedError.message, normalizedError.hint)
  }
  runtime.cookies = cookies
  logger.info('代理会话 cookie 就绪：' + config.cookies.maxAgeDays + ' 天有效，剩余不足 '
    + config.cookies.renewWithinDays + ' 天自动续期，存储 ' + cookies.file)

  // ── 起服务
  runtime.cookies = cookies
  const ready = (async () => {
    try {
      runtime.stop = await startProxy(runtime)
    } catch (error) {
      const explained = explainListenFailure(error, config)
      runtime.lastError = {
        code: error?.code === 'EADDRINUSE' ? 'net/port-in-use' : 'net/listen-failed',
        message: explained.message,
        hint: explained.hint,
        at: nowIso(),
        holder: explained.holder ?? null,
      }
      logger.error(explained.message + '。' + explained.hint)
      for (const line of explained.lines ?? []) logger.error('  占用者：' + line)
      return
    }

    runtime.started = true
    const accounts = runtime.passwords?.count() ?? 0
    if (accounts === 0) {
      logger.warn('还没有任何 Basic 账号：' + config.auth.htpasswdFile + ' 不存在且配置里没有 auth.users。'
        + '局域网访问会一律 401；放一个 htpasswd（$apr1$ 格式）或在 auth.users 里写内联哈希')
    }
    if (Object.keys(config.auth.users).length > 1) {
      logger.warn('配置了 ' + Object.keys(config.auth.users).length + ' 个账号：本版不支持真多用户隔离，'
        + '它们共享同一个上游 authority 与同一枚代理 cookie（PLAN §3.6）')
    }
    const scheme = config.tls.enabled ? 'https' : 'http'
    const lan = lanAddresses()
    logger.info('已监听 ' + scheme + '://' + config.listen.host + ':' + String(config.listen.port)
      + '（账号 ' + String(accounts) + ' 个；本机入口 ' + scheme + '://localhost:' + String(config.listen.port)
      + (lan.length > 0 ? '，局域网入口 ' + lan.map((ip) => scheme + '://' + ip + ':' + String(config.listen.port)).join(' ') : '')
      + '；健康检查 /__proxy/health ' + (config.health.loopbackOnly ? '仅回环' : '需认证') + '）')
  })()

  ctx.effect(() => () => {
    try { disposeTools() } catch { /* noop */ }
    return ready.then(async () => {
      if (runtime.started && runtime.stop) {
        logger.info('卸载：关闭监听并断开在途连接')
        try { await runtime.stop() } catch { /* 退场不抛 */ }
      }
      claim.release()
    })
  })

  return { ok: true, baseDir: config.baseDir, protocol: config.tls.enabled ? 'https' : 'http', listenPort: config.listen.port }
}

/** 供自检脚本使用（不是 DSH 接口）。 */
export const __testing = {
  readVersion,
  lanAddresses,
}
