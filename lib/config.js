/**
 * mira_proxy / config.js —— 配置归一 + 路径解析 + 校验
 *
 * 两套键都认（新结构优先，旧的扁平键映射进去并记进 `deprecated`）：
 *   新：listen{host,port} / tls{enabled,certDays,commonName} / upstream{host,port} /
 *       auth{realm,htpasswdFile,users} / cookies{maxAgeDays,renewWithinDays} / log{maxBytes} / health{loopbackOnly}
 *   旧：listenHost / listenPort / certFile / keyFile / certDays / upstreamHost / upstreamPort /
 *       realm / htpasswdFile / users / cookieMaxAgeDays / logFile / logMaxBytes / healthLoopbackOnly
 *
 * 为什么还认旧键：本仓的 `cordis.patch.yml` 与本机 profile 里仍是扁平写法。直接不认会让
 * 「监听端口/上游端口/SAN」这些关键项静默回落默认值 —— 反代起得来但打不开，比报错难查。
 * 旧键一律进 `deprecated`，由 index.js 打一条 warn 并在 `mira_proxy_status` 里可见。
 *
 * 约定1【定】：数据目录一律 `$DSH_HOME/mira_config/mira_proxy/`（DSH_HOME 缺省 ~/.dsh）。
 * 旧版用 `<.dsh>/plugin-data/mira_proxy`，迁移见 README（插件只提示、不自动搬文件）。
 */

import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

export const CONFIG_SCHEMA = 2

export const DEFAULTS = {
  enabled: true,
  listen: { host: '0.0.0.0', port: 8543 },
  tls: { enabled: true, certDays: 3650, commonName: '', certFile: '', keyFile: '' },
  upstream: { host: '127.0.0.1', port: 3080 },
  auth: {
    realm: 'DeepSeek Harness',
    htpasswdFile: '',
    users: {},
    // 给上游现签 dsh-auth-* 用：DSH 自己的凭证文件与密钥 id（一般不用改）
    credentialsFile: '',
    credentialsKeyId: 'client-connection/browser-session',
  },
  cookies: { maxAgeDays: 30, renewWithinDays: 7 },
  log: { maxBytes: 5 * 1024 * 1024, file: '' },
  health: { loopbackOnly: true },
}

/** 旧扁平键 → 新路径。值只在「新路径没写」时才采用。 */
const LEGACY_MAP = [
  ['listenHost', 'listen.host'],
  ['listenPort', 'listen.port'],
  ['upstreamHost', 'upstream.host'],
  ['upstreamPort', 'upstream.port'],
  ['realm', 'auth.realm'],
  ['htpasswdFile', 'auth.htpasswdFile'],
  ['users', 'auth.users'],
  ['credentialsFile', 'auth.credentialsFile'],
  ['credentialsKeyId', 'auth.credentialsKeyId'],
  ['certDays', 'tls.certDays'],
  ['certCommonName', 'tls.commonName'],
  ['certFile', 'tls.certFile'],
  ['keyFile', 'tls.keyFile'],
  ['cookieMaxAgeDays', 'cookies.maxAgeDays'],
  ['logMaxBytes', 'log.maxBytes'],
  ['logFile', 'log.file'],
  ['healthLoopbackOnly', 'health.loopbackOnly'],
]

export function dshHome() {
  const env = process.env.DSH_HOME
  if (typeof env === 'string' && env.trim() !== '') return env.trim()
  return join(homedir(), '.dsh')
}

/** `$DSH_HOME/mira_config/mira_proxy`。 */
export function proxyBaseDir() {
  return join(dshHome(), 'mira_config', 'mira_proxy')
}

/** 旧版目录（只用来在日志里提示迁移，不自动搬文件）。 */
export function legacyBaseDir() {
  return join(dshHome(), 'plugin-data', 'mira_proxy')
}

function getPath(target, dotted) {
  return dotted.split('.').reduce((node, key) => (node === undefined || node === null ? undefined : node[key]), target)
}

function setPath(target, dotted, value) {
  const keys = dotted.split('.')
  let node = target
  for (const key of keys.slice(0, -1)) {
    if (typeof node[key] !== 'object' || node[key] === null) node[key] = {}
    node = node[key]
  }
  node[keys[keys.length - 1]] = value
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** 深合并（对象逐层，数组与标量整体替换）。 */
function merge(base, patch) {
  const out = Array.isArray(base) ? base.slice() : { ...base }
  for (const [key, value] of Object.entries(patch || {})) {
    if (isPlainObject(value) && isPlainObject(base?.[key])) out[key] = merge(base[key], value)
    else if (value !== undefined) out[key] = value
  }
  return out
}

function bad(code, message, hint) {
  return { ok: false, error: { code, message, hint } }
}

/**
 * @param {object} rawConfig  插件行 config
 * @param {object} [options]  { baseDir }
 * @returns {{ok:true, config:object, deprecated:string[], warnings:string[]} | {ok:false, error:object}}
 */
export function normalizeConfig(rawConfig = {}, options = {}) {
  const raw = isPlainObject(rawConfig) ? rawConfig : {}
  const deprecated = []
  const warnings = []

  // 1. 旧扁平键 → 新路径（新路径已有值时只记 deprecated）
  const migrated = {}
  for (const [legacyKey, newPath] of LEGACY_MAP) {
    if (raw[legacyKey] === undefined) continue
    deprecated.push(legacyKey + ' → ' + newPath)
    if (getPath(raw, newPath) === undefined) setPath(migrated, newPath, raw[legacyKey])
  }

  // 2. 归一
  const merged = merge(merge(structuredClone(DEFAULTS), migrated), raw)
  const baseDir = resolve(options.baseDir ?? (raw.baseDir ? String(raw.baseDir) : proxyBaseDir()))
  if (raw.baseDir !== undefined && raw.baseDir !== '') deprecated.push('baseDir（现在固定为 $DSH_HOME/mira_config/mira_proxy）')

  const num = (value, fallback) => {
    const n = Number(value)
    return Number.isFinite(n) ? n : fallback
  }

  const config = {
    ...merged,
    baseDir,
    enabled: merged.enabled !== false,
    listen: {
      host: String(merged.listen?.host ?? DEFAULTS.listen.host),
      port: num(merged.listen?.port, DEFAULTS.listen.port),
    },
    tls: {
      enabled: merged.tls?.enabled !== false,
      certDays: num(merged.tls?.certDays, DEFAULTS.tls.certDays),
      commonName: String(merged.tls?.commonName ?? ''),
      certFile: String(merged.tls?.certFile ?? ''),
      keyFile: String(merged.tls?.keyFile ?? ''),
    },
    upstream: {
      host: String(merged.upstream?.host ?? DEFAULTS.upstream.host),
      port: num(merged.upstream?.port, DEFAULTS.upstream.port),
    },
    auth: {
      realm: String(merged.auth?.realm ?? DEFAULTS.auth.realm),
      htpasswdFile: String(merged.auth?.htpasswdFile ?? ''),
      users: isPlainObject(merged.auth?.users) ? merged.auth.users : {},
      credentialsFile: String(merged.auth?.credentialsFile ?? ''),
      credentialsKeyId: String(merged.auth?.credentialsKeyId ?? DEFAULTS.auth.credentialsKeyId),
    },
    cookies: {
      maxAgeDays: num(merged.cookies?.maxAgeDays, DEFAULTS.cookies.maxAgeDays),
      renewWithinDays: num(merged.cookies?.renewWithinDays, DEFAULTS.cookies.renewWithinDays),
    },
    log: {
      maxBytes: num(merged.log?.maxBytes, DEFAULTS.log.maxBytes),
      file: String(merged.log?.file ?? ''),
    },
    health: { loopbackOnly: merged.health?.loopbackOnly !== false },
  }

  // 3. 校验（不猜、不静默降级）
  if (!(config.listen.port >= 1 && config.listen.port <= 65535)) {
    return bad('config/invalid', 'listen.port 非法：' + JSON.stringify(config.listen.port), '给 1–65535 之间的整数，例如 8543')
  }
  if (!config.listen.host) {
    return bad('config/invalid', 'listen.host 为空', '想对局域网开放写 0.0.0.0；只想本机用写 127.0.0.1')
  }
  if (!(config.upstream.port >= 1 && config.upstream.port <= 65535)) {
    return bad('config/invalid', 'upstream.port 非法：' + JSON.stringify(config.upstream.port), 'DSH Web GUI 的端口，本机通常是 3080')
  }
  if (!(config.cookies.maxAgeDays >= 1)) {
    return bad('config/invalid', 'cookies.maxAgeDays 必须 ≥ 1', '任务书口径是 30 天')
  }
  if (!(config.cookies.renewWithinDays >= 0 && config.cookies.renewWithinDays < config.cookies.maxAgeDays)) {
    return bad('config/invalid', 'cookies.renewWithinDays 必须 ≥ 0 且小于 cookies.maxAgeDays',
      '例如 maxAgeDays=30、renewWithinDays=7：剩余不足 7 天就自动续期')
  }
  for (const [user, hash] of Object.entries(config.auth.users)) {
    if (typeof hash !== 'string' || hash.trim() === '') {
      return bad('config/invalid', 'auth.users.' + user + ' 不是字符串', '内联账号要写口令哈希，例如 $apr1$...（不要写明文口令）')
    }
    if (!hash.startsWith('$apr1$') && !hash.startsWith('{SHA}') && !hash.startsWith('$2')) {
      return bad('config/invalid', 'auth.users.' + user + ' 看起来不是口令哈希',
        '支持 $apr1$ / {SHA} / $2*（bcrypt 只识别不校验，纯 Node 不实现）；明文口令一律拒绝')
    }
  }

  // 4. 路径解析（相对路径落到 baseDir 下）
  const under = (value, fallback) => {
    const target = value === '' ? fallback : String(value)
    return isAbsolute(target) ? target : join(baseDir, target)
  }
  config.tls.certFile = under(config.tls.certFile, join('data', 'proxy-cert.pem'))
  config.tls.keyFile = under(config.tls.keyFile, join('data', 'proxy-key.pem'))
  config.auth.htpasswdFile = under(config.auth.htpasswdFile, join('data', 'webapps.htpasswd'))
  config.log.file = under(config.log.file, join('logs', 'proxy.log'))
  config.cookiesFile = join(baseDir, 'cookies.json')
  config.cookieSecretFile = join(baseDir, 'cookie-secret.key')

  // 5. 多用户口径（PLAN §3.6：本轮只做单用户）
  const userCount = Object.keys(config.auth.users).length
  if (userCount > 1) {
    warnings.push('配置了 ' + userCount + ' 个内联账号：本版**不支持真多用户**（每人独立 authority / 凭据 / cookie）。'
      + '这些账号共享同一个上游 authority 和同一枚代理会话 cookie；要隔离请给每人一个独立实例。')
  }

  // 6. 旧目录提示（只提示，不搬文件）
  if (!existsSync(baseDir) && existsSync(legacyBaseDir())) {
    warnings.push('新目录还不存在，但旧目录 ' + legacyBaseDir() + ' 有数据。按约定1 请把 data/ 与 logs/ 搬到 '
      + baseDir + '（插件不会自动搬）：mv "' + legacyBaseDir() + '" "' + baseDir + '"')
  }

  return { ok: true, config, deprecated, warnings }
}
