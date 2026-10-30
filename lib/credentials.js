/**
 * DSH 浏览器会话 cookie 的复刻：读取 `~/.dsh/.credentials.yaml` 里的签名密钥，
 * 按 Harness 自己的构造为「某个 authority」现签一枚合法 cookie。
 *
 * 为什么反代必须做这件事：DSH Web GUI 的 /api 有两道关卡——Host/Origin 信任栅栏
 * 之外，还有浏览器会话（入口 URL 带 ?token=，换取一枚绑定 authority 的签名 cookie）。
 * 光转发 TCP/HTTP 拿不到这枚 cookie，用户就得每次去终端抄启动 token。
 * 这里直接搬运实现（对齐 @deepseek-ai/dsh-client-connection 的
 * cookieName / encodeCookie / signature），因此**不需要重启正在跑的 GUI**。
 */

import { createHash, createHmac } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

import { parseHtpasswd, verifyApr1 } from './apr1.js'

export const COOKIE_PREFIX = 'dsh-auth-'
export const COOKIE_PAYLOAD_VERSION = 1
export const DEFAULT_KEY_ID = 'client-connection/browser-session'
export const DEFAULT_MAX_AGE_DAYS = 30

export function b64url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
}

export function unb64url(value) {
  return Buffer.from(String(value).replaceAll('-', '+').replaceAll('_', '/'), 'base64')
}

/** 凭证文件默认位置：优先 `DSH_HOME`，否则 `~/.dsh`。 */
export function defaultCredentialsPath() {
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  return join(home, '.credentials.yaml')
}

/**
 * `.dsh` 这个「数据主目录」本身。
 *
 * 注意：`DSH_HOME` 的取值随部署而变 —— 本机实测是 `C:\Users\<you>`（即 `.dsh` 的
 * **父**目录），而 `mint-cookie.js` 之类的脚本会把它当成 `.dsh` 本身。用
 * `.credentials.yaml` 是否存在来判定，两种语义都能落到真正的 `.dsh` 上；
 * 它是唯一必须存在的输入（没有它插件根本起不来），所以最适合当锚点。
 */
export function credentialsDir() {
  const configured = process.env.DSH_HOME
  if (configured !== undefined && configured !== '') {
    if (existsSync(join(configured, '.credentials.yaml'))) return configured
    if (existsSync(join(configured, '.dsh', '.credentials.yaml'))) return join(configured, '.dsh')
    return configured
  }
  return join(homedir(), '.dsh')
}

/**
 * 从凭证 YAML 里取出某条授权记录的 secret，不引入 YAML 依赖
 * （只认 `keyId:` 这一层缩进块里的 `secret:`）。
 */
export function readSecret(credentialsPath, keyId = DEFAULT_KEY_ID) {
  const text = readFileSync(credentialsPath, 'utf8')
  const lines = text.split(/\r?\n/u)
  let inRecord = false
  let recordIndent = -1
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === `${keyId}:`) {
      inRecord = true
      recordIndent = line.length - line.trimStart().length
      continue
    }
    if (inRecord) {
      const indent = line.length - line.trimStart().length
      if (trimmed !== '' && indent <= recordIndent) break
      const match = /^secret:\s*(\S+)\s*$/u.exec(trimmed)
      if (match) {
        const secret = unb64url(match[1])
        if (secret.byteLength !== 32) throw new Error('browser-session secret is not 32 bytes')
        return secret
      }
    }
  }
  throw new Error(`no ${keyId} secret in ${credentialsPath}`)
}

/** cookie 名与 authority 绑定：`dsh-auth-` + base64url(sha256(authority))。 */
export function cookieName(authority) {
  return COOKIE_PREFIX + b64url(createHash('sha256').update(authority).digest())
}

export function encodeCookie(payload, secret) {
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const signature = createHmac('sha256', secret).update(body).digest()
  return `v1.${body}.${b64url(signature)}`
}

/** 现签一枚 authority 绑定的会话 cookie。 */
export function mintCookie(authority, secret, maxAgeDays = DEFAULT_MAX_AGE_DAYS) {
  const issuedAt = Date.now()
  // 留在服务端 maxAge 上限之内：cookie 生命周期要对得上。
  const expiresAt = issuedAt + Math.floor((Math.max(1, maxAgeDays) - 1) * 24 * 60 * 60 * 1000)
  return {
    name: cookieName(authority),
    value: encodeCookie({ version: COOKIE_PAYLOAD_VERSION, authority, issuedAt, expiresAt }, secret),
  }
}

/**
 * 签名密钥的缓存：文件 mtime/size 变了就重读，所以密钥轮换不必重启插件
 * （旧 cookie 会随之失效，浏览器重输一次 Basic 口令即可）。
 */
export class CredentialSecret {
  constructor(file = defaultCredentialsPath(), keyId = DEFAULT_KEY_ID) {
    this.file = file
    this.keyId = keyId
    this.stamp = undefined
    this.secret = undefined
  }

  get() {
    const stat = statSync(this.file)
    const stamp = `${String(stat.mtimeMs)}:${String(stat.size)}`
    if (stamp !== this.stamp || this.secret === undefined) {
      this.secret = readSecret(this.file, this.keyId)
      this.stamp = stamp
    }
    return this.secret
  }
}

/**
 * htpasswd 口令表：文件改动即生效（下次请求重读），无需重启。
 * 同时支持配置里直接写 `<user>: $apr1$...` 的内联账号（免维护文件）。
 */
export class PasswordFile {
  constructor(file, inlineUsers = {}) {
    this.file = file
    this.inline = new Map(Object.entries(inlineUsers ?? {}))
    this.stamp = undefined
    this.users = new Map()
    this.error = undefined
  }

  reload() {
    let stat
    try {
      stat = statSync(this.file)
    } catch (error) {
      this.users = new Map()
      this.stamp = undefined
      this.error = this.inline.size > 0 ? undefined : error
      return
    }
    const stamp = `${String(stat.mtimeMs)}:${String(stat.size)}`
    if (stamp === this.stamp) return
    try {
      this.users = parseHtpasswd(readFileSync(this.file, 'utf8'))
      this.stamp = stamp
      this.error = undefined
    } catch (error) {
      this.error = error
    }
  }

  /**
   * 口令表指纹：文件内容 + 内联账号的 sha256。
   * 用来实现「改密即让所有代理 cookie 失效」（功能点6）——
   * 换掉 htpasswd 或改 users 里一行，指纹就变，旧 cookie 校验立刻不过。
   */
  passwordStamp() {
    this.reload()
    let fileText = ''
    try {
      fileText = readFileSync(this.file, 'utf8')
    } catch {
      fileText = ''
    }
    const inline = [...this.inline.entries()].sort((a, b) => String(a[0]).localeCompare(String(b[0])))
      .map(([user, hash]) => user + ':' + hash).join('\n')
    return createHash('sha256').update(fileText).update('\u0000').update(inline).digest('hex')
  }

  /** 账号是否已配置（文件或内联）；用于启动时给出「没配账号」的警告。 */
  count() {
    this.reload()
    const names = new Set([...this.inline.keys(), ...this.users.keys()])
    return names.size
  }

  verify(user, password) {
    if (typeof user !== 'string' || typeof password !== 'string') return false
    this.reload()
    const hash = this.users.get(user) ?? this.inline.get(user)
    if (hash === undefined) return false
    if (hash.startsWith('$apr1$')) return verifyApr1(password, hash)
    if (hash.startsWith('{SHA}')) {
      const digest = createHash('sha1').update(password, 'utf8').digest('base64')
      return digest === hash.slice(5)
    }
    if (hash.startsWith('$2y$') || hash.startsWith('$2b$') || hash.startsWith('$2a$')) {
      return false // bcrypt：纯 Node 不做，README 里说明用 apr1
    }
    return false
  }
}
