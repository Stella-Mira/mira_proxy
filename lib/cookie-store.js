/**
 * mira_proxy / cookie-store.js —— 代理自己的「浏览器会话」cookie
 *
 * 为什么要它：任务书功能点2 要求「用户不需要 token，换成一枚绑定 authority、有效期 30 天的
 * HMAC 签名 cookie」。反代给上游现签 `dsh-auth-*` 解决的是「不用抄启动 token」；这一层解决的是
 * 「用户自己的会话」：Basic 认证成功后发一枚代理自有的 cookie，之后凭 cookie 就够，
 * 并且它**可撤销、可续期、能落盘**（功能点5/6）。
 *
 * 落盘（均在 `$DSH_HOME/mira_config/mira_proxy/`，600 权限）：
 *   cookie-secret.key   32 字节 HMAC 密钥（首次生成；删掉 = 所有 cookie 立刻失效）
 *   cookies.json        { schemaVersion, generation, records: { "<user>@<authority>": {...} } }
 *
 * 撤销语义（三档，都是「让旧 cookie 立刻不认」）：
 *   1. 改口令 → passwordStamp 变 → 校验失败（功能点6「改密即全失效」）
 *   2. revokeAll() → generation+1 且清空 records → 旧 cookie 因 generation 不符失效
 *   3. revoke(user) / 删记录 → 校验时查不到记录就失效
 *
 * 续期：剩余不足 `renewWithinDays` 天时重新签发一枚，并更新 expiresAt（功能点6「可滚续」）。
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import {
  MiraError, ensureDir, fileMode, nowIso, readJsonStrict, toError, writeJsonSecure,
} from './kit.mjs'
import { b64url, unb64url } from './credentials.js'

export const COOKIE_SCHEMA = 1
/** 代理自有 cookie 名。刻意不用 `dsh-auth-` 前缀，避免和 DSH 自己的会话 cookie 混。 */
export const COOKIE_NAME = 'mira-proxy-auth'
const PAYLOAD_VERSION = 1
const DAY_MS = 24 * 60 * 60 * 1000

export function parseCookieHeader(header) {
  const out = {}
  if (typeof header !== 'string' || header === '') return out
  for (const part of header.split(';')) {
    const trimmed = part.trim()
    if (trimmed === '') continue
    const at = trimmed.indexOf('=')
    if (at <= 0) continue
    out[trimmed.slice(0, at).trim()] = trimmed.slice(at + 1).trim()
  }
  return out
}

/** `Set-Cookie` 头：HttpOnly + SameSite=Lax；HTTPS 时加 Secure。 */
export function setCookieHeader(value, { maxAgeSeconds, secure }) {
  const parts = [
    COOKIE_NAME + '=' + value,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + String(Math.max(0, Math.floor(maxAgeSeconds))),
  ]
  if (secure) parts.push('Secure')
  return parts.join('; ')
}

export function clearCookieHeader({ secure }) {
  return setCookieHeader('', { maxAgeSeconds: 0, secure })
}

export class CookieStore {
  /**
   * @param {object} options
   * @param {string} options.baseDir
   * @param {number} [options.maxAgeDays]
   * @param {number} [options.renewWithinDays]
   * @param {object} [options.logger]
   * @param {()=>number} [options.now]
   */
  constructor({ baseDir, cookiesFile, secretFile, maxAgeDays = 30, renewWithinDays = 7, logger = null, now = () => Date.now() }) {
    this.baseDir = baseDir
    this.file = cookiesFile ?? join(baseDir, 'cookies.json')
    this.secretFile = secretFile ?? join(baseDir, 'cookie-secret.key')
    this.maxAgeDays = Math.max(1, Number(maxAgeDays) || 30)
    this.renewWithinDays = Math.max(0, Number(renewWithinDays) || 0)
    this.logger = logger
    this.now = now
    this.secret = null
    this.generation = 1
    this.records = new Map()
    this.fatalError = null
    this.lastError = null
  }

  load() {
    ensureDir(this.baseDir)
    this.secret = this.#loadSecret()

    const read = readJsonStrict(this.file)
    if (!read.ok) {
      if (read.reason === 'missing') return this
      this.fatalError = new MiraError('config/corrupt',
        'cookies.json 无法解析（' + read.reason + '）：' + this.file,
        '备份后删掉它（会让所有已发出的代理 cookie 失效，用户重输一次 Basic 口令即可）；不会静默重建')
      this.logger?.warn?.('[mira_proxy] ' + this.fatalError.message)
      return this
    }
    if (read.value.schemaVersion !== COOKIE_SCHEMA) {
      this.fatalError = new MiraError('config/schema',
        'cookies.json 的 schemaVersion 是 ' + JSON.stringify(read.value.schemaVersion) + '，本代码要求 ' + COOKIE_SCHEMA,
        '删掉该文件即可重建（代价是已发出的 cookie 全部失效）')
      this.logger?.warn?.('[mira_proxy] ' + this.fatalError.message)
      return this
    }
    this.generation = Number(read.value.generation) || 1
    for (const [key, value] of Object.entries(read.value.records ?? {})) {
      if (value && typeof value === 'object') this.records.set(key, value)
    }
    return this
  }

  #loadSecret() {
    if (existsSync(this.secretFile)) {
      const text = readFileSync(this.secretFile, 'utf8').trim()
      const secret = unb64url(text)
      if (secret.byteLength !== 32) {
        throw new MiraError('creds/invalid',
          'cookie-secret.key 不是 32 字节：' + this.secretFile,
          '这个文件被改坏了。删掉它会让所有代理 cookie 失效（用户重输 Basic 口令即可），然后重启插件')
      }
      return secret
    }
    const secret = randomBytes(32)
    ensureDir(dirname(this.secretFile))
    writeFileSync(this.secretFile, b64url(secret) + '\n', 'utf8')
    try { chmodSync(this.secretFile, 0o600) } catch { /* 平台不支持交给 umask */ }
    this.logger?.info?.('[mira_proxy] 已生成 cookie 签名密钥：' + this.secretFile + '（600）')
    return secret
  }

  get ready() {
    return this.secret !== null && this.fatalError === null
  }

  save() {
    if (this.fatalError) return false
    return writeJsonSecure(this.file, {
      schemaVersion: COOKIE_SCHEMA,
      generation: this.generation,
      updatedAt: nowIso(this.now()),
      records: Object.fromEntries([...this.records.entries()]),
    })
  }

  #sign(body) {
    return createHmac('sha256', this.secret).update(body).digest()
  }

  #recordKey(user, authority) {
    return user + '@' + authority
  }

  /**
   * 签发一枚 cookie（并落盘记录）。
   * @returns {{value:string, expiresAt:number, record:object}}
   */
  issue(user, authority, passwordStamp) {
    if (!this.ready) throw new MiraError('creds/missing', 'cookie 签名密钥不可用', '检查 ' + this.secretFile + ' 与 cookies.json')
    const issuedAt = this.now()
    const expiresAt = issuedAt + this.maxAgeDays * DAY_MS
    const payload = {
      v: PAYLOAD_VERSION,
      gen: this.generation,
      authority,
      user,
      iat: issuedAt,
      exp: expiresAt,
      stamp: String(passwordStamp ?? ''),
    }
    const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
    const value = 'v1.' + body + '.' + b64url(this.#sign(body))
    const record = { value, user, authority, issuedAt, expiresAt, stamp: payload.stamp, updatedAt: nowIso(issuedAt) }
    this.records.set(this.#recordKey(user, authority), record)
    this.save()
    return { value, expiresAt, record }
  }

  /**
   * 校验一枚 cookie。
   * @returns {{ok:true, user:string, record:object, needsRenew:boolean} | {ok:false, reason:string}}
   *   reason ∈ invalid | expired | revoked | stamp | generation | unknown
   */
  verify(value, { authority, passwordStamp }) {
    if (typeof value !== 'string' || value === '') return { ok: false, reason: 'invalid' }
    const parts = value.split('.')
    if (parts.length !== 3 || parts[0] !== 'v1') return { ok: false, reason: 'invalid' }
    const [, body, signature] = parts
    let expected
    try {
      expected = this.#sign(body)
    } catch {
      return { ok: false, reason: 'invalid' }
    }
    let actual
    try {
      actual = unb64url(signature)
    } catch {
      return { ok: false, reason: 'invalid' }
    }
    if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return { ok: false, reason: 'invalid' }

    let payload
    try {
      payload = JSON.parse(unb64url(body).toString('utf8'))
    } catch {
      return { ok: false, reason: 'invalid' }
    }
    if (!payload || payload.authority !== authority) return { ok: false, reason: 'invalid' }
    if (Number(payload.exp) <= this.now()) return { ok: false, reason: 'expired', user: payload.user }
    if (Number(payload.gen) !== this.generation) return { ok: false, reason: 'revoked', user: payload.user }
    const record = this.records.get(this.#recordKey(payload.user, authority))
    if (!record || record.value !== value) return { ok: false, reason: 'revoked', user: payload.user }
    if (String(payload.stamp) !== String(passwordStamp ?? '') || String(record.stamp) !== String(passwordStamp ?? '')) {
      return { ok: false, reason: 'stamp', user: payload.user }
    }
    const needsRenew = record.expiresAt - this.now() < this.renewWithinDays * DAY_MS
    return { ok: true, user: payload.user, record, needsRenew }
  }

  /** 续期：剩余不足 renewWithinDays 天时重签。返回 null 表示不用续。 */
  renewIfNeeded(record, passwordStamp) {
    if (!record) return null
    if (record.expiresAt - this.now() >= this.renewWithinDays * DAY_MS) return null
    // 并发续期：两个请求可能拿着**同一枚**旧 cookie 同时进来，都判定「该续」。
    // 若直接各签一枚，后一枚会覆盖 records 里前一枚，前一个响应刚发出去的 cookie
    // 立刻变成 revoked（浏览器被弹回 401）。所以先看存储里是不是已经有别的请求
    // 刚续过的、仍然新鲜的记录：有就把它原样回给本方，两边拿到同一枚。
    const current = this.records.get(this.#recordKey(record.user, record.authority))
    if (current && current.value !== record.value
      && current.expiresAt - this.now() >= this.renewWithinDays * DAY_MS) {
      return { value: current.value, expiresAt: current.expiresAt, record: current }
    }
    const issued = this.issue(record.user, record.authority, passwordStamp)
    this.logger?.info?.('[mira_proxy] 已续期 cookie：' + record.user + '@' + record.authority
      + '（新到期 ' + new Date(issued.expiresAt).toISOString() + '）')
    return issued
  }

  /** 撤销某个用户（或某个用户+authority）的记录。 */
  revoke(user, authority) {
    let removed = 0
    for (const [key, record] of [...this.records.entries()]) {
      if (record.user !== user) continue
      if (authority !== undefined && record.authority !== authority) continue
      this.records.delete(key)
      removed++
    }
    if (removed > 0) this.save()
    return removed
  }

  /** 全撤销：generation+1 并清空记录，旧 cookie 立刻不认（改密/换设备时用）。 */
  revokeAll(reason = 'manual') {
    const count = this.records.size
    this.records.clear()
    this.generation += 1
    this.save()
    this.logger?.info?.('[mira_proxy] 已撤销全部代理 cookie（' + reason + '）：' + count + ' 条')
    return count
  }

  status() {
    const now = this.now()
    return {
      ready: this.ready,
      file: this.file,
      secretFile: this.secretFile,
      generation: this.generation,
      count: this.records.size,
      maxAgeDays: this.maxAgeDays,
      renewWithinDays: this.renewWithinDays,
      records: [...this.records.values()].map((r) => ({
        user: r.user,
        authority: r.authority,
        issuedAt: new Date(r.issuedAt).toISOString(),
        expiresAt: new Date(r.expiresAt).toISOString(),
        expiresInDays: Math.max(0, Math.round((r.expiresAt - now) / DAY_MS)),
        // 不返回 cookie 值本身（凭据性质）
      })),
      fatalError: this.fatalError ? toError(this.fatalError).error : null,
      secretMode: fileMode(this.secretFile),
      fileMode: fileMode(this.file),
    }
  }
}
