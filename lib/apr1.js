/**
 * Apache APR1（`htpasswd -m`）口令哈希，仅基于 node:crypto 实现。
 *
 * 这是 `htpasswd -m` / `openssl passwd -apr1` 使用的格式，也就是常见的 Apache / VisualSVN 部署上
 * 导出的 `webapps.htpasswd` 的格式；纯 Node 环境没有 crypt(3) 可依赖，
 * 所以在这里自带一份实现，让现有口令文件可以原样复用。
 *
 * 参考：Apache Portable Runtime, crypto/apr_md5.c。
 * 本实现已用 `openssl passwd -apr1` 的向量交叉验证（见 reverse-proxy/tools/apr1-crosscheck.js）。
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const MAGIC = Buffer.from('$apr1$', 'utf8')
const DIGEST_SIZE = 16
const SALT_MAX = 8
const SALT_ALPHABET = ITOA64

function md5(...chunks) {
  const hash = createHash('md5')
  for (const chunk of chunks) hash.update(chunk)
  return hash.digest()
}

/** APR 的 to64：按最低 6 位优先，输出 length 个 base64 字符。 */
function to64(value, length) {
  let out = ''
  let rest = value >>> 0
  let remaining = length
  while (remaining-- > 0) {
    out += ITOA64[rest & 0x3f]
    rest >>>= 6
  }
  return out
}

/** 计算 `$apr1$<salt>$<hash>`；salt 最多取 8 个字符。 */
export function apr1(password, salt) {
  const pw = Buffer.from(String(password), 'utf8')
  const saltBytes = Buffer.from(String(salt).slice(0, SALT_MAX), 'utf8')

  // 摘要 B = md5(pw + salt + pw)，按长度切成 16 字节块追加到运行中的消息后面
  // （消息本身是 pw + "$apr1$" + salt，最后统一哈希一次）。
  const message = [pw, MAGIC, saltBytes]
  let final = md5(pw, saltBytes, pw)

  for (let pl = pw.length; pl > 0; pl -= DIGEST_SIZE) {
    message.push(final.subarray(0, Math.min(DIGEST_SIZE, pl)))
  }
  for (let i = pw.length; i !== 0; i >>= 1) {
    message.push((i & 1) === 1 ? Buffer.from([0]) : pw.subarray(0, 1))
  }

  // 摘要 A 作为下面 1000 轮摘要 C 的种子。
  final = md5(...message)

  for (let i = 0; i < 1000; i += 1) {
    const parts = []
    parts.push((i & 1) === 1 ? pw : final)
    if (i % 3 !== 0) parts.push(saltBytes)
    if (i % 7 !== 0) parts.push(pw)
    parts.push((i & 1) === 1 ? final : pw)
    final = md5(...parts)
  }

  let out = ''
  out += to64((final[0] << 16) | (final[6] << 8) | final[12], 4)
  out += to64((final[1] << 16) | (final[7] << 8) | final[13], 4)
  out += to64((final[2] << 16) | (final[8] << 8) | final[14], 4)
  out += to64((final[3] << 16) | (final[9] << 8) | final[15], 4)
  out += to64((final[4] << 16) | (final[10] << 8) | final[5], 4)
  out += to64(final[11], 2)
  return `$apr1$${saltBytes.toString('utf8')}$${out}`
}

/** 用随机 salt 生成 htpasswd 形式的口令哈希。 */
export function hashPassword(password) {
  const bytes = randomBytes(SALT_MAX)
  let salt = ''
  for (const byte of bytes) salt += SALT_ALPHABET[byte & 0x3f]
  return apr1(password, salt)
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.byteLength !== right.byteLength) return false
  return timingSafeEqual(left, right)
}

/** 校验口令是否匹配已存的 `$apr1$<salt>$<hash>`。 */
export function verifyApr1(password, stored) {
  if (typeof stored !== 'string') return false
  const trimmed = stored.trim()
  const match = /^\$apr1\$([^$]{1,8})\$([./0-9A-Za-z]{22})$/u.exec(trimmed)
  if (match === null) return false
  return timingSafeEqualText(apr1(password, match[1]), trimmed)
}

/** 解析 htpasswd 文本为 `Map<user, hash>`；注释与空行忽略。 */
export function parseHtpasswd(text) {
  const users = new Map()
  for (const rawLine of String(text).split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) continue
    const at = line.indexOf(':')
    if (at <= 0) continue
    users.set(line.slice(0, at), line.slice(at + 1))
  }
  return users
}

export { SALT_ALPHABET }
