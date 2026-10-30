/**
 * 自签 TLS 证书生成：无需 openssl / mkcert，只依赖 node:crypto。
 *
 * 参考实现（另有一套独立进程版本）是从包里复制证书再用 openssl 重签；
 * 插件里不想让用户去装 openssl，所以自带一个最小 DER/X.509 编码器：
 * RSA-2048 + SHA-256，SAN 覆盖 localhost / 机器名 / 本机各网卡 IPv4。
 *
 * 只生成一次的产物落在 `data/` 下；如果用户自己提供 cert/key，则完全不进这里。
 */

import { generateKeyPairSync, randomBytes, sign as cryptoSign, X509Certificate } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { networkInterfaces } from 'node:os'
import { dirname } from 'node:path'

/* ------------------------------------------------------------------ DER ---- */

/** DER 长度字段。 */
function derLength(length) {
  if (length < 0x80) return Buffer.from([length])
  const bytes = []
  let rest = length
  while (rest > 0) {
    bytes.unshift(rest & 0xff)
    rest >>>= 8
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

/** 一个 DER TLV：tag + 长度 + 内容。 */
export function der(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content)
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body])
}

export const derSequence = (...parts) => der(0x30, Buffer.concat(parts))
export const derSet = (...parts) => der(0x31, Buffer.concat(parts))

/** INTEGER：正数最高位为 1 时补一个 0x00，保证被解释为无符号正数。 */
export function derInteger(value) {
  let hex = typeof value === 'bigint' ? value.toString(16) : Buffer.from(value).toString('hex')
  if (hex.length % 2 === 1) hex = `0${hex}`
  let bytes = Buffer.from(hex, 'hex')
  while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1)
  if (bytes.length === 0) bytes = Buffer.from([0])
  if ((bytes[0] & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0x00]), bytes])
  return der(0x02, bytes)
}

export function derOid(dotted) {
  const parts = String(dotted).split('.').map((p) => Number(p))
  const bytes = [40 * parts[0] + parts[1]]
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f]
    let rest = Math.floor(part / 128)
    while (rest > 0) {
      stack.unshift((rest & 0x7f) | 0x80)
      rest = Math.floor(rest / 128)
    }
    bytes.push(...stack)
  }
  return der(0x06, Buffer.from(bytes))
}

export function derNull() {
  return der(0x05, Buffer.alloc(0))
}

export function derUtf8(text) {
  return der(0x0c, Buffer.from(String(text), 'utf8'))
}

export function derPrintable(text) {
  return der(0x13, Buffer.from(String(text), 'ascii'))
}

export function derOctetString(buffer) {
  return der(0x04, buffer)
}

/** BIT STRING；unusedBits 为 0 时用于包住公钥/签名位串。 */
export function derBitString(buffer, unusedBits = 0) {
  return der(0x03, Buffer.concat([Buffer.from([unusedBits]), Buffer.from(buffer)]))
}

export function derBoolean(value) {
  return der(0x01, Buffer.from([value ? 0xff : 0x00]))
}

/** UTCTime（YYMMDDHHMMSSZ），证书有效期用。 */
export function derUtcTime(date) {
  const pad = (n) => String(n).padStart(2, '0')
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z'
  return der(0x17, Buffer.from(text, 'ascii'))
}

/** RDNSequence：每项一个 SET(SEQUENCE(OID, value))。 */
function derName(pairs) {
  return derSequence(
    ...pairs.map(([oid, value, kind]) =>
      derSet(derSequence(derOid(oid), kind === 'printable' ? derPrintable(value) : derUtf8(value))),
    ),
  )
}

/** 解析 JWK 里的 base64url 定长字段（n / e）为无符号大整数。 */
function jwkUnsigned(jwk, field) {
  const raw = Buffer.from(jwk[field], 'base64url')
  const bytes = Buffer.from(raw)
  return bytes.length === 0 ? Buffer.from([0]) : bytes
}

/* ------------------------------------------------------------- certificate ---- */

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  commonName: '2.5.4.3',
  organizationName: '2.5.4.10',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
}

/** 本机各网卡的 IPv4 地址（含 127.0.0.1）。 */
export function localIPv4Addresses() {
  const found = new Set(['127.0.0.1'])
  try {
    for (const list of Object.values(networkInterfaces())) {
      for (const item of list ?? []) {
        if (item.family === 'IPv4' && item.internal === false) found.add(item.address)
      }
    }
  } catch {
    /* 取不到就只用回环 */
  }
  return [...found]
}

function ipv4ToBuffer(address) {
  return Buffer.from(address.split('.').map((part) => Number(part) & 0xff))
}

/**
 * 生成自签 RSA-2048 证书。
 *
 * @param {{commonName?: string, dnsNames?: string[], ipAddresses?: string[], days?: number, organization?: string}} options
 * @returns {{cert: string, key: string, commonName: string, sans: string[], expires: Date}}
 */
export function createSelfSignedCertificate(options = {}) {
  const commonName = options.commonName || 'dsh-reverse-proxy'
  const organization = options.organization || 'DSH mira_proxy'
  const days = options.days ?? 3650
  const dnsNames = [...new Set((options.dnsNames ?? ['localhost']).filter(Boolean))]
  const ipAddresses = [...new Set((options.ipAddresses ?? localIPv4Addresses()).filter(Boolean))]

  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = publicKey.export({ format: 'jwk' })
  const n = jwkUnsigned(jwk, 'n')
  const e = jwkUnsigned(jwk, 'e')

  // SubjectPublicKeyInfo = SEQUENCE(算法标识, BIT STRING(RSAPublicKey))
  const algorithm = derSequence(derOid(OID.rsaEncryption), derNull())
  const rsaPublicKey = derSequence(derInteger(n), derInteger(e))
  const subjectPublicKeyInfo = derSequence(algorithm, derBitString(rsaPublicKey))

  const name = derName([
    [OID.organizationName, organization],
    [OID.commonName, commonName],
  ])

  const notBefore = new Date(Date.now() - 5 * 60 * 1000)
  const notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000)

  // SAN：GeneralName dNSName=[2] IA5String、iPAddress=[7] OCTET STRING
  const generalNames = [
    ...dnsNames.map((dns) => der(0x82, Buffer.from(dns, 'ascii'))),
    ...ipAddresses.map((ip) => der(0x87, ipv4ToBuffer(ip))),
  ]
  const extensions = derSequence(
    // basicConstraints: critical, CA:FALSE（自签但不当 CA）
    derSequence(derOid(OID.basicConstraints), derBoolean(true), derOctetString(derSequence())),
    // keyUsage: critical, digitalSignature + keyEncipherment
    derSequence(
      derOid(OID.keyUsage),
      derBoolean(true),
      derOctetString(derBitString(Buffer.from([0xa0]), 3)),
    ),
    // extKeyUsage: serverAuth
    derSequence(derOid(OID.extKeyUsage), derOctetString(derSequence(derOid(OID.serverAuth)))),
    // subjectAltName: 非 critical（浏览器/客户端都读）
    derSequence(derOid(OID.subjectAltName), derOctetString(derSequence(...generalNames))),
  )

  // 签名算法标识：必须声明 sha256WithRSA（rsaEncryption 是公钥 OID，
  // 写进 signatureAlgorithm 会让 OpenSSL 3 拒绝加载：ca md too weak）。
  const signatureAlgorithm = derSequence(derOid(OID.sha256WithRsa), derNull())

  const tbsCertificate = derSequence(
    der(0xa0, derInteger(2n)), // [0] EXPLICIT version v3
    derInteger(Buffer.concat([Buffer.from([0x40]), randomBytes(8)])), // 正数随机序列号
    signatureAlgorithm, // signature
    name, // issuer（自签：与 subject 相同）
    derSequence(derUtcTime(notBefore), derUtcTime(notAfter)),
    name, // subject
    subjectPublicKeyInfo,
    der(0xa3, extensions), // [3] EXPLICIT extensions
  )

  const signature = cryptoSign('sha256', tbsCertificate, privateKey)
  const certificate = derSequence(tbsCertificate, signatureAlgorithm, derBitString(signature))

  const toPem = (label, buffer) =>
    `-----BEGIN ${label}-----\n${buffer.toString('base64').replace(/(.{64})/gu, '$1\n').replace(/\n$/u, '')}\n-----END ${label}-----\n`

  return {
    cert: toPem('CERTIFICATE', certificate),
    key: privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
    commonName,
    sans: [...dnsNames, ...ipAddresses],
    expires: notAfter,
  }
}

/**
 * 检查现成的证书文件。
 *
 * 只看「还在不在」是不够的：证书到期后 https.createServer 照样能起来，浏览器却一律
 * 拒连，而且代码再也不会重签 —— 用户唯一的出路是手动删文件。所以这里读 validTo，
 * 快到期就重签（**只重签我们自己生成的那种**：subject 里带 `O=DSH mira_proxy`）。
 * 用户自己提供的证书一律不覆盖，只把 expired 报给调用方去 warn。
 */
function inspectExistingCert(certFile) {
  try {
    const cert = new X509Certificate(readFileSync(certFile))
    const validTo = new Date(cert.validTo).getTime()
    return { readable: true, validTo, ours: /O=DSH mira_proxy/u.test(cert.subject) }
  } catch {
    // 解析不了的文件可能是用户自己签的：不碰它（真正的握手错误会在启动时暴露）
    return { readable: false, validTo: Number.NaN, ours: false }
  }
}

const CERT_RENEW_MARGIN_MS = 7 * 24 * 60 * 60 * 1000

/**
 * 确保 cert/key 存在：缺失（或我们自签的已过期/将过期）就生成并落盘。
 *
 * @returns {{certFile: string, keyFile: string, generated: boolean, sans: string[], expires?: Date, expired?: boolean}}
 */
export function ensureCertificate({ certFile, keyFile, commonName, dnsNames, ipAddresses, days }) {
  if (existsSync(certFile) && existsSync(keyFile)) {
    const existing = inspectExistingCert(certFile)
    const expires = Number.isFinite(existing.validTo) ? new Date(existing.validTo) : undefined
    const nearExpiry = Number.isFinite(existing.validTo) && existing.validTo <= Date.now() + CERT_RENEW_MARGIN_MS
    if (!nearExpiry) return { certFile, keyFile, generated: false, sans: [], expires }
    if (!existing.ours) {
      // 用户自己的证书：不覆盖，交给调用方提示「该换了」
      return { certFile, keyFile, generated: false, sans: [], expires, expired: true }
    }
    // 我们自签的证书快到期 → 重新生成一对（cert 与 key 必须一起换，否则不匹配）
  }
  const created = createSelfSignedCertificate({ commonName, dnsNames, ipAddresses, days })
  mkdirSync(dirname(certFile), { recursive: true })
  mkdirSync(dirname(keyFile), { recursive: true })
  writeFileSync(certFile, created.cert, { encoding: 'utf8', mode: 0o600 })
  writeFileSync(keyFile, created.key, { encoding: 'utf8', mode: 0o600 })
  return { certFile, keyFile, generated: true, sans: created.sans, expires: created.expires }
}
