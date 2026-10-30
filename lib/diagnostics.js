/**
 * mira_proxy / diagnostics.js —— 启动失败时把「为什么」说清楚（任务书功能点8）
 *
 * 任务书原话：「启动时若端口被占 / 证书缺失，日志要给『谁占着、怎么换端口』，
 * 不要静默降级 http」。
 *
 * 所以这里不做事后猜测：真的去问操作系统谁占着这个端口（`ss` / `lsof`），
 * 问不到就明说「问不到」，并把「怎么换端口」写成可以直接照做的一句话。
 * 任何失败路径都不允许悄悄改用 http —— 那会让人以为自己在用 HTTPS。
 */

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { X509Certificate } from 'node:crypto'

/**
 * 查谁占着某个 TCP 端口。返回 { found, command, lines, hint }。
 * 只用 Node 内置的 child_process：不引入任何包。问不到就 found:false（不猜）。
 */
export function describePortHolder(port, options = {}) {
  const run = options.exec ?? ((cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }))
  const attempts = [
    ['ss', ['-ltnp', 'sport = :' + String(port)]],
    ['lsof', ['-nP', '-iTCP:' + String(port), '-sTCP:LISTEN']],
  ]
  for (const [cmd, args] of attempts) {
    let output
    try {
      output = run(cmd, args)
    } catch {
      continue // 这条命令不存在或没权限：换下一条
    }
    const lines = String(output ?? '').split('\n').map((l) => l.trim()).filter((l) => l !== '')
    const body = lines.slice(1)
    if (body.length === 0) continue
    return {
      found: true,
      command: cmd + ' ' + args.join(' '),
      lines: body.slice(0, 5),
      hint: '端口 ' + port + ' 正被占用（见上）。换端口：在 profile 该插件行的 config 里把 listen.port 改成别的值'
        + '（例如 ' + (Number(port) + 1) + '）；或先停掉占用它的进程再重启 DSH。',
    }
  }
  return {
    found: false,
    command: null,
    lines: [],
    hint: '端口 ' + port + ' 被占用，但查不到占用者（`ss` / `lsof` 不可用或没权限）。'
      + '手动查：ss -ltnp | grep :' + port + '；换端口：config.listen.port 改成别的值。',
  }
}

/** 证书指纹（sha256），启动日志里给出来便于比对。 */
export function certFingerprint(certFile) {
  try {
    const pem = readFileSync(certFile)
    const cert = new X509Certificate(pem)
    const sha = createHash('sha256').update(cert.raw).digest('hex').match(/.{2}/g).join(':').toUpperCase()
    return { ok: true, subject: cert.subject, validTo: cert.validTo, fingerprint: 'SHA256 ' + sha }
  } catch (error) {
    return { ok: false, error: error?.message ?? String(error) }
  }
}

/**
 * 把监听失败翻译成一句能照做的话。
 * @param {Error} error
 * @param {object} config  归一后的配置
 * @param {object} [options] { exec, tlsEnabled }
 */
export function explainListenFailure(error, config, options = {}) {
  const code = error?.code ?? ''
  const host = config?.listen?.host ?? '?'
  const port = config?.listen?.port ?? '?'
  if (code === 'EADDRINUSE') {
    const holder = describePortHolder(port, options)
    return {
      code,
      message: '监听 ' + host + ':' + port + ' 失败：端口已被占用',
      holder,
      hint: holder.hint,
      lines: holder.lines,
    }
  }
  if (code === 'EACCES') {
    return {
      code,
      message: '监听 ' + host + ':' + port + ' 失败：没有权限（1024 以下端口需要 root）',
      holder: null,
      hint: '把 config.listen.port 改成 1024 以上（例如 8543），或给进程相应权限',
      lines: [],
    }
  }
  if (code === 'EADDRNOTAVAIL') {
    return {
      code,
      message: '监听 ' + host + ':' + port + ' 失败：本机没有这个地址',
      holder: null,
      hint: 'listen.host 填错了。对局域网开放用 0.0.0.0，只本机用 127.0.0.1；本机实际网卡地址见 ip -4 addr',
      lines: [],
    }
  }
  return {
    code: code || 'UNKNOWN',
    message: '监听 ' + host + ':' + port + ' 失败：' + (error?.message ?? String(error)),
    holder: null,
    hint: '检查 config.listen.host / listen.port；完整错误见上',
    lines: [],
  }
}

/** 证书缺失/不可用时的说明（不静默降级到 http）。 */
export function explainCertFailure(error, config) {
  return {
    message: 'TLS 证书不可用：' + (error?.message ?? String(error)),
    hint: '插件会在证书缺失时自动现签一张自签证书；现签也失败时请检查目录可写权限与 '
      + config?.tls?.certFile + ' / ' + config?.tls?.keyFile
      + '。不会静默降级成 http —— 那会让你以为自己在用 HTTPS。'
      + '若确实想用 http，请在配置里显式写 tls.enabled: false。',
  }
}
