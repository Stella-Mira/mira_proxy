/**
 * 代理日志：写轮转文件，同时转发到 DSH 插件 logger（宿主控制台/日志）。
 *
 * 之所以不用 `ctx.logger` 了事：反代是每请求都要记一行的东西，写文件便于事后排查
 * （谁在什么时候拿哪个账号访问了什么），而宿主 logger 负责让插件加载信息出现在
 * DSH 自己的日志里。任何写失败都不允许影响请求处理。
 */

import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readSync, renameSync, statSync } from 'node:fs'
import { dirname } from 'node:path'

export class Logger {
  /**
   * @param {string} file 日志文件路径
   * @param {number} maxBytes 超过该大小就轮转成 `<file>.1`
   * @param {{info?: Function, warn?: Function, error?: Function}|null} host DSH 插件 logger
   */
  constructor(file, maxBytes, host = null) {
    this.file = file
    this.maxBytes = maxBytes
    this.host = host
    this.failed = false
    try {
      mkdirSync(dirname(file), { recursive: true })
    } catch {
      /* 目录建不出来时下面的 append 会失败并静默降级 */
    }
  }

  /** 只写文件、不打扰宿主 logger（每请求都会用到）。 */
  write(line) {
    const text = `${new Date().toISOString()} ${line}\n`
    try {
      if (existsSync(this.file) && statSync(this.file).size + text.length > this.maxBytes) {
        renameSync(this.file, `${this.file}.1`)
      }
      appendFileSync(this.file, text)
    } catch {
      this.failed = true // 日志永远不能打断请求
    }
  }

  info(line) {
    this.write(line)
    try {
      this.host?.info?.(`[mira_proxy] ${line}`)
    } catch {
      /* 宿主 logger 不可用无所谓 */
    }
  }

  warn(line) {
    this.write(`WARN ${line}`)
    try {
      this.host?.warn?.(`[mira_proxy] ${line}`)
    } catch {
      /* 同上 */
    }
  }

  error(line) {
    this.write(`ERROR ${line}`)
    try {
      this.host?.error?.(`[mira_proxy] ${line}`)
    } catch {
      /* 同上 */
    }
  }

  /** 最近几十行，供健康检查/状态排查使用。 */
  tail(lines = 20) {
    try {
      const bytes = statSync(this.file).size
      const read = Math.min(bytes, 64 * 1024)
      const buffer = Buffer.alloc(read)
      const fd = openSync(this.file, 'r')
      try {
        readSync(fd, buffer, 0, read, bytes - read)
      } finally {
        closeSync(fd)
      }
      return buffer.toString('utf8').split(/\r?\n/u).filter((l) => l !== '').slice(-lines)
    } catch {
      return []
    }
  }
}
