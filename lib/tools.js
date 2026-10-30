/**
 * mira_proxy / tools.js —— 只读状态工具（约定5：每个插件一个 status）
 *
 * 为什么代理需要一个工具：反代坏了的表现是「浏览器打不开」或「401」，从会话里根本看不见。
 * 有一个只读入口，就能当场判断是「没起来 / 端口被占 / 没账号 / cookie 被撤销 / 证书过期」。
 *
 * 刻意只读：这里不提供 restart / revoke 之类会改运行状态的动作，
 * 免得 agent 在用户不知情时把局域网入口关掉。要撤销 cookie 请改口令（改密即全失效）。
 */

import { textTool } from './kit.mjs'

const obj = (props = {}, required = []) => ({ type: 'object', properties: props, required })

export function registerTools(ctx, getRuntime) {
  const defs = []

  defs.push(textTool(
    'mira_proxy_status',
    '反向代理的只读状态：是否已监听、协议（https/http）、入口地址、上游地址、'
    + '账号数（**不返回任何口令或 cookie 值**）、TLS 证书指纹与到期时间、'
    + '代理会话 cookie 的条数与各自到期天数、启动失败原因（端口被谁占 / 证书缺失）、'
    + '以及配置里被弃用的旧键。排查「浏览器打不开 / 一直 401」先看这里。',
    obj(),
    async () => getRuntime().status(),
  ))

  const disposers = defs.map((def) => ctx.tools.register(def))
  return () => disposers.forEach((d) => { try { d() } catch { /* noop */ } })
}
