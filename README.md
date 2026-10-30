# mira_proxy

DSH 反向代理插件：随插件加载在插件进程内起一个 **TLS + HTTP Basic 认证**的反向代理，
把**只监听回环地址**的 DSH Web GUI（默认 `127.0.0.1:3080`）变成局域网可访问的 HTTPS 入口。

等价于本机那套独立进程实现 `reverse-proxy`（独立进程版本）（同一个设计、同一套 cookie 复刻），
区别只在于落地方式：

| | `reverse-proxy`（独立进程） | `mira_proxy`（本插件） |
|---|---|---|
| 启动 | 计划任务 + 隐藏窗口 + 几个 ps1 | 随 DSH 启动/卸载，无额外进程 |
| 配置 | 自己维护 `config.json` | 插件行 `config:`（本文件下方） |
| 证书 | 从包里复制 / 手工 openssl 重签 | **缺失时自动现签**（SAN 覆盖 localhost / 机器名 / 各网卡 IPv4） |
| 日志 | `logs/proxy.log` | `$DSH_HOME/mira_config/mira_proxy/logs/proxy.log` + DSH 插件日志 |
| 端口 | 8443 | **8543**（默认，避开上面那套） |

```
浏览器  https://192.168.1.212:8543 ──TLS + Basic 认证──▶ http://127.0.0.1:3080
        （或 https://your-host:8543 / https://localhost:8543）        DSH Web GUI（只监听回环）
```

## 为什么必须是 HTTP 反代，而不是端口转发

DSH GUI 拒绝监听局域网地址，并且对自己的 `/api` 有两道关卡：

1. **Host/Origin 信任栅栏**：`Host` 必须是回环或显式 `--trusted-host`；带了 `Origin`
   就必须与 `Host` 同源；`sec-fetch-site: cross-site` 一律拒绝。
2. **浏览器会话**：入口 URL 要带每次启动的 `?token=`，换成一枚**绑定 authority**、
   有效期 30 天的 HMAC 签名 cookie。

本插件对应做两件事（`netsh portproxy` 这类四层转发做不到）：

- 把上游 `Host` 改写成 `127.0.0.1:3080`，把**属于本站点的** `Origin` 一起改写；
  **外来的 `Origin` 原样透传**，跨站请求依旧被 GUI 拒掉；
- 用 `~/.dsh/.credentials.yaml` 里的持久化签名密钥，**每个上游请求现签一枚合法 cookie 注入**
  （复刻 Harness 的 HMAC 构造）。因此**不需要重启正在跑的 GUI，也不用去终端抄启动 token**。

WebSocket（`/api/remote.mux`）认证后走原生 Upgrade 隧道，实测 101 与隧道内双向数据。

## 安装

```powershell
# 在 DSH 会话里让 agent 执行（等价于 UI 里装本地 bundle）：
#   plugin_manager install_bundle  target = <插件源码目录>/mira_proxy
```

插件通过 `cordis.patch.yml` 往 profile 插入一行（id `mira-proxy`，name `mira_proxy`）。
启用/停用直接改这一行：

```yaml
- id: mira-proxy
  name: 'mira_proxy'
  config: {}          # 全默认：https://0.0.0.0:8543 -> http://127.0.0.1:3080
  # 需要改就用新结构（见下表「配置」）：
  #   listen:  { host: 0.0.0.0, port: 8543 }
  #   upstream:{ host: 127.0.0.1, port: 3080 }
```

## 数据目录

```
$DSH_HOME/mira_config/mira_proxy/          （DSH_HOME 缺省 ~/.dsh；本机 = $DSH_HOME）
  data/proxy-cert.pem    自签证书（缺失时自动现签）
  data/proxy-key.pem     私钥（600）
  data/webapps.htpasswd  Basic 口令表（$apr1$ / {SHA}），可选
  cookies.json           代理会话 cookie 记录（600，**不含明文**，只有签发/到期时间）
  cookie-secret.key      cookie 的 HMAC 密钥（600，32 字节；删掉 = 所有 cookie 立刻失效）
  logs/proxy.log         访问日志（超过 log.maxBytes 轮转成 .1）
```

> 0.1.x 用的是 `<.dsh>/plugin-data/mira_proxy/`。本版按约定1 改到 `mira_config` 下，
> **不会自动搬文件**；启动时如果发现新目录不存在而旧目录有数据，会打一条 warn 给出现成的 `mv` 命令。

## 配置

所有字段都有默认值，`config: {}` 即可跑。路径可写相对路径（相对 `baseDir`）。

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | `false` 则完全不监听（也不注册状态工具） |
| `listen.host` | `0.0.0.0` | 功能点4：对局域网开放用 `0.0.0.0`，只想本机用写 `127.0.0.1` |
| `listen.port` | `8543` | 监听端口 |
| `tls.enabled` | `true` | 功能点3：`true`=自签名 https，`false`=明文 http（**必须显式关**，不会自动降级） |
| `tls.certFile` / `tls.keyFile` | `data/proxy-cert.pem` / `data/proxy-key.pem` | 留空/不存在则自动现签 |
| `tls.commonName` | 机器名 | 自签证书 CN |
| `tls.certDays` | `3650` | 自签证书有效期（天） |
| `upstream.host` / `upstream.port` | `127.0.0.1` / `3080` | 上游（DSH Web GUI） |
| `auth.realm` | `DeepSeek Harness` | Basic 认证域 |
| `auth.htpasswdFile` | `data/webapps.htpasswd` | `$apr1$`（`htpasswd -m`）或 `{SHA}` 格式 |
| `auth.users` | `{}` | **内联账号**哈希，如 `{"dsh-user": "$apr1$..."}`；**明文一律拒绝启动** |
| `auth.credentialsFile` | `$DSH_HOME/.credentials.yaml` | 给上游现签 `dsh-auth-*` 的签名密钥来源 |
| `auth.credentialsKeyId` | `client-connection/browser-session` | 密钥记录 id |
| `cookies.maxAgeDays` | `30` | 代理会话 cookie 的有效期（功能点2 的口径） |
| `cookies.renewWithinDays` | `7` | 剩余不足这么多天就自动续期（功能点6） |
| `log.file` | `logs/proxy.log` | 超过 `log.maxBytes` 轮转成 `.1` |
| `log.maxBytes` | `5242880` | 5 MB |
| `health.loopbackOnly` | `true` | `/__proxy/health` 是否只允许回环访问 |

**旧扁平键仍然认**（`listenHost` / `listenPort` / `certFile` / `upstreamPort` / `realm` /
`htpasswdFile` / `users` / `cookieMaxAgeDays` / `logFile` / `logMaxBytes` / `healthLoopbackOnly` …）：
新键优先，用到的旧键会记进日志与 `mira_proxy_status.deprecated`。这不是静默兼容 ——
旧键一定会被点名，请按上表改成新结构。

配置非法（端口越界、`renewWithinDays ≥ maxAgeDays`、明文口令、`users` 值不像哈希）
**直接拒绝启动**并说明改哪个字段，不猜、不降级。

## 代理会话 cookie（功能点 2 / 5 / 6）

两层 cookie 别混：

| cookie | 谁签 | 给谁 | 作用 |
|---|---|---|---|
| `dsh-auth-*` | 代理用 `.credentials.yaml` 的密钥**每请求现签** | 上游 DSH | 让上游认这次请求，用户不用抄启动 `?token=` |
| `mira-proxy-auth` | 代理自己的 HMAC 密钥 | 浏览器 | Basic 过一次之后就凭它，可撤销、可续期、落盘 |

`mira-proxy-auth` 的语义：

- **绑定 authority**：同一个 cookie 只对签它时的 `upstream.host:port` 有效
- **30 天**（`cookies.maxAgeDays`），`HttpOnly` + `SameSite=Lax`，https 模式再加 `Secure`
- **可续期**：剩余不足 `cookies.renewWithinDays` 天时，下一次请求就重签一枚并 `Set-Cookie`
- **可撤销**（三档，都会让旧 cookie 立刻不认）：
  1. **改口令** → 口令表指纹（`PasswordFile.passwordStamp()`）变化 → 旧 cookie 401 并清掉记录 + 打一行 info
  2. `revokeAll()` → `generation+1` 且清空记录（删 `cookie-secret.key` 也能达到同样效果）
  3. 删掉 `cookies.json` 里对应记录
- 代理自己的 cookie **不会转发给上游**（与 `dsh-auth-*` 一起在 `stripSessionCookies` 里剥掉）

## 工具

| 工具 | 说明 |
|---|---|
| `mira_proxy_status` | 只读：是否已监听、协议、入口地址、上游、账号数与用户名（**不含口令**）、证书指纹与到期、cookie 条数与各自剩余天数、启动失败原因（含端口占用者）、被弃用的配置键、最近错误 |

刻意只读：不提供 restart / revoke 之类会改运行状态的动作（免 agent 悄悄把入口关掉）。
要撤销所有 cookie 请改口令，或删 `cookie-secret.key` 后重启。

## 启动失败怎么排查（功能点8）

失败**不会静默降级**（尤其不会悄悄改成 http），而是打一条能照做的日志：

| 现象 | 日志里会有 |
|---|---|
| 端口被占 | `ss -ltnp` / `lsof` 查到的占用者行（含 pid），以及「改 `listen.port`」的具体建议 |
| 查不到占用者 | 明说查不到，并给出手动命令 `ss -ltnp | grep :8543` |
| 端口 <1024 无权限 | 建议改到 1024 以上 |
| `listen.host` 填错 | `EADDRNOTAVAIL` + 建议（`0.0.0.0` / `127.0.0.1` / `ip -4 addr`） |
| 证书现签失败 | 报出 `tls.certFile` / `tls.keyFile` 与目录权限；**不会改用 http** |
| 一个账号都没有 | warn：局域网访问会一律 401（默认安全姿态，不是故障） |

### 账号从哪来

`webapps.htpasswd` 是 Apache `$apr1$` 格式，插件的 `lib/apr1.js` 是纯 Node 实现
（已用 `openssl passwd -apr1` 现算向量交叉验证）：

```bash
# 把现有账号表放到插件的默认位置
cp /path/to/webapps.htpasswd ~/.dsh/mira_config/mira_proxy/data/webapps.htpasswd
```

htpasswd 文件改动**无需重启**：下一次请求就会重读（按 mtime/size 判断）。
也可以完全不落文件，直接在配置里写内联账号：`auth.users: { "dsh-user": "$apr1$xxxx$...." }`。

## 多用户口径（PLAN §3.6）

本版**只支持单用户**：所有账号共享同一个上游 authority 与同一枚代理 cookie。
配置里写多个 `auth.users` **不会**被拒绝启动（那会让你现有的多账号配置直接失效，是功能回退），
而是启动时 warn 并在 `mira_proxy_status.accounts.multiUser` 里标出来：

> 要真多用户（每人独立 authority / 凭据 / cookie），需要给每人一个独立实例；
> 本版不做半套多用户。

## 已知限制

- **单用户**：见上。
- **明文 http 模式**（`tls.enabled: false`）会把口令与内容明文暴露在网络里；只建议在完全可信的内网用，启动时会有 warn。
- **bcrypt**（`$2y$` / `$2b$` / `$2a$`）只识别不校验：纯 Node 不实现 bcrypt，请用 `$apr1$` 或 `{SHA}`。
- 证书是自签的，浏览器首次会告警（与旧版一致）；要正式证书请把 `tls.certFile` / `tls.keyFile` 指过去。
- 改 `lib/` 下的代码必须重启 DSH 才生效（模块实例已加载）；改配置项走热重载。

## 两个实测踩到的坑（重要）

### 1. `DSH_HOME` 的语义在不同地方不一致

`$DSH_HOME` 在不同工具里有两种用法：**数据目录本身**（本机 `DSH_HOME=$DSH_HOME`），
或者**它的父目录**（Windows 那台机器上 `DSH_HOME=C:\Users\<you>`）。

本版这样处理，两种语义都不会落错地方：

- 插件配置/状态一律走 `kit.dshHome()` 的规则：`$DSH_HOME` 非空就用它，否则 `~/.dsh`，
  再拼 `mira_config/mira_proxy`。**本机实测 `$DSH_HOME/mira_config/mira_proxy`。**
- 找 DSH 自己的 `.credentials.yaml` 走 `credentialsDir()`：优先 `$DSH_HOME/.credentials.yaml`，
  再试 `$DSH_HOME/.dsh/.credentials.yaml`，都没有就按 `$DSH_HOME` 本身。用文件存在性当锚点，
  两种语义都能落到真正的 `.dsh` 上。

路径在 `mira_proxy_status.baseDir` 与启动日志里都能直接看到，不用猜。

### 2. 改完 `lib/` 必须重启 DSH

宿主进程按模块名缓存插件代码：**停用再启用、甚至重装 bundle，都只会重新跑
`apply()` 而仍然执行旧模块**（实测：新代码的 `apply` 跑出 v0.1.1 的日志，
但监听中的实例仍报旧路径与 `accounts: 0`）。改代码后请重启 DSH，让插件用新的
模块代号加载。这也是 `plugin_manager` 返回 `restart-required` 的含义。


## 运维手段

- `/__proxy/health`（**仅回环**）：监听地址、上游、账号数、证书 subject/有效期、服务器时间；
- 日志：`$DSH_HOME/mira_config/mira_proxy/logs/proxy.log`（每请求一行：状态码 / 账号 / 来源 IP / 路径 / 耗时）；
- 插件加载日志：协议与监听地址、局域网入口、账号数、证书是否新签、cookie 是否就绪；
- `mira_proxy_status`：会话里直接看（见上「工具」）。

## 安全说明

- 口令只经 TLS（Basic 明文头在 TLS 之内），监听默认 `0.0.0.0`；**建议只对本子网放行**
  （Windows 防火墙入站规则限 `LocalSubnet`）。
- 代理侧注入会话 cookie 意味着：**能过 Basic 认证的人就能用 GUI** —— 口令是第一道门。
  跨站请求仍被 GUI 的 `Origin` / `sec-fetch-site` 检查拦住，插件不会伪造这两个头。
- 自签证书会让浏览器告警；正式用请换成受信任证书（把 `certFile`/`keyFile` 指过去即可）。
- `/__proxy/health` 默认只答回环请求，避免把内部信息（账号数、证书、上游端口）发给整个局域网。

- 上游必须是 HTTP 回环服务；HTTPS 上游（`https://127.0.0.1:...`）未实现。
- 自签证书是首启现签的；SAN 覆盖 `localhost`、机器名与本机各网卡 IPv4，
  换网段/换机器名后删掉 `data/proxy-cert.pem`、`data/proxy-key.pem` 让它重签。
- **未在第二台机器上实测**（只能自测到本机这一层），正式用请用手机或另一台电脑确认一次。

## 自检

```bash
cd mira_proxy && node test/smoke.mjs       # 期望末行：==== ALL PASS（79 项断言）====，退出码 0
node ../tool_shared/tools/check-zero-dep.mjs   # 只许 node: 与相对 import
node ../tool_shared/tools/check-kit.mjs        # lib/kit.mjs 与规范源逐字节一致
```

`test/smoke.mjs` 覆盖 PLAN §1.6 的 F1–F6，并且**真起一个 http 反代**跑端到端：
401 → Basic+Set-Cookie → 仅 cookie 通过 → 改密后 401 且记录被清 → 续期。
它用 `tls.enabled=false` + `127.0.0.1:0`（系统分配端口）+ 同进程假上游，
不需要证书信任、不碰真实配置、不需要真 GUI。

`_test/` 下是历史脚本（不属于插件包，`files` 未包含），仍然有用：

```bash
# 端到端：apr1 交叉验证、自签证书与 TLS 握手、cookie 复刻、反代真实往返（含 WS 101 与停服端口释放）
node _test/e2e.mjs
# 用真实环境（真实 ~/.dsh/.credentials.yaml）跑一遍 apply()，再立刻卸载
node _test/apply-live.mjs
# 对真实 DSH GUI 定「会话是否被接受」的判定标准：合法会话 -> 404，无效会话 -> 401
node _test/upstream-cookie.mjs
```

## 文件

```
lib/index.js          入口：配置归一 → 证书 → 密钥 → cookie 存储 → 监听；单实例；卸载清理
lib/config.js         配置归一（新旧键）、路径解析、校验（非法即拒绝启动）
lib/cookie-store.js   代理会话 cookie：HMAC 签发/校验/续期/撤销，600 落盘
lib/proxy.js          反代本体：TLS/明文开关、Basic + cookie 认证、Host/Origin 改写、cookie 注入、WS 直通
lib/credentials.js    .credentials.yaml 密钥读取、dsh-auth-* 现签、口令表（含改密指纹 passwordStamp）
lib/diagnostics.js    端口占用者查询、证书指纹、监听/证书失败的可操作说明
lib/cert.js           自签证书生成（纯 Node，不依赖 openssl）
lib/logger.js         文件日志（带轮转）+ 转发到 DSH 插件日志
lib/apr1.js           $apr1$ 与 htpasswd 解析（纯 Node）
lib/kit.mjs           共享小工具（与 tool_shared/kit/kit.mjs 逐字节一致）
lib/tools.js          mira_proxy_status（只读）
cordis.patch.yml      bundle 补丁：插入 id=mira-proxy 的插件行
test/smoke.mjs        自检（79 项断言，含真起反代的端到端）
```
