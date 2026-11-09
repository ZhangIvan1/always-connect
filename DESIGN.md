# AlwaysConnect 详细设计

版本：v0.4（2026-10-30）
目标：Mac VPN 客户端，替代 Cisco Secure Client（AnyConnect），个人自用。
一句话：打开就自动连上，断线绝不漏网，分流规则自己说了算。
本版改动：核心技术栈定为 Rust（Swift 只做 NE 壳与 UI）；分流规则引擎改按业界成熟机制复用（不再自研）；应用规则机制纠正为透明代理（上一版的 NEAppProxyProvider 有误）；交互按 macOS 原生菜单栏应用重做；新增第五节功能取舍判断。

## 一、目标与非目标

### 目标
- 连公司现有 Cisco 网关（当前配置：服务器条目 VPN-A，Group Staff）。
- 打开 app 自动登录：账号密码 Keychain 保存，免手动输入。
- 断线无限自动重连；断线期间故障关闭，流量不回落本地网络。
- VPN 开启时家里局域网（192.168.0.0/16）直通，可开路由器管理页。
- 应用 / 域名 / 网段三级分流规则：哪些走公司 VPN、哪些走直连，用户说了算；实现机制复用业界成熟方案（见第四节），不自研。
- 交互不照搬 AnyConnect：按 macOS 原生菜单栏应用的形态做（见第三节），高级、美观、低开销。

### 非目标（本期不做）
- 企业管理侧：策略下发、集中管理、多用户管理。
- Posture 合规检查、Umbrella DNS 防护、AMP 终端防护联动（Cisco 的 NAC/AMP/Web Security 模块，后续扩展池）。
- 标准协议扩展（WireGuard / OpenVPN / IKEv2），后续再议。
- iOS 版本。

## 二、总体架构

```
┌─────────────────────────────────────────────────────────────┐
│ App 进程（Swift + SwiftUI/AppKit，LSUIElement 菜单栏应用）     │
│  菜单栏面板（第一界面）/ 主窗口（第二入口）/ 首次向导 / 规则编辑 │
│  Keychain 凭据管理 / 规则配置 / 诊断打包                       │
└──────────────┬──────────────────────────────────────────────┘
               │ C ABI（FFI）
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Rust 核心（alwaysconnect-core，可移植，无 Apple 框架依赖）      │
│  规则引擎 / DNS 动态路由 / 重连状态机 / 退避 / libopenconnect 绑定│
│  Linux 上 cargo test 全量验证；macOS 上由 Swift 壳调用          │
└──────────────┬──────────────────────────────────────────────┘
               │ App Groups 共享状态 + XPC（NETunnelProviderManager）
               ▼
┌─────────────────────────────────────────────────────────────┐
│ PacketTunnelProvider（NetworkExtension，系统扩展进程，Swift 壳） │
│  调用 Rust 核心驱动 libopenconnect（AnyConnect SSL VPN 协议）   │
│  认证 / 会话恢复 / 隧道数据面 / 路由安装 / 重连状态机           │
│  DNS 代理（域名规则解析 + 动态路由，Cisco 动态分流机制）         │
└──────────────┬──────────────────────────────────────────────┘
               │ 需要时
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Transparent Proxy Provider（NetworkExtension，应用级规则）     │
│  IVPN / PIA / GlobalProtect 同款透明代理机制：                  │
│  按应用身份逐连接决定走隧道还是直连                            │
└──────────────┬──────────────────────────────────────────────┘
               │ 需要时
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 特权 Helper（LaunchDaemon，管理员授权安装一次）                  │
│  pf 规则兜底：故障关闭第二道防线                                │
└─────────────────────────────────────────────────────────────┘
```

关键设计决策：
- 核心用 Rust，Swift 只做壳。Rust 核心不依赖任何 Apple 框架，因此同一份代码在 Linux 上 cargo test 全量验证，macOS 上由 Swift 壳经 C ABI 调用；NE 生命周期、Keychain、UI 仍是 Swift 的。
- 隧道与重连逻辑放在 PacketTunnelProvider 里，而不是 App 里。Provider 是系统管理的常驻进程，App 退出、界面关闭都不影响隧道与重连；故障关闭也因此天然成立（Provider 活着，路由就一直在）。
- OpenConnect 以 libopenconnect 形式由 Rust 核心绑定，不走命令行子进程。命令行子进程在系统扩展沙箱里受限多，且状态同步难。
- App 只做三件事：给 Provider 递凭据与配置、把 Provider 的状态展示出来、管理分流规则。
- 分流规则分层复用成熟机制（见第四节）：网段规则 = WireGuard AllowedIPs 式 CIDR 路由；域名规则 = Cisco 动态分流 + Cloudflare WARP 分流隧道；应用规则 = 透明代理（IVPN / PIA / GlobalProtect 同款）。

## 三、交互设计（macOS 原生菜单栏应用）

借鉴对象：Cloudflare WARP（菜单栏一键开关、状态一目了然）、WireGuard macOS（菜单栏隧道列表开关）、Tailscale（菜单栏状态与出口选择）、IVPN macOS（菜单栏与设置分离）、TripMode（菜单栏里按应用开关，与我们的规则卡片同构）。不借鉴 AnyConnect 的多 Tile、多弹窗。

- **形态**：LSUIElement 菜单栏应用，无 Dock 图标；状态栏图标 + Popover 是第一界面，主窗口保留为第二入口（Apple HIG 要求菜单栏附加项不能是功能的唯一入口，设置与规则编辑放主窗口）。
- **状态栏内容**：图标为主，不堆文字。图标用颜色 + 形状双重区分（绿实心=已连接、黄三角=等批准/连接中、红空心=已断开且拦截中），不只靠颜色。点击弹出面板：大开关、一句话状态（"已连接 · 公司网络"、"重连中 · 网络已拦截（第 3 次）"、"等你在手机上确认登录"）、当前分流模式、最近一次断线、规则与统计快捷入口。面板内容定高、不滚动，Liquid Glass regular 材质，跟随系统外观与"减透明度"设置。
- **首次向导三步，之后不再打扰**：① 保存凭据（Group Staff 预填、服务器 VPN-A 预填，只输账号密码一次）→ ② 选分流模式（安全模式/分流模式，见第四节）→ ③ 完成并自动连接。以后打开即连，不再问。
- **等批准与断线都不弹模态框**：等批准时只发一条通知 + 菜单栏变黄 + 面板里一句话"去手机上确认登录"；断线时菜单栏变红 + 通知聚合（多次断线合并为一条，不刷屏），不弹窗轰炸。
- **规则编辑用卡片，不用手写配置**：应用规则从本机应用列表里勾选（不用手输 Bundle ID）；域名规则支持通配符；网段规则带格式校验；另附规则模板一键套用（见第五节）。命中冲突时当场红字提示，不让用户配出一套自相矛盾的规则。
- **规则测试器**：输入一个域名或选一个应用，立刻显示它会走哪条路、命中了哪条规则、当前生效与否。分流配错时先查这里，不用猜。
- **泄漏自检**：一键检查当前出口 IP 与 DNS 是否符合预期（VPN 应为公司出口、直连应为本地出口），结果一句话，不贴原始报文。
- **统计是二级页面**：在线时长、流量、路由表、重连记录只放在统计页，不进主路径。
- **资源开销控制**：App 本体不轮询，状态由 Provider 经 XPC 推送；Popover 懒加载，关闭即释放；隧道、规则、重连逻辑全在系统扩展进程，App 退出也不影响；无后台定时器，全部用系统事件驱动（NWPathMonitor、系统通知）；界面用 SwiftUI 轻量视图，不做常驻动画与重型图表；日志限速限量。

## 四、分流规则引擎（复用业界成熟机制）

你说得对，分流是成熟机制，不自研。下面每种规则都对到业界已落地的实现，机制、边界、取舍都按公开资料写。

### 4.1 网段规则：WireGuard AllowedIPs 式 CIDR 路由
- 机制：路由表即策略。WireGuard 的 AllowedIPs 同时是路由决策与访问控制：填 0.0.0.0/0 就是全隧道，填具体网段就是分流——"路由表就是配置"。
- 复用点：我们的网段规则直接映射为 includedRoutes / excludedRoutes（NEIPv4Settings），与 AllowedIPs 同款语义：192.168.0.0/16 直连、公司网段走隧道，写进路由表即生效。
- 边界：这是最底层、最稳定的规则，不受 DNS 与应用变化影响。

### 4.2 域名规则：Cisco 动态分流 + Cloudflare WARP 分流隧道
- 机制：Cisco AnyConnect 4.5+ 的 Dynamic Split Tunneling——按 DNS 域名动态下发分流排除，客户端解析出域名对应的 IPv4/IPv6 地址后动态改路由表与过滤器，让该域名的流量走隧道外；Cloudflare WARP 的 Split Tunnels 同款：Exclude 模式（默认全走网关，列出的 IP/域名除外）与 Include 模式（仅列出的 IP/域名走网关）。
- 复用点：我们的域名规则就是这套机制的客户端本地版——Provider 内 DNS 代理 + 动态路由：规则域名解析时记录结果 IP，动态装路由；按 TTL 刷新；IP 失效删路由。
- 业界已知的边界（照单全收，不回避）：
  - 域名比 IP 慢：需要实时查 IP、改路由表与防火墙，生效有延迟（Cloudflare 原话）。
  - CDN 共用 IP 会误伤：一个 IP 上多个域名时，排除/纳入一个域名可能连带影响同 IP 的其他域名（Cloudflare 原话）。处理：冲突时一律按走 VPN 处理并提示用户。
  - 通配符：Cisco 的动态分流 Values 字段不支持通配符；我们的客户端实现可支持 *.example.com，但要注明这是超出 Cisco 原版的扩展，行为以实测为准。
  - 刷新时机：Cloudflare 是隧道建立时按当时解析结果建规则、每次建隧道时刷新；我们的实现按 TTL 刷新，比它更勤快，代价是路由表 churn 更大，需控制刷新频率。

### 4.3 应用规则：透明代理（IVPN / PIA / GlobalProtect 同款）
- 机制：NETransparentProxyProvider。系统把每个新建的出站 TCP/UDP 连接交给扩展，扩展按源应用身份决定：被排除的应用走物理网卡，其余连接拒绝后按正常路由走（即 VPN 隧道）。IVPN 2026-10-20 刚在 macOS 上线了这套机制（此前 Windows/Linux/Android 早有，macOS 是最后一块拼图），PIA 与 Palo Alto GlobalProtect 在 macOS 上也是同款路线。
- 复用点：我们的应用规则直接用透明代理实现，不再用上一版写错的 NEAppProxyProvider。注意：包隧道的源应用模式（appRules）只对 MDM 纳管设备开放，个人设备不可用，透明代理是个人设备上唯一成熟的应用级分流路径。
- 业界已知的边界（照单全收）：
  - 仅新连接生效：已建立的连接保持原路，直到应用重建连接；改规则会短暂中断被排除应用的连接。
  - 仅 TCP/UDP：系统服务代查的 DNS 仍走 VPN；ping 这类 raw socket 恒走 VPN。
  - 子进程继承：被排除应用拉起的子进程同样被排除，但经 Finder、登录项或 open 命令拉起的不算。
  - 逆向模式在 macOS 上不成熟：IVPN 明确说明"仅选定应用走 VPN、其余直连"的逆向模式在 macOS 上暂不可用（Windows/Linux 有）。影响：我们的分流模式下，应用级"纳入 VPN"规则能否实现需 Phase 0 验证；若不可行，分流模式的应用规则降级为"排除制 + 提示"，不硬上。
  - Safari 排除受限：多数厂商无法把 Safari 排除出隧道（系统限制），PIA 需用特殊的 WebKit 规则且连带影响 Mail 与地图。我们的应用规则对 Safari 做同样提示，不承诺。
- 接线进展：Proxy 已链接 Rust staticlib（Bridge 目录复用 Tunnel 的 RustCore.swift），handleNewFlow 已能按 metaData.sourceAppSigningIdentifier + remoteHostname + TCP 端点主机名做直接放行判定（directEgress，引擎未配置时一律走 VPN）；数据泵（NWConnection 转发）仍是 Phase 2，在此之前直接命中的流也先走 VPN（安全方向，不漏网）。

### 4.4 分离 DNS：Tailscale Split DNS
- 机制：按域名选解析器。Tailscale 的 Split DNS 把特定域名的解析指到特定 DNS 服务器，其余走正常 DNS。
- 复用点：规则域名与公司域名走隧道 DNS（或网关下发 DNS），其余域名走本地 DNS；内网域名误配直连时本地解析不到，只会连不上，不会泄漏（fail-safe 方向）。

### 4.5 默认模式：Cloudflare 的 Exclude / Include
- 安全模式（默认）= Exclude 模式：全走 VPN，列出的除外。好处：没配规则的公司流量不漏网；代价：大流量下载也走 VPN。
- 分流模式 = Include 模式：仅列出的走 VPN，其余直连。好处：不需要 VPN 的流量不挤隧道；代价：没配进 VPN 规则的公司流量会走直连——切到分流模式时 App 强制提醒"需要走 VPN 的应用必须配一条应用规则"。
- 断线期间两档都一样：故障关闭接管，未命中的流量一律拦截（放行表内除外），不按默认模式放行。

### 4.6 优先级与冲突
应用规则 > 域名规则 > 网段规则 > 默认模式；局域网硬规则高于一切（192.168.0.0/16 永远直连，即使被误配进 VPN 规则也以直连为准并告警）。同目标出现在 VPN 与直连两侧 → 按走 VPN 处理并红字提示。

### 4.7 规则热更新
改规则不重连：App 把新规则推给 Provider，Provider 增量更新路由与 DNS 配置，隧道不断。正在进行的连接按旧规则走完，新连接按新规则走（与 IVPN 的"仅新连接生效"一致）。

## 五、功能优化判断（本轮新增：加 / 暂缓 / 不加）

| 功能 | 判断 | 理由 |
|---|---|---|
| 规则模板一键套用（指定应用走 VPN、指定网站直连、局域网直连） | 加 | 规则引擎再成熟，配起来也费事；模板把你的实际场景一次配好，之后只改例外 |
| 断线历史与质量看板（轻量，面板一行 + 统计页） | 加 | 你的核心痛点是频繁断线；看得到断线时间、次数与恢复时长，才分得清是网络问题还是网关问题 |
| 通知聚合（断线重连通知合并） | 加 | 无限重连会产生大量事件，不聚合就是刷屏；断线只提醒一次，恢复再提醒一次 |
| 规则导入导出（JSON） | 加 | 成本极低，换机、备份、回滚都有用 |
| 全局快捷键开关（默认关闭，可自定义） | 加 | 菜单栏应用的标配；默认关闭避免与系统快捷键冲突 |
| 泄漏自检与规则测试器 | 加 | 已在第三节，分流配错时唯一的自查手段 |
| 按端口分流、按时间段分流 | 暂缓 | 规则引擎复杂度上升明显，个人场景收益低；留在扩展池 |
| 流量图表、测速 | 暂缓 | 违背低开销原则；计数器够用，图表以后再说 |
| 多账号 / 多网关快速切换 | 暂缓 | 个人自用单网关，优先级低；Phase 3 再做 |
| 按网络位置自动切默认模式 | 不加 | 静默改路由策略有安全风险；安全模式与分流模式必须由用户显式决定 |
| iOS 伴生 App | 不加 | 超出本期范围；macOS 先跑通再说 |

## 六、模块划分

### 1. UI 层（App）
菜单栏面板、主窗口、首次向导、规则编辑（卡片 + 模板）、规则测试器、泄漏自检、统计页、通知。见第三节。
- App 侧接线已落地：KeychainStore 真实现（generic password，AfterFirstUnlock）、ProfileStore（App Groups 非敏感持久化）、TunnelManager（NETunnelProviderManager 建/存/启/停 + 状态观察 + lastError）、菜单栏面板开关接线与启动自动连接；凭据收集 UI（Settings）仍是 Phase 2。

### 2. 凭据与会话层
- 存储：账号、密码、服务器、Group 只存 macOS Keychain（generic password），不写明文文件、不进日志。Touch ID 仅用于"查看/修改凭据"，不 gate 自动登录（否则自动登录会被打断）。
- 启动自动登录：App 启动 → 读 Keychain → 起 Provider → Provider 用保存的凭据认证，全程无弹窗。
- 会话恢复：断线重连优先用原会话恢复（网关会话保持窗口内免 2FA），这是用户实测确认的行为。
- 等批准态：网关要求重新批准时，Provider 上报 awaiting-approval 状态，App 通知 + 菜单栏变黄并持续等待；网关超时关闭尝试后，Provider 自动再发起一次（会再推一条批准消息），直到连上或用户手动断开。
- 实现：Rust 核 `core/src/session.rs`（SessionDriver + SessionRecord + AuthOutcome + DriverAction），决策逻辑与退避、状态机复用；认证结果到 AuthOutcome 的映射已落地（`core/src/openconnect.rs` 的 map_auth_error：Obtain(-1)→Rejected，为回调拒填约定；其他 Obtain 码与 NoCookie→Transient；ParseUrl/CaFile→Rejected）。
- NeedsApproval 在阻塞等待中的上报仍是缺口：obtain_cookie 在等 push 时是阻塞的，驱动要实时知道"在等批准"，需表单回调在看到无凭据字段的 push 形表单时通知驱动，并用 openconnect_set_cancel_fd 实现批准超时中断——两者都需真实网关的表单形状验证，挂起到有 Mac + 真实网关。
- 会话恢复的边界（2026-10-30 更正：此前“库路径无 Cookie 注入公开函数”的说法是错的，错在信了二手 API 总结；本地 9.12 头文件原文为准）：`openconnect_set_cookie()` 存在（openconnect.h:669，另有 clear_cookie :670），因此新进程走库路径也能用已存 Cookie 恢复（set_cookie 后建连接），SessionRecord 两条路线都能用。进程内存活的 vpninfo 掉线后靠 mainloop 原地重连仍是最快路径；Cookie 被拒或过期则回落完整认证（可能需批准）。驱动不猜 Cookie 过期：有效性只由服务器对重连尝试的响应证明，不用计时器。
- 状态机扩展：原机没有\"认证被拒\"的终态路径和连接中/认证中的手动断开路径，驱动需要，`state_machine` 增加 AuthRejected（认证中 → 已断开）与 ManualDisconnect（连接中/认证中 → 已断开）。

### 3. 隧道层（Provider + libopenconnect）
- 协议：AnyConnect SSL VPN（CSTP over TLS，DTLS 数据面按网关协商）。
- 认证：Group（Staff）+ 用户名 + 密码 + 手机推送确认等待。
- 路由：默认路由走 utun；排除路由 192.168.0.0/16 走物理网卡（NEIPv4Settings.excludedRoutes）。
- DNS：隧道 DNS 按网关下发；规则域名走 Provider 的 DNS 代理；局域网域名解析走本地。
- 睡眠/唤醒、网络切换（Wi-Fi 漫游、网络变化）：NWPathMonitor 触发立即重连尝试，并刷新域名规则的解析结果。

### 4. 重连与故障关闭（核心）
状态机：
```
已断开 → 连接中 → 认证中 → 等批准 → 已连接
已连接 →（掉线）→ 重连中（会话恢复）
重连中 →（会话失效）→ 认证中 → 等批准 → 已连接
重连中 / 等批准 →（用户手动断开）→ 已断开（恢复本地网络）
```

- 退避策略：1s、2s、5s、10s、30s封顶，带抖动，永不放弃；成功后重置。
- 故障关闭第一道（主防线）：掉线后 Provider 不拆除 utun、不撤销路由，数据面停止转发，流量黑洞丢弃。系统路由仍指向隧道，物理网卡收不到外发流量，因此不可能"回落本地"。
- 故障关闭第二道（pf 兜底，需特权 Helper）：pf 锚点规则——物理网卡出方向默认拒绝，仅放行 192.168.0.0/16、DHCP（获取局域网地址必需）与本地回环。Provider 异常退出时规则仍在，不漏网。
- 实现：`core/src/pf.rs` 生成锚点文本（纯文本生成，加载/卸载归 Helper 的 pfctl 调用）。关键约束：网关 IP 必填——没有它 pf 会把重连自身的路也挡住，客户端断线后永远连不回来；所以 Helper 只在隧道起来后（网关 IP 已知）才装规则，装之前没有隧道、没有可漏的流量。另放行 mDNS 与 fe80::/10；pfctl 是最终校验，加载失败必须上报用户、不得静默跳过。
- Helper 已接 pf 生成：`AlwaysConnectHelper generate-pf`（经 C ABI 调 Rust 核）在 stdout 输出锚点文本；CI 在 macOS runner 上实跑并校验输出（含无网关时失败）。pfctl 加载/卸载随 LaunchDaemon 安装来（Phase 2，需 root 与 Mac）。
- 手动断开 vs 意外掉线严格区分：只有手动断开才恢复本地网络、清除 pf 规则；意外掉线一律保持拦截，直到连上或用户手动断开。
- 拦截期间的用户可见状态：菜单栏变红，面板显示"已断开，网络已拦截，正在重连（第 N 次）"，而不是假装在线。

### 5. 诊断层
- 日志：分级（错误/信息/调试），默认信息级；调试级记录协议关键步骤，密码、Cookie、2FA 相关内容一律脱敏。
- 诊断包：日志 + 配置（去敏感）+ 系统与版本信息，一键导出，对标 Cisco DART。

## 七、关键流程

### 启动自动登录
1. 用户打开 App。
2. App 读 Keychain，拿到服务器、Group、账号、密码。
3. App 起 Provider 并递交配置。
4. Provider 认证 → 网关放行（会话保持期内无 2FA，或 手机批准后放行）→ 建隧道、装路由 → 状态"已连接"。

### 断线重连（会话恢复路径）
1. 隧道丢包/保活超时 → Provider 判定掉线，状态"重连中"，路由保持、流量黑洞。
2. 按退避间隔用原会话恢复；成功 → 状态"已连接"，退避重置。
3. 会话已失效 → 转完整认证；网关要求批准 → 状态"等批准"，App 通知用户；批准后建隧道。

### 断线重连（需批准路径）
1. 同上进入"等批准"，App 通知用户。
2. 用户点批准 → 连上；网关超时 → Provider 自动再发起（再推一条批准），循环直到连上或手动断开。
3. 全程 Kill Switch 生效，工作流量不会换 IP 出去。

### 局域网访问（VPN 连通时）
1. 访问 192.168.x.x → 匹配排除路由 → 走物理网卡直连 → 路由器管理页打开。
2. 访问其他地址 → 按规则引擎判定：命中规则按规则走，未命中按默认模式走。

### 手动断开
1. 用户点 Disconnect → Provider 拆隧道、撤路由 → Helper 清除 pf 规则 → 恢复本地网络 → 状态"已断开"。

## 八、数据模型

- Profile：{ 服务器（VPN-A）、Group（Staff）、自动连接开关、默认模式（安全/分流） }。
- Credential：Keychain 条目 { 服务器、账号、密码 }，按服务器+账号区分。
- Rule：{ 类型（应用/域名/网段）、目标（签名身份/域名通配符/网段）、方向（走 VPN/直连）、启用开关 }。
- NetworkPolicy：{ 分流排除网段[]（默认 192.168.0.0/16）、断线放行表[]（默认同左）、pf 兜底开关 }。
- SessionState：{ 状态、网关、隧道 IP、连接开始时间、重连次数、上次断线时间、等批准标志 }。
- Statistics：{ 上行/下行字节、在线时长、历史断线记录 }。

## 九、安全设计

- 密码只进 Keychain，不进偏好文件、日志、诊断包、崩溃报告。
- Provider 与 App 之间只传配置与状态，不回传密码明文到界面进程日志。
- pf 规则最小化：默认拒绝 + 明确放行，不做"允许全部再补洞"。
- 日志与诊断包强制脱敏：密码、会话 Cookie、Authorization 相关字段。
- 代码与素材全部自研自绘，不复制 Cisco 二进制、界面资源与品牌。

## 十、权限、分发与签名

- 必需权限：NetworkExtension（Packet Tunnel + Transparent Proxy），需 Apple Developer Program 会员。
- 特权 Helper：SMAppService / LaunchDaemon，安装时一次管理员授权。
- 分发：Developer ID + 公证，不走 Mac App Store。原因：App Store 对 NetworkExtension + 特权 Helper + GPL 组件的组合限制多，个人自用没必要过审。
- 系统要求：macOS 13+（NetworkExtension 现代 API），Apple Silicon 与 Intel 通用架构。

## 十一、开发排期（估计，非承诺）

- Phase 0 原型验证（1–2 周）：① libopenconnect 在 PacketTunnelProvider 内跑通一次完整连接（手动账号密码 + 手机批准），验证会话恢复与路由安装；② 透明代理与包隧道共存验证（应用规则流量能否按排除制出站、逆向模式能否实现）；③ DNS 代理 + 动态路由验证（域名规则生效、TTL 刷新、CDN 共用 IP 冲突）；④ macOS 下隧道数据面接法二选一：NE 包泵（packetFlow ↔ libopenconnect 对接）或特权 Helper 直接跑 openconnect CLI（Tunnelblick 式）。任一受阻则改走兜底方案（见第十二节）。
- Phase 1 MVP（3–4 周）：App + Provider + Keychain 自动登录 + 连接/断开 + 192.168 分流 + 网段规则 + 无限重连 + 故障关闭主防线（路由不撤）。
- Phase 2 加固（2–3 周）：pf 兜底 Helper、菜单栏、统计、通知、等批准态 UI、诊断打包、应用规则、域名规则、规则测试器、泄漏自检、规则模板、通知聚合。
- Phase 3 完善（2 周）：偏好设置完整、放行表编辑、开机自启、多服务器/多账号、日志脱敏、公证分发。

## 十二、风险与未知

- 网关会话保持窗口未知：快速重连免批准的窗口多长，需实测；窗口外重连必然触发批准。
- 手机批准超时未知：超时后 Provider 自动再发起的行为需实测。
- OpenConnect 与公司网关版本兼容性需实测（协议细节、Group 选择、DTLS 协商）。
- PacketTunnelProvider 沙箱对 libopenconnect 的限制需 Phase 0 验证。
- 透明代理与包隧道共存、逆向模式（仅选定应用走 VPN）能否实现，需 Phase 0 验证；若不可行，分流模式的应用规则降级为排除制 + 提示，不硬上。
- Safari 排除受限：系统级限制，应用规则对 Safari 不承诺排除效果。
- pf 规则与 macOS 大版本升级的兼容性需持续跟进。
- 本设计不改动公司网关配置；若网关侧策略（如禁止保存密码、强制每次 2FA）与自动登录冲突，以网关策略为准，App 侧只能做到"少输密码 + 等批准"。

## 十三、查漏清单（逐项已覆盖）

- **IPv6 泄漏**：系统有 IPv6 时，未经隧道的 IPv6 出口会绕过全部规则。处理：VPN 激活时物理网卡出方向 IPv6 默认拦截（pf 兜底包含 IPv6 规则），除非网关下发 IPv6 隧道；局域网 IPv6（fe80::/10 链路本地）放行。
- **DNS 泄漏**：规则外域名的解析必须走隧道 DNS；Provider 的 DNS 配置只覆盖规则域名与隧道域名，其余域名解析仍走系统 DNS 时需确认不经过本地明文通道外泄内网域名。处理：默认模式为安全模式时，全部 DNS 走隧道；分流模式时仅规则域名与公司域名走隧道，其余走本地（用户已知情）。
- **DoH/DoT 绕过**：浏览器或应用自带加密 DNS 会绕过 Provider 的 DNS 代理，域名规则对它失效。处理：应用规则是后盾——给浏览器配一条应用规则即可全量覆盖；规则测试器里对 DoH 应用做提示。
- **QUIC（UDP 443）**：HTTP/3 走 UDP，域名规则靠 DNS 解析结果的 IP 路由，同样生效；应用规则走透明代理的 UDP 流，同样生效。无额外缺口。
- **Captive Portal（酒店/机场 Wi-Fi 登录页）**：Kill Switch 全拦截时，Portal 登录页打不开。处理：检测到 Captive Portal 时，App 提示用户"临时放行 Portal 登录"，用户确认后仅放行 Portal 域名/IP，登录完成自动恢复拦截；不自动静默放行。
- **mDNS / Bonjour / AirDrop / 打印机发现**：链路本地组播（224.0.0.0/4、ff02::/16）与局域网发现流量放行，不进隧道。
- **网关自身直连**：到网关的流量必须走物理网卡（隧道还没建起来时），网关地址自动加入直连排除，不依赖用户配置。
- **DHCP 与链路本地**：DHCP（67/68）、ARP、本地回环一律放行，否则局域网地址都拿不到。
- **睡眠唤醒与网络切换**：唤醒与 Wi-Fi 切换时立即重连并刷新域名解析，不用等退避周期跑完。
- **规则热更新**：改规则不重连，增量更新路由与 DNS；进行中连接按旧规则走完。
- **规则冲突**：同目标出现在 VPN 与直连两侧 → 按走 VPN 处理并红字提示；局域网网段被配进 VPN → 以直连为准并告警。
- **内网域名误配直连**：公司内网域名若被配进直连，因本地 DNS 解析不到，只会连不上，不会泄漏到外网（fail-safe 方向），规则测试器会提示"该域名本地解析不到"。

## 十四、后续扩展池（本期不做）

- 标准协议：WireGuard / OpenVPN / IKEv2。
- Cisco 对齐：Posture 合规、Umbrella 式 DNS 防护、AMP 联动、Web Security。
- 通用附加：分流可视化编辑器、连接质量看板、断网保护可视化、DNS 泄漏检测、Shortcuts、多账号快速切换、配置加密分享。
- 高级规则：按端口分流（如仅 443 走 VPN）、按时间段分流（如工作时间自动切安全模式）。

## 十五、Phase 0 分叉决议（v0.5，2026-10-31，用户授权助手定）

### 决议：走特权 Helper + openconnect CLI 路线，放弃 NE 包泵路线

新架构：App（菜单栏）+ Helper（LaunchDaemon，root：跑 openconnect CLI、管 pf、管路由与 DNS）+ Proxy（透明代理，只做应用规则）+ pf 兜底。PacketTunnelProvider 目标移出构建，不再承担隧道；其源码保留在 Sources/Tunnel（不编译）作参考，CLI 路线跑通后删除。2026-11-02：CLI 路线已跑通（Phase 1 闭环 + CI 全绿），Sources/Tunnel 与 App 侧已废弃的 TunnelManager 一并删除。

### 定性理由（按权重排序）

1. **最少未验证机制**：CLI 路线复用久经实战的 openconnect 二进制——认证、CSTP、DTLS、重连、MTU、DPD 全是现成的。NE 包泵路线要把 packetFlow 的包喂给 libopenconnect，依赖的喂包机制（socketpair + tun fd 注入或等效 API）未经本项目验证，NE 沙箱对库的网络、文件、Keychain 访问也未经验证。没 Mac 的情况下，每多一个未验证机制，风险就翻一倍。
2. **没 Mac 也能验得更多**：CLI + ocserv 在 Linux 上就能跑通编排逻辑（拉起、传参、Cookie 恢复、退出码、脚本钩子），只剩 tun 与路由表被沙箱挡住；NE 包泵离开 NE 运行时一步都验不了。
3. **Helper 本来就要有**：pf 兜底无论如何都需要一个特权 Helper，CLI 路线不新增特权组件，只给已有组件加活。一次管理员授权装 Helper，同时解决 pf 与隧道。
4. **Tunnelblick 同款，有维护先例**：同一模型在 macOS 大版本间有人持续维护，不是孤例。
5. **沉没成本可控**：被放弃的只是 Tunnel 目标的接线代码（Provider 壳 + 会话驱动适配），Rust 核的规则、会话驱动、pf、认证映射全部复用；Proxy 不受影响。

### 付出的代价（明说，不藏）

- App 与隧道的关系从 NETunnelProviderManager 改为 XPC：App 读 Keychain，启动时经 XPC 把凭据发给 Helper（Helper 只放内存，不落盘）；Helper 用 --passwd-on-stdin（新认证）或 --cookie-on-stdin（会话恢复）起 openconnect，--authgroup 传 Group。
- 失败关闭的第一道改由自定义 vpnc-script 承担：脚本的断开路径一律不拆路由、不清 pf（只记日志），只在 Helper 确认"用户手动断开"后才由 Helper 显式恢复本地网络；意外掉线时路由与 pf 原地保留，openconnect 自身重连 + Helper 的退避双保险。
- 等批准态的感知从"库回调通知"变为"CLI 输出启发式"：Helper 从 openconnect 的 --dump-http-traffic 输出里识别 push 等待标记，真实网关的实际输出形状是 Phase 1 待验证项，验出来之前不承诺精确的等批准文案。
- 分发仍需付费开发者账号（Proxy 的 NE entitlement + Helper 的 SMAppService + 公证），包隧道 entitlement 省掉了，但 binding 约束没变。
- openconnect 是 GPL：个人自用无碍，对外分发需处理源码义务。

### 随决议的改动清单（Phase 1 重做项）

- project.yml：Tunnel 目标移出构建，App 目标去掉对 Tunnel 的依赖；Proxy、Helper 不变。
- App 侧：TunnelManager（NETunnelProviderManager）替换为 HelperClient（XPC：启动、停止、状态订阅、lastError）；面板状态源从 NEVPNStatus 改为 Helper 上报的状态。
- Helper 侧：除 generate-pf 外，增加 CLI 编排（拉起、停止、退出码与重连决策、Cookie 持久化复用 SessionRecord、pf 加载/卸载、vpnc-script）。
- Rust 核：会话驱动复用为编排决策逻辑；认证结果映射从 obtain_cookie 码改为 CLI 退出码 + 脚本钩子信号（Phase 1 落实）。
- 本决议之前的 Tunnel 相关设计段落（第二节架构、第六节第 3 条隧道层）以本节为准，不再单独改旧文。

## 十六、Phase 1：Helper XPC + CLI 编排契约

Phase 1 的第一步，先定接口再写码。本节是 App、Helper、openconnect CLI、vpnc-script 之间的契约，后续代码按本节实现；与实测不符处以实测为准并回改本节，不静默偏离。

### 16.1 XPC 协议（App ↔ Helper）

Helper 以 LaunchDaemon 常驻，App 经 NSXPCConnection 连 Helper 的 Mach service。Helper 只把凭据放内存，绝不落盘；Helper 重启后 App 在启动自动连接时重新发送。

App → Helper：

| 消息 | 参数 | 说明 |
| --- | --- | --- |
| connect | server、group、username、password | 启动一次连接；Helper 决定走 Cookie 恢复还是全新认证 |
| disconnect | 无 | 用户手动断开；Helper 停 CLI 并显式恢复本地网络 |
| getStatus | 无 | 拉取当前状态与 lastError |

Helper → App（状态订阅回调）：

| 回调 | 参数 | 说明 |
| --- | --- | --- |
| statusChanged | state（六态之一）、detail | 状态变化即推，面板只认 Helper 上报，不再认 NEVPNStatus |
| errorChanged | lastError（原因 + 下一步，不贴码） | 错误行文案来源 |

六态与 UI-DESIGN.md 第三节一一对应：Disconnected / Connecting / Authenticating / AwaitingApproval / Connected / Reconnecting；凭据被拒不是第七态，是 Connected 失败后的错误行 + 驱动停住。

### 16.2 CLI 拉起参数

Helper 用 Foundation Process 拉起 openconnect，参数只给必需项，不堆 flags：

- 全新认证：`openconnect --server=<server> --authgroup=<group> --user=<user> --passwd-on-stdin --script=<vpnc-script> --dump-http-traffic`
- 会话恢复：把 `--passwd-on-stdin` 换成 `--cookie-on-stdin`，其余相同。
- 凭据经子进程 stdin 一次性写入，写入后立即关闭（已写数据仍会送达；第二次读取见 EOF，子进程自行退出，永不因等输入挂住——2026-10-31 实测：macOS openconnect 9.21 在 CSTP 401 后若 stdin 保持打开会永久阻塞）；Helper 不把凭据写进命令行参数（ps 可见）或日志。
- `--dump-http-traffic` 有两个目的：等批准态的输出启发式（16.5）与隧道 Cookie 捕获（16.3.2）；它的输出是 verbose 进度的超集。除此之外不依赖输出文案做决策。

### 16.3 退出码与重连决策：先定分类，码值以实测为准

openconnect 的精确退出码表不在本节写死——以 ocserv 实测与真实网关观测为准，Phase 1 落实阶段填表。决策只认四类，分类依据是退出状态 + 子进程 stderr 尾行 + 脚本钩子信号三者合议，任一信号不足时按 Transient 处理（宁可多重试一次，不把可恢复的掉线判成死局；但 Rejected 例外，见下）：

| 类别 | 含义 | 驱动动作 |
| --- | --- | --- |
| CleanStop | 手动断开或 Helper 主动停止 | 停住，恢复本地网络，面板灰圆环 |
| AuthFailure | 认证被拒（坏密码、坏 Cookie 且密码兜底亦拒） | 停住不重试（防账号锁定），面板红字 + 直达凭据页 |
| Transient | 网络中断、DPD 超时、网关不可达等可恢复失败 | 按退避（1/2/5/10/30s 封顶 + ±20% 抖动）无限重连，pf 与路由原地保留 |
| ApprovalTimeout | 等批准启发式命中后 120s 内无进展 | 自动再发起一次认证并再推一条批准通知（面板显示次数） |

Cookie 恢复失败不直接判 AuthFailure：先回落到密码全新认证一次，密码亦拒才判 AuthFailure。SessionRecord 的 usable_for 规则不变（只判网关匹配与 Cookie 非空），不猜过期。

### 16.3.1 实测依据（2026-10-31，ocserv 1.2.4 + openconnect 9.12，沙箱）

分类器只认 Helper 观测到的事实，不认退出码数值本身——实测证明退出码会骗人：

| 场景 | 客户端所见 | 服务端实情（debug 日志） | 分类 |
| --- | --- | --- | --- |
| 错密码 | exit 1，stderr 含 "Login failed."，脚本零调用 | 表单认证失败 | AuthFailure（停住不重试） |
| 假 Cookie（--cookie-on-stdin） | exit 1，stderr "VPN service unavailable"，脚本零调用 | Cookie 校验失败 | Cookie 失效 → 丢弃记录、密码兜底一次 |
| 正确密码 | exit 2，stderr "Cookie was rejected by server; exiting."，脚本零调用 | 会话已建立、已分配 IP 10.77.0.121，随后 `TUNSETIFF: Operation not permitted`（沙箱禁 tun 设备） | Transient（认证后失败），绝不是 AuthFailure |

教训：exit 2 + "Cookie was rejected" 在沙箱里是 tun 失败的表象，不是认证被拒；把退出码或该文案直接映射成"密码错"会在 Mac 上误杀正常会话。分类的第一信号永远是脚本钩子（connect 到达与否）与喂入的凭据种类，stderr 文案只作辅助；"Login failed." 是表单阶段的实测信号，真实网关的文案可能不同，届时以实测补表。

### 16.3.2 隧道 Cookie 的捕获方式（已更正：Set-Cookie 抓不到）

CLI 进程不向调用方返回 Cookie；2026-10-31 实测证明，openconnect 自身会在所有输出模式里把 Set-Cookie 的值写成字面量 `<elided>`（verbose 与 --dump-http-traffic 均如此，哈希核对确认），所以解析 Set-Cookie 只能抓到 "<elided>"——早期设计稿里写的那条路是错的，现已废弃。

唯一真实的捕获通道是 --dump-http-traffic 输出里 CSTP CONNECT 请求头：`Cookie: webvpn=<真值>`（同法哈希核对：mock 网关发出的 mockcookie123 在该行原样出现）。引擎只解析该行，前缀必须精确匹配（`webvpncontext=` 不算），值为 "<elided>" 或空时丢弃，后出现的行覆盖先前的行，存下的永远是最新值；捕获后立即写入 CookieStore（0600）。

代价：dump 输出同时印出认证请求的 XML（含 <password> 明文），因此引擎的 redact 规则除掩码 `webvpn=` / `webvpncontext=` 外，还掩码 <password>…</password> 内容；子进程输出绝不原样进日志或诊断包。

### 16.4 vpnc-script：失败关闭第一道

Helper 自带自定义 vpnc-script（sh），openconnect 以 `$reason` 区分调用点：

- `connect`：按 Helper 写入的配置设路由与 DNS；成功后向 stdout 写钩子行 `AC_HOOK connect tun=<if> gateway=<ip>`，Helper 据此把状态推为 Connected 并装载 pf。路由/DNS 命令失败时脚本以非零退出且不发钩子，引擎永不把"路由没立起来"报成已连接。
- `disconnect`：一律只记日志，不拆路由、不清 pf；唯一的例外是 Helper 在手动断开前先落一个标志文件，脚本见标志才执行恢复路径。标志的传递方式必须是文件路径而非环境变量值：子进程环境在拉起时冻结，停机时再设值永远到不了脚本——2026-10-31 发现的 Phase 1 遗留 bug 正是这处错位（引擎落标志文件，脚本却查一个拉起时已被显式删掉的环境变量，手动断开永远走 held 分支、脚本的路由/DNS 恢复分支永不执行）。修法（2026-10-31）：拉起时引擎把标志文件路径以 `ALWAYSCONNECT_MANUAL_FLAG_PATH` 传给子进程，`stop()` 在终止子进程前先落文件，脚本判文件存在才走恢复；`finishManualStop` 删文件，拉起时先清上一次崩溃残留的旧文件，防止意外掉线误读旧标志而放行。意外掉线时路由与 pf 原地保留，openconnect 自身重连 + Helper 退避双保险。
- 脚本与 openconnect 共享 stdout/stderr：钩子行与 `--dump-http-traffic` 输出走同一流，Helper 按行解析；钩子行格式固定为 `AC_HOOK <事件>`，事件名只增不改名。

脚本分支逻辑已在 Linux 上验过（取 Swift 内嵌文本、按 Swift 多行字符串缩进规则还原后逐分支执行）：disconnect 无标志 → `disconnect-held` 且不跑路由命令；disconnect 有手动标志 → `disconnect-manual`；connect（NO_ROUTES 测试模式）→ `connect tun=… gateway=…`；attempt-reconnect / pre-init / 未知 reason → exit 0。注意旧版验证设的是环境变量值，修法后验证口径改为标志路径 + 文件存在与否，并已固化为 CI 的 vpnc-script 分支步骤：Helper 的 `dump-script` 子命令输出引擎实际安装的原文，步骤对 disconnect 的无路径/路径无文件/文件存在三种状态、connect 测试模式、其余 reason 逐一断言。Mac 专属的 `route`/`scutil` 命令本身未在 Mac 上跑过，仍是 Mac proof 待验证项。2026-11-03 起 connect/restore 的路由、接口与 DNS 段已按 openconnect 官方 vpnc-script 的 Darwin 分支重写，见 §20.4。

### 16.5 等批准态启发式（待验证项，不承诺精确文案）

Helper 从 `--dump-http-traffic` 输出里识别 push 等待标记，命中后状态推为 AwaitingApproval 并推通知；120s 内无进展按 ApprovalTimeout 再发起。真实网关的实际输出形状是 Phase 1 待验证项：ocserv 只能验"启发式框架能跑"，验不出真实网关的标记文本；在拿到真实网关输出之前，文档与面板文案不承诺"识别到某某字样"，只承诺"等批准时面板与通知如实显示等待态"。

### 16.6 pf 生命周期

- 装载时机：`AC_HOOK connect` 到达且隧道接口已存在时，Helper 用 `pfctl -a com.apple/300.AlwaysConnect -f <锚点文件>` 装载 ac_pf_generate 的输出（锚点路径与开启方式见 §20.5，旧名 com.alwaysconnect.killswitch 不被主规则集求值）；锚点文件由 Helper 生成，不复用 App 侧。
- 卸载时机：只在手动断开（CleanStop）时卸载并恢复本地网络；Transient、ApprovalTimeout、AuthFailure 一律不卸载。
- 网关 IP 变化时 Helper 重新生成锚点并重装（pf.rs 已定约束：网关 IP 必填，否则 pf 会挡住重连自身）。

### 16.7 Cookie 持久化

Helper 以 root 身份把 SessionRecord 存于 Helper 专属文件（0600，仅 root 可读），内容只有 gateway、server_fingerprint、cookie、saved_at_unix。App 侧 Keychain 仍是密码的唯一长期存放处；Helper 的 Cookie 文件是会话恢复缓存，不是凭据库。Cookie 恢复路径与密码路径共用同一套退出码分类与退避。

### 16.8 验证矩阵（Linux 能验什么、什么只能 Mac 验）

| 项 | Linux CI（ocserv）可验 | 只能 Mac 验 |
| --- | --- | --- |
| 拉起 / 停止 / 退出码分类框架 | 是（错密码 → AuthFailure；杀网关 → Transient） | 否 |
| Cookie 恢复（拿 Cookie、复用、坏 Cookie 回落密码） | 是 | 否 |
| vpnc-script 钩子行与 disconnect 不拆路由 | 是（脚本逻辑本身） | 路由表真实生效否 |
| 退避决策、会话驱动、pf 文本生成 | 是（单测 + Helper 实跑） | 否 |
| tun 设备、真实路由/DNS 切换 | 否（沙箱禁 tun 与改路由表） | 是 |
| 真实网关输出形状、手机批准流 | 否 | 是 |
| Helper 安装（SMAppService）、pfctl 真实装载、签名/公证 | 否 | 是 |
| Proxy 数据泵运行时 | 否 | 是 |

Phase 1 的完成标准是左列全绿；右列仍挂起，不假装已验。

2026-10-31 收口实证（CI run 全绿，commit 9db2dd9）：macOS runner 上又多验了引擎整环——mock AnyConnect 网关（重放 ocserv 真实认证表单 XML）下，密码认证 → Cookie 捕获 → Cookie 复用 → 密码兜底 → 次数耗尽 TERMINAL 全通；Linux CI 的行为契约（错密码 exit 1、假 Cookie exit 1）同趟绿。左列至此全部兑现，Phase 1 闭环；右列不动。

### 16.9 XPC 落实（Phase 1 step 3）

共享契约在 Sources/Shared/HelperXPC.swift（App 与 Helper 双目标编译，防漂移）：

- Mach service：`com.alwaysconnect.app.helper`。
- App → Helper：`connect(server:group:username:password:reply:)`、`disconnect(reply:)`、`getStatus(reply:) -> (stateCode, detail)`。凭据每次连接时经 XPC 发送一次，Helper 只放内存。
- Helper → App：`statusChanged(state:detail:)` 单向推送，App 不轮询。
- 状态码与 Rust 驱动一致（0–5）；凭据被拒不设第七态，以 terminal 回调的 error detail 呈现。

Helper 侧（Sources/Helper/HelperDaemon.swift）：`daemon` 子命令起 NSXPCListener，accept 时校验客户端团队标识——取客户端 pid 对应的可执行文件静态码签名信息中的团队标识，须与 Helper 自身的团队标识一致；未签名的开发构建两侧均为 nil，放行并记日志；签名后只有同团队客户端能连，任意本地进程无法驱动 root 守护进程的 pf 与隧道。Helper 重启后 App 下一次用户操作或启动自动连接时重新发送凭据，不做静默无限重连。

App 侧（Sources/App/HelperClient.swift）：懒建连接，中断/失效时面板显示 Helper 未运行；面板（PanelAndSettings.swift）状态源已切到 HelperClient，开关 off 时先出内联确认行，确认后才断开；快捷入口四格待 Settings 页落地时再接（Phase 2）。

Mac-proof 待验证项（不在 runner 上假装）：launchd plist 与 SMAppService 安装、签名后的团队标识校验、菜单栏图标四态、XPC 端到端（App ↔ Helper ↔ openconnect）实跑。

### 16.10 子进程看门狗（待定，不做假证明）

已观测的挂起类：子进程活着、既不退出也不再产生事件。2026-10-31 的实例曾先后归因于 mock 的 keep-alive 401（已修 mock，401 后关连接，无害但非主因）与 stdin 保持打开（已改喂完即关，无害但非主因）；最终实证根因是引擎的 redact() 无限循环：掩码替换后键仍留在串里，while 循环原地重匹配同一处，引擎串行队列冻在第一条 Set-Cookie 行，子进程独自跑完而引擎再无事件。定位靠 run-once --debug-child-output 的流式输出，修法为掩码后搜索起点移到掩码值之后（commit 6ed87d6）。

引擎侧目前没有单次子进程运行的超时看门狗。补一个的约束：超时必须长于 120 秒等批准超时（等批准先触发），且 hook 到达后立即解除（隧道建立后子进程跑几小时是正常态）。在真实网关能验证 push 行为之前不加——一个未经验证的看门狗可能在等批准时误杀子进程。

## 十七、Phase 2：Proxy 数据泵契约

范围：Phase 2 在此定义为数据泵落地（本节 17.1–17.7）。旧 §十二列表中的菜单栏、统计、Settings 页、规则测试器、泄漏自检等顺延，不在本节；与实测不符处以实测为准并回改本节，不静默偏离。

### 17.1 语义：只泵直连流

handleNewFlow 的决策表（引擎是唯一判据）：

| 引擎判定 | handleNewFlow 返回 | 流向 |
| --- | --- | --- |
| 直连，且泵建成 | true | 泵出物理口（17.2） |
| 直连，但泵建成失败（无物理口、绑定失败、解析失败、建 socket 失败） | false | 按系统路由走隧道（安全方向：只错路，不漏网） |
| 走 VPN | false | 按系统路由走隧道 |
| 引擎未配置（startProxy 未完成规则加载） | false | 走 VPN（故障关闭，与 Phase 1 一致） |

绝不出现“判直连但无泵”的悬空态：泵建失败不返回 true，流不会悬在 provider 里。

区分两种失败：同步建泵失败（无物理口、端点不可用）返回 false，走 VPN；返回 true 之后的异步失败（flow open 失败、connect 超时）无法把流交回系统，只能断流。不断流回 VPN 是有意的：直连规则静默变成 VPN 路由会违背用户写规则的本意，且失败可见、用户可改规则。

### 17.2 绕隧道机制：IP_BOUND_IF

出向 socket 在 connect 之前绑定物理口：IPv4 用 `IP_BOUND_IF`、IPv6 用 `IPV6_BOUND_IF`，值为物理口索引（if_nametoindex）。只绑接口不绑源地址：源地址绑定改不了目的路由，绑接口才强制出物理口。绑定失败 → 泵建失败 → 按 17.1 走 VPN。

已知限制（与 §4.3 一致，面板不承诺反向）：系统 DNS 仍走 VPN。直连流的目的地若是主机名，先经系统解析（getaddrinfo）得 IP，再对该 IP 建绑定连接；解析查询本身走 VPN，不产生业务流量旁路。TCP/UDP 之外（ping 等原始 socket）恒走 VPN。

### 17.3 物理口发现：逐流 getifaddrs

provider 进程内自行发现，不依赖 Helper 传入（两者进程不同，App Groups 不传运行时口状态）。每次建泵时重新枚举，接口变化（Wi-Fi 漫游、插拔网线）即时生效：

1. 过滤：flags 含 IFF_UP 且 IFF_RUNNING、非 IFF_LOOPBACK、名不以 utun/stf/gif/pdp_ip/ipsec/ppp 开头、有 IPv4 地址。
2. 唯一幸存 → 它；多个 → en0 优先，其次最小 enN，其次字典序首个；零个 → 泵建失败 → 走 VPN。
3. 名字转索引用 if_nametoindex；返回 0 → 泵建失败。

Helper 的 physicalIf（默认 en0）与 provider 的发现结果在单物理口 Mac 上一致；多宿主下两者可能错位（泵口与 pf 网关口不一致）是已知限制，见 17.6，不静默处理。

### 17.4 中继核（PumpCore）：端点抽象 + 双向中继

中继核与 NetworkExtension 解耦，可在 runner 上实测（17.6）：

- 端点协议：异步 read（Data? + Error?，nil 数据 + nil 错误 = EOF）、write、closeRead、closeWrite。
- 双向各一循环，读→写串行（读下一块只在上一块写完后，天然背压；个人客户端流量下足够，不做多读并发）。
- 半关闭：一方 EOF → 关另一方写侧，另一方向继续排空直至自身 EOF；任一侧写错 → 双向关闭；两方向都终结 → onDone 回调，provider 释放泵。
- NE 适配：TCP 用 open/readData/writeData/closeReadWithError/closeWriteWithError；UDP 按远端端点分 socket（一个 flow 内多远端各一个绑定 socket），datagram 中继，120 秒空闲关闭。
- fd 适配（DispatchIO + shutdown 语义：closeWrite = shutdown(SHUT_WR) 而非关 fd，保证另一方向能排空）供 PumpTest harness 用同一中继核，不另写一套。
- fd 端点 teardown 实证（CI 四轮 SIGTRAP 定位）：DispatchSource 被 cancel 后若仍处于 suspended 态、未 resume 就释放，会在释放时以静默 SIGTRAP（exit 133，无运行时报错）死掉，且死点随队列时序在不同检查间移动。修法：close() 块里 cancel 后，对所有仍 suspended 的 source 调 resume（以标志位为准，只 resume 确实 suspended 的），让 cancel 完成后再关 fd、再释放。PumpTest 的 ALWAYSCONNECT_PUMP_TRACE=1 追踪（同步 stderr 写）是定位它的手段，CI 默认开启。
- SIGPIPE 实证（2026-11-03，本机 macOS 26.5 实跑 PumpTest）："relay error teardown" 一项每次都以 exit 141（SIGPIPE）死掉——对端 RST 后中继往该 socket 写，默认信号动作杀整个进程；放到 Provider 里即一条直连流被远端重置就带崩全部流。修法：FDEndpoint 构造时对 fd 设 SO_NOSIGPIPE（非 socket 拒收无害），FlowPump 建绑定 socket 时同设（UDP 发送路径直写 fd，不经 FDEndpoint），写失败改以 EPIPE 返回、走既有写错双向关闭。同类风险在 Helper：喂凭据时子进程若已退出，写管道同样 SIGPIPE 杀 root 守护进程，故 Helper 入口 `signal(SIGPIPE, SIG_IGN)`，喂凭据改用会抛错的 write(contentsOf:)（旧 write(_:) 遇 EPIPE 抛不可捕获的 ObjC 异常）。验证级别：本机 PumpTest 10/10 通过（修前 6/6 失败）。

### 17.5 pf 两态协同：泵生效的前提

泵不改 pf 就等于没泵：连接态若仍用封堵集，泵出的直连流会被物理口末尾 block 规则挡掉，应用/域名直连规则全部失效。因此 pf 分两态，锚点与加载路径不变：

| 态 | 物理口末尾规则 | 装载点 |
| --- | --- | --- |
| 连接态 | `pass out quick on {phys} all`（其余规则与顺序不变，特定放行行保留） | connect 钩子，且仅当透明代理在泵直连流时（2026-11-03 起默认不装，见 §20.7） |
| 封堵态 | `block drop out quick on {phys} all`（现行文本，不变） | 钩子后掉线（childExited 的 hookFired 分支），重连前保持封堵 |
| 手动断开 | 卸载（不变） | finishManualStop（不变） |

pf-state 持久化：每次装载写 supportDir/pf-state.json（0600，含 tunnelIf/gatewayIps/physicalIf/allowNetworks），手动卸载时删除。daemon 启动时若文件存在则重装封堵态：Helper 崩溃重启默认故障关闭；隧道若仍存活（孤儿 openconnect），直连流降级走 VPN 直至下次重连——安全方向。

边界（明说，不藏）：连接态放行物理口出向，意味着本地应用若主动绑定物理口可绕隧道。本客户端的威胁模型是“掉线意外泄漏”而非“本地恶意应用主动绕过”，该窗口不在防范范围；掉线检测到封堵重装之间，vpnc-script 的路由持有（不拆路由）仍是第一道黑洞。

### 17.6 验证矩阵（Phase 2）

| 项 | runner 可验 | 只能 Mac 验 |
| --- | --- | --- |
| 编译 + 链接（新 Proxy 文件、PumpCore、PumpTest 靶） | 是（xcodebuild 既有步骤 + PumpTest 靶显式构建） | 否 |
| 中继核：字节双向、半关闭排空、写错双向关闭 | 是（PumpTest harness，真实 loopback socket） | 否 |
| 物理口选择纯函数（过滤、en0 优先、多口/零口） | 是（PumpTest  canned 列表） | 否 |
| IP_BOUND_IF/IPV6_BOUND_IF 实测（setsockopt 成功） | 是（PumpTest，lo0 索引） | 否 |
| pf 两态文本（连接态末尾 pass、封堵态末尾 block、默认仍为封堵） | 是（Rust 单测 + generate-pf CI 既有断言） | 否 |
| 隧道 up 时直连流真实走物理口、掉线时封堵重装时序 | 否 | 是 |
| Provider 与 Helper 的口一致性（多宿主）、IPv6/UDP 直连流实跑、手机确认登录不受影响 | 否 | 是 |
| Safari 排除受限、系统 DNS 走 VPN、仅新连接生效 | 否（既有限制，见 §4.3） | 是（行为与 Phase 1 结论一致） |

Phase 2 的完成标准是左列全绿；右列仍挂起，不假装已验。

### 17.7 文件清单

- Sources/PumpCore/RelayCore.swift（端点协议 + 双向中继 + fd 适配）、InterfaceSelect.swift（纯选择函数 + getifaddrs 枚举）。
- Sources/Proxy/FlowPump.swift（NE TCP/UDP 适配 + 绑定 socket 创建）、TransparentProxyProvider.swift（handleNewFlow 按 17.1、startProxy 从 App Groups 读 profile/rules、stopProxy 取消全部泵）。
- core/src/pf.rs（PfInput 加 allow_direct_egress）、core/src/ffi.rs（ac_pf_generate 加参）、Sources/Helper/PfAnchor.swift（透传）、HelperMain.swift（generate-pf 加 --connected）、CLIOrchestrator.swift（连接态/封堵态切换 + pf-state 持久化）。
- Sources/PumpTest/main.swift（工具靶）+ project.yml（AlwaysConnectPumpTest 靶）+ CI macOS 步骤（构建并运行 harness）。

## 十八、Phase 3 App 层（2026-11-02，不依赖 Mac 实机的收口）

本节记录 Phase 3 的 App 层实现：菜单栏打磨、六页设置窗口、首次向导、规则测试器、诊断与统计。所有内容均以 CI 编译为证；运行时行为（安装、通知、快捷键、泄漏自检的真实命令输出）仍需 Mac 实测，见 §17.6 右列与下文。

### 18.1 菜单栏面板（UI-DESIGN.md §三/§四）

- 状态图标：颜色 + 形状双编码（绿实心已连接、黄三角连接中/认证中/等批准、红空心重连中、灰圆环手动断开），由 HelperClient.state 驱动；悬停文案与面板状态行一致。
- 状态行文案按 UI-DESIGN.md §三；无凭据时开关置灰、状态行写"未设置凭据"，入口第一位换成"去设置凭据"。
- 掉线历史行：HelperClient 记录 connected → reconnecting → connected 的完整掉线（时间 + 时长），持久化于 App Groups（原为最近 50 条；§21.21 改为 20 条，§21.22 改为 10 条并记录结果、重新登录次数、手机批准次数与失败原因，失败的掉线也记），面板与诊断页共用。
- 快捷入口：规则 / 统计 / 设置走 SettingsLink 打开设置窗口；导出诊断包直出文件（状态、profile、规则、掉线历史、版本，去敏感：不含密码与用户名）。
- Helper 未运行时红字 + [安装 Helper] 按钮（SMAppService，幂等：已注册即成功）。

### 18.2 设置窗口六页（UI-DESIGN.md §五）

- 通用：启动自动连接（profile）、开机自启（SMAppService.mainApp）、通知聚合（见 18.5）、全局快捷键（默认关，录制式，须带修饰键，须辅助功能权限）。
- 凭据：服务器 / Group / 用户名（ProfileStore）+ 密码（Keychain，只改不显，无显示开关）+ [测试连接]（走 connectWithStoredCredentials，结果即状态机本身）。
- 网络：默认模式（profile，Proxy 实时读取，见 18.4）。其余为信息行：局域网 192.168.0.0/16 恒直连（引擎硬规则）、pf 兜底已启用（放行网段即 Helper 当前值）、DNS 说明。
- 规则：卡片 CRUD（ProfileStore，Proxy 实时读取）、三个模板（家里局域网直连 192.168.0.0/16、公司内网走 VPN 10.0.0.0/8 占位、常用直连 *.example.com 占位，均可再改）、冲突红字（同目标双向）与局域网进 VPN 告警（CIDR 重叠判定，展示用，权威判定在 Rust 引擎）。
- 诊断：状态、掉线历史表、泄漏自检（见 18.6）、诊断包导出。日志级别控件未做：没有日志管线可供它控制，存一个死开关是假控件。
- 统计：本次连接时长（TimelineView 秒级刷新）、隧道口上下行流量（Helper getStats）、累计掉线次数。不做流量图表（已定）。

### 18.3 首次向导（UI-DESIGN.md §六）

四步：欢迎 → 装 Helper → 填凭据 → 选模式 → [完成并连接]。无用户名时首次启动弹出；凭据与 Helper 两步不可跳过（无有效输入时 [下一步] 置灰）；关闭窗口则下次启动重现。凭据页与模式页复用 CredentialForm / ModePicker，不另写一套表单。

### 18.4 规则实时生效（修掉的假承诺）

此前 Provider 只在 startProxy 建一次引擎，改规则要重连才生效，与 UI-DESIGN.md §七"改规则不重连，增量生效"矛盾。本轮修真：handleNewFlow 每次先比对 App Groups 的 profile/rules 字节，变化才重建引擎；进行中连接按旧规则走完（决策已做出）；解码失败不覆盖可用引擎。

Fail-closed 边界：profile 缺失或解码失败 → 保持原引擎（首启则为 nil，全部走 VPN）；split 模式且从未存过规则 → 保持 fail-closed（全部走 VPN），直到第一次保存规则；secure 模式且无规则 → 空规则集，与 fail-closed 等价。

App Groups 键（suite、profile、rules、username、appSettings、dropHistory）收进 Shared 的 AppGroups 单一源，App 与 Proxy 不再手工同步字符串。

### 18.5 通知（UI-DESIGN.md §一.5/§二）

HelperClient 的状态迁移驱动：首次掉线推一条、恢复推一条、等批准每次都推。聚合开关开 = 掉线/恢复也推；关 = 只推等批准与终态（动作必需类）。被拒通知已补（§十九）：终态原因码经 getSessionInfo 回传，App 按码通知；面板错误行仍是被拒的主界面。

### 18.6 诊断 XPC（新增方法与升级安全）

HelperXPC 新增三个 App → Helper 方法，全部由 HelperClient 包 3 秒超时回落（见下）：

- evaluateRule：App 把规则 JSON 与默认模式发给 Helper，Helper 建一次性引擎调 ac_engine_resolve_detail，回方向（0 走 VPN / 1 直连 / -1 输入无效）+ 原因码。App 不直连 Rust（App 目标不链 staticlib）；Helper 不读用户 App Groups（root 守护进程解析用户容器不可靠），规则由 App 显式传入。
- getStats：Helper 对隧道口做 getifaddrs，取 ifi_ibytes / ifi_obytes；无隧道回零与空接口名。
- runLeakCheck：默认路由经隧道口（route -n get default）、pf 锚点已装载（pfctl -s rules 非空）、网关经物理口直连（逐网关 route -n get）；DNS 只出解析器列表作信息行，不伪造方向结论。

升级安全：Helper 随 App 包安装但独立更新，新 App 可能面对旧 Helper。新增方法一律加超时：3 秒无回包即按"Helper 版本过旧或未运行"回落，不挂起。Phase 1 的 connect / disconnect / getStatus 签名未动，无此问题。

### 18.7 Helper 嵌入

project.yml 的 App 目标依赖 AlwaysConnectHelper，并以构建后脚本把 Helper 二进制与 AlwaysConnectHelper.plist 拷进 App 包 Contents/Library/LaunchDaemons/，供 SMAppService.daemon 注册。plist 以 BundleProgram 指向包内 Helper，ProgramArguments 首项为工具名、次项为 daemon 子命令，并以 MachServices 声明 XPC 服务名（2026-11-03 补，见 §20.2）；SMAppService 的实际解析与安装效果需签名构建 + Mac 实测（与付费开发者账号同一门槛）。

### 18.8 有意 defer 的项（不是忘了，是有原因）

- pf 关闭开关：UI-DESIGN.md §五有此开关，但亲手关掉故障关闭第二道是安全关键操作，需单独的安全设计（关后警告、状态明示、重开路径），不能顺手加一个持久化开关了事。本轮网络页只展示"已启用"事实。
- 自定义放行网段：Helper 的 allowNetworks 目前硬编码 192.168.0.0/16（已覆盖用户家里内网的实际需求）。接通自定义值需要 Config 由 let 改 var + 引擎队列内的实时 pf 重装设计（当前 pf 集由驱动状态决定），属于引擎改动，不宜塞进 App 层收口批。
- DNS 方向判定：泄漏自检的 DNS 项需 VPN 的 DNS 集合，需 vpnc-script 把 INTERNAL_IP4_DNS 回传给引擎（connect 钩子输出扩展 + mock 网关配合），是后续的引擎 + 脚本工作。
- 被拒通知与重连次数显示：两者都需要 Helper 推送带更多信息（终态原因码、单次掉线内的重试次数）。Helper 与 App 独立更新，推协议改动需升级安全设计（老 Helper 调新方法、新 App 收老推送），不在本批做。
- 菜单栏图标关闭开关：菜单栏是 LSUIElement 应用的唯一入口，关掉图标即无处再打开应用，故不做此开关。
- §16.10 子进程看门狗、approvalPatterns、库路径 NeedsApproval：仍挂起，原因不变（需真实网关行为/输出形状，不编造）。

### 18.9 §18.8 收口状态（2026-11-03）
以下三项已在 §十九做完，不再是 defer：自定义放行网段、DNS 方向判定（钩子回传 + 自检 verdict）、被拒通知与重连次数显示。仍 defer 的只有：pf 关闭开关（安全设计未做）、菜单栏图标关闭开关（唯一入口，不做）、§16.10 看门狗、approvalPatterns、库路径 NeedsApproval（均需真实网关）。

## 十九、Phase 4：defer 项收口（2026-11-03，不依赖 Mac 实机的第二批）

### 19.1 自定义放行网段
Profile 新增 allowNetworks（默认 ["192.168.0.0/16"]；老 profile 解码时合成 Codable 回落默认值）。App 在 connect 接受后与网络页保存时调新增 XPC 方法 updateAllowNetworks；Helper 在引擎队列内改 config.allowNetworks（Config 由 let 改 var，改动只发生在引擎队列），并按当前 pf 形态（lastAllowDirectEgress）重装已加载的 pf 集，无需重连；未加载 pf 时新值在下次加载与 pf-state 持久化中自动生效。校验两层：App 侧 isValidCIDR（Shared，App 与 Helper 共用）拦截非法输入，Helper 侧再过滤。空列表语义：掉线封堵期连局域网也不放行（故障关闭优先，见 pf.rs 两态）。已知限制：App 侧校验只接受 IPv4 CIDR；Rust 的 valid_cidr 也接受 IPv6，但 UI 不发送 IPv6，故无不一致。验证级别：CI 编译；运行时重装需 Mac 实测。

### 19.2 DNS 回传与自检 verdict
vpnc-script connect 钩子追加 dns=<逗号连接>（INTERNAL_IP4_DNS 为空白分隔；网关未下发时无此字段）。引擎 handleHook 解析并存 tunnelDnsServers（每次 spawn 清零）。泄漏自检 DNS 项由纯信息行改为 verdict：隧道 DNS 非空且至少一条在系统解析器中 → 通过；非空但无一在列 → 失败；空 → informational（网关未下发，不判）。验证级别：CI 脚本级断言（dump-script + 伪造 env 断言钩子行）；hook→引擎→自检链路编译验证，运行时需 Mac 实测。假设待 Mac 验证：INTERNAL_IP4_DNS 的空白分隔形态（脚本按此解析）。

### 19.3 规则 JSON 导入导出
规则页新增导出/导入按钮。导出为 [Rule] JSON（pretty + sorted keys，与测试器、evaluateRule 同一形状）。导入严格解码 [Rule]：整文件不可解析则拒绝并明示；空目标跳过、type+target+direction 重复跳过（与模板同一去重规则），计数汇报；导入经规则页 onChange 自动保存，新连接即生效。

### 19.4 终态原因码与重连次数
引擎新增 episodeRetries（driver 为 Reconnecting 时每次 spawn +1，connect 钩子清零）与 lastTerminalReason；HelperSession 跟踪并经新增 XPC 方法 getSessionInfo 返回（原因码 0 = 无/进行中、1 = 手动、2 = 凭据被拒、3 = 次数耗尽）。App 在重连推送时刷新次数、终态断开时取原因并通知：被拒与耗尽为动作必需类，不受聚合开关影响；手动不通知；老 Helper 超时则无通知，与旧行为一致。面板重连行显示"第 N 次"。协议安全：Phase 1 三方法签名未动；新增方法一律 3 秒超时回落（§18.6 模式）。验证级别：CI 编译；通知与次数的运行时表现需 Mac 实测。

## 二十、本机实测收口（2026-11-03，本机 macOS 26.5，无 Xcode、无签名证书）

本节记录在用户本机上实际跑出来的问题与修法。本机条件：只有 Command Line Tools（无 Xcode，xcodebuild 不可用）、无开发者证书、已装 Homebrew openconnect 9.21；构建改用 swiftc 直接编四个目标（scripts/build-local.sh）。验证级别逐条写明，不把本机实测说成真实网关实测。

### 20.1 会话归守护进程，不归 XPC 连接（修掉的故障开放）
旧实现每条 XPC 连接各建一个 HelperSession，连接失效时 shutdown() 调 engine.stop()——而 stop() 就是手动断开路径（落手动标志、脚本恢复路由、卸 pf）。后果：App 退出、崩溃或被系统杀掉，隧道即被拆、本地网络即被恢复，直接违反"只有手动断开才恢复本地网络"，也与 AppDelegate.applicationWillTerminate 的注释（退出不拆隧道）矛盾。修法：守护进程只持有一个 HelperSession；XPC 连接只是状态订阅者（addClient / removeClient），连接失效只退订、不碰引擎；状态推送广播给所有已连客户端；会话状态全部收进一条串行队列（XPC 回调与引擎回调线程不定，旧实现无同步）。重复 connect 且参数（server、group、username、password）完全相同时视为加入正在运行的会话、直接回 true（App 重启后的自动连接不再拆掉正在跑的隧道）；参数不同（凭据页测试连接）仍按旧语义替换引擎。被替换引擎的迟到回调按引擎身份过滤，不再串进新会话的状态。
团队标识校验改走 Security 框架按 pid 取客户端代码（SecCodeCopyGuestWithAttributes），不再经 NSRunningApplication：后者走 LaunchServices，root 守护进程不在用户会话里，取不到时客户端团队为 nil，签名构建下会把所有 App 都拒掉。Helper 因此不再链接 AppKit。
验证级别：本机 XPC 实测——Helper 以用户域 launchd 服务（launchctl bootstrap gui/<uid>，带 MachServices）拉起，独立 XPC 客户端实连：接入即收到状态推送；evaluateRule 往返（经 Rust 引擎，域名规则命中直连）；connect 后客户端退出，引擎继续重试，新客户端接入看到进行中状态；同参 connect 不重启引擎；disconnect 后 getSessionInfo 原因码 1。同一实测换旧版 HelperDaemon 复现了缺陷：客户端退出后新客户端只看到 state 0、引擎已停。root 域（SMAppService 安装的真守护进程）与团队标识校验的签名分支仍需签名构建 + Mac 实测。

### 20.2 Helper 安装链：四处会让 App 连不上 Helper 的缺陷
- launchd plist 缺 MachServices：守护进程里的 NSXPCListener(machServiceName:) 只能接管 plist 声明过的服务名，未声明则 App 永远查不到 com.alwaysconnect.app.helper。已补。
- launchd plist 缺 BundleProgram：SMAppService 注册的守护进程以 BundleProgram（相对 App 包的路径 Contents/Library/LaunchDaemons/AlwaysConnectHelper）定位可执行文件；ProgramArguments 只给 argv（首项工具名、次项 daemon 子命令）。已补。
- SMAppService.daemon(plistName:) 取的是 Contents/Library/LaunchDaemons 下的文件名、含扩展名；旧值缺 .plist。已改为 com.alwaysconnect.app.helper.plist（与 project.yml 构建后脚本拷入的文件名一致）。
- App 连系统域（LaunchDaemon）的 Mach 服务须带 NSXPCConnectionOptions.privileged；旧值为空选项，只会在用户域查找。已改。
另：守护进程首次 register() 成功后处于 requiresApproval，需用户在"系统设置 → 通用 → 登录项"里允许才真正运行。旧实现把它报成"已安装"；现在安装器在该态打开登录项设置页并提示去允许，向导在 App 回到前台时重读状态。
验证级别：plist 经 plutil 校验；MachServices 与 XPC 链路由 §20.1 的用户域实测覆盖（用的是同样的 MachServices 声明）；SMAppService 真实注册、BundleProgram 解析、privileged 查找与登录项批准流程需签名构建 + Mac 实测（见 §20.4）。

### 20.3 无 Xcode 的本机构建与启动
本机只有 Command Line Tools 时，`scripts/build-local.sh` 用 swiftc 直接编 Helper、PumpTest、App、Proxy 四个目标（Proxy 只编不嵌：要 NE entitlement），按 project.yml 的"Embed Helper daemon"组装 `.local-build/AlwaysConnect.app`（Helper 与 launchd plist 进 Contents/Library/LaunchDaemons），默认 ad-hoc 签名，设 SIGN_IDENTITY 可换真证书；`--tests` 接着跑 `scripts/local-checks.sh`，即 CI macOS 任务的运行时断言（引擎冒烟、mock 网关整环、pf 文本、vpnc-script 分支、PumpTest），不碰路由与 pf。Homebrew Rust 的 std 按宿主 macOS 构建，链接时有"built for newer macOS"告警，本机运行无碍，发布构建仍以 CI 工具链为准。
启动实测：App 起来后除首次向导外还多出一个 900×450 的空白窗口——SwiftUI 的 WindowGroup 在启动时总会开一个窗口，菜单栏应用不该有。改为空的 Settings 场景占位（它不在启动时开窗）后只剩向导窗口。验证级别：本机启动 + CGWindowList 枚举窗口（无屏幕录制权限，未截图；菜单栏图标在 macOS 26 上由控制中心托管，枚举不到，需人眼确认）。

### 20.4 vpnc-script 的 Mac 路由段重写（旧版在真实 Mac 上建不起隧道）
对照 openconnect 自带 vpnc-script（Homebrew /opt/homebrew/etc/vpnc/vpnc-script）的 Darwin 分支审旧脚本，四处在真实 Mac 上必坏：① 没给 utun 配地址（openconnect 自己不配，靠脚本 ifconfig），隧道起来也走不了包；② `route add default -interface utun` 在已有默认路由时报 File exists，脚本 exit 1、钩子不发，永远连不上；③ 没有"VPN 网关经物理网关"的主机路由，默认路由一旦指进隧道，openconnect 自己到网关的包也会进隧道成环；④ DNS 写在 Setup: 键（配置库），运行时不生效，官方用 State: 键并以 OverridePrimary 让隧道成为主服务。
重写（复用官方做法，不自研）：connect = ifconfig 配 utun 地址与 MTU → 取物理默认网关（默认路由不在 utun/ipsec/ppp 上才算）→ 加 VPN 网关主机路由（已存在则 change）→ 删默认路由、加经 utun 的默认路由 → scutil 写 State:/Network/Service/<utun>/DNS 与 IPv4（Router、OverridePrimary；有 CISCO_DEF_DOMAIN 时加搜索域）→ 发钩子；任一步失败 exit 1 不发钩子。全隧道：网关下发的 CISCO_SPLIT_INC/EXC 只记日志不执行（设计目标是出口 IP 恒为公司出口），真实网关若只放行分流网段会在实测中暴露。
物理网关存于 Helper 专属的 route-state 文件（supportDir，引擎以 ALWAYSCONNECT_ROUTE_STATE_PATH 传入，拉起前建目录，不随每次拉起清除）：掉线时默认路由随旧 utun 一起消失（第一道黑洞），重连时已取不到物理网关，故复用存档；重连换了 utun 时清掉旧 utun 的服务键。
restore（新增 reason，幂等，以状态文件为"有东西要撤"的标记）：清隧道服务键 → 当前没有非隧道默认路由时才按存档恢复默认路由（掉线期间若 configd 已为新网络装了默认路由，不去覆盖）→ 删网关主机路由 → 删状态文件。手动断开分支调用它；引擎 finishManualStop 再调一次（`<脚本> restore`）：子进程若停在两次重试之间，openconnect 从未走 disconnect，旧实现此时路由永不恢复。另补无引擎的断开：守护进程重启后按 pf-state 重装了封堵集但没有引擎，旧实现的 disconnect 无事可做、本地网络一直被挡；现在 disconnect 在无引擎时直接跑 restore + 卸 pf + 删 pf-state。
已知限制（明说）：掉线期间 configd 遇网络变化可能自行装回物理默认路由，此时第一道被绕过、只剩 pf 封堵集（第二道）；VPN 网关 IP 在重连间变化时，旧主机路由残留到下次 restore 前（只删最后一个）。
验证级别：脚本级断言——`core/scripts/vpnc-route-plan-test.sh` 以 PATH 桩替换 route/ifconfig/scutil（只记参数、按 FAKE_DEFAULT 应答 `route -n get default`），跑真实脚本的路由开启分支：首连、掉线保持、无默认路由下换 utun 重连、手动恢复、二次 restore 无动作、保留 configd 已装默认、无网关时失败且不发钩子，已进 CI 与 scripts/local-checks.sh。它证明计划不证明效果：真实路由/DNS 生效与断线不漏网仍是 Mac proof B1/B2。

### 20.5 pf 兜底此前从未生效：锚点不被求值、pf 未开启
pf 只求值主规则集引用到的锚点。本机 /etc/pf.conf 只引用 `com.apple/*`（另有 Cisco 的 cisco.anyconnect.vpn），旧锚点名 com.alwaysconnect.killswitch 是顶层新锚点：pfctl 照样装载成功、`pfctl -a … -s rules` 照样列得出规则（泄漏自检因此会报"已装载"），但任何包都不经过它——故障关闭的第二道是空的。另外 macOS 默认 pf 关闭，旧代码从不开启。
修法：锚点改为 `com.apple/300.AlwaysConnect`（主规则集的 `anchor "com.apple/*"` 会逐个求值 com.apple 下的子锚点；系统自带的是 200.AirDrop、250.ApplicationFirewall，300 排在其后）；装载前以 `pfctl -E` 取一个引用计数的开启令牌（stderr 的 "Token : <n>"），卸载后以 `pfctl -X <令牌>` 归还——只增减自己的引用，不替别的软件（Cisco 等）关 pf。守护进程带着令牌死掉即泄漏一个引用：pf 保持开启、锚点保持封堵或空，属故障关闭一侧。Rust 的 ANCHOR 常量、泄漏自检的查询锚点同步改名。
验证级别：本机 `pfctl -n -a com.apple/300.AlwaysConnect -f <文件>` 解析封堵态与连接态两套生成文本均通过（pfctl 首次作为最终校验器实跑；连接态里被 `pass out quick on en0 all` 覆盖的特定放行行由优化器合并，语义不变），已进 CI pf 步骤与 local-checks。真实装载、`com.apple/*` 对运行时子锚点的求值、-E/-X 令牌往返需 root，属 Mac proof C2。

### 20.6 服务器条目名 → 真实地址
预填的 "VPN-A" 是 Cisco Secure Client 配置文件里服务器条目的显示名（HostName），不是主机名；旧实现把它原样作为 `--server` 交给 openconnect，DNS 解析必然失败，永远连不上。Cisco 在本机 /opt/cisco/secureclient/vpn/profile（旧版 /opt/cisco/anyconnect/profile）的 XML 里存着 HostName → HostAddress 的映射。修法：App 连接时经 CiscoProfiles.resolve 查表（XMLParser 解析各 profile 的 HostEntry；含点或冒号的输入视为地址原样放行；查不到也原样放行），只把解析结果发给 Helper；Keychain 仍以用户填的条目名为键，改动不影响已存密码。凭据页在条目名可解析时显示实际连接地址。公司网关域名因此不进公开仓库。验证级别：本机解析实测（本机 profile 中 VPN-A 可解析为带端口的地址、地址与未知名原样放行）；连真实网关属 Mac proof A1。

### 20.7 已连接时也保持封堵态；pf 封的是网关实际走的物理口
连接态（物理口出向全放行）只为透明代理泵出的直连流而设（§17.5）。而 App 从未启用透明代理，旧引擎却在每次 connect 钩子都装连接态：没有任何流需要它，第二道防线在"已连接"期间白白失效——连接中网络切换、configd 为新网络装回物理口默认路由时，流量直接从物理口出去。现在引擎配置 allowDirectEgressWhenConnected 默认 false，connect 钩子装封堵态（隧道口、lo0、DHCP、网关、放行网段、mDNS、fe80 照常放行，隧道流量不受影响）；等透明代理真正启用且处于分流模式时再由它置 true。pf.rs 的两态生成与 `generate-pf --connected` 保留不动。
物理口旧为硬编码 en0：Wi-Fi 不是 en0 的机器、USB/雷雳网卡上，pf 封错了口，封堵形同虚设。vpnc-script 现在从物理默认路由同时取网关与接口，存入 route-state（AC_PHYS_IF，掉线后重连沿用），connect 钩子行末尾追加 `phys=<接口>`（测试模式不带）；引擎以它覆盖配置的 physicalIf，pf 生成、pf-state 持久化与泄漏自检随之用实际接口。多物理口同时在线时只封网关所走的那个，仍是 §17.3 已述限制。
验证级别：脚本级断言（路由计划测试断言首连钩子带 phys=en0、无默认路由的重连沿用存档接口）+ 本机 local-checks 全绿；pf 实装属 Mac proof C2，连接期间网络切换不漏属 B1。

### 20.8 掉线期间对外报 Reconnecting
Rust 驱动的 on_drop(cookie 已随子进程死亡) 在同一次调用里先进 Reconnecting、再直接进 Authenticating，引擎随后 reportState 读到的永远是 Authenticating。后果是真实掉线时 App 从来收不到 Reconnecting：菜单栏不变红空心、掉线/恢复通知不发、掉线历史不记、"第 N 次重连"恒为 0（引擎只在驱动处于 Reconnecting 时给 episodeRetries 计数）。驱动的状态机本身没错（重连确实要重新认证），错在对外报告。修法：引擎自记 inDropEpisode（已建立的隧道掉线时置位，connect 钩子或终态时清除）；期间驱动处于 Connecting/Authenticating 一律对外报 Reconnecting，AwaitingApproval 照报（要用户拿手机）；episodeRetries 按 inDropEpisode 计数。
验证级别：CI harness——新增 `core/scripts/fake-openconnect.sh` 冒充 openconnect（读 stdin 凭据、印 CSTP CONNECT 的 Cookie 头、以测试模式跑引擎自己的 vpnc-script connect、1 秒后 disconnect 并以非零退出），run-once 实跑断言 connected → reconnecting → 第 2 次以 Cookie 重连 → 次数耗尽，Cookie 落盘；已进 CI 与 local-checks。真实掉线的状态与通知属 Mac proof B1。

### 20.9 App 与 Helper 状态对齐：启动即接入、"网络仍拦截"、Helper 重启后重连
走查 App 层发现四处与"故障关闭 + 无限重连"不对齐：
- App 只在用户操作或自动连接时才建 XPC 连接、从不主动取状态（refreshStatus 无人调用）。§20.1 之后 Helper 的会话不随 App 退出，App 重开时若未开自动连接，面板显示"已断开"+"Helper 未运行"，而 VPN 实际在跑。现在启动时与每次打开面板都 getStatus（顺带登记为推送订阅者）；helperAvailable 只在 Helper 真正回包或推送后才置真（旧实现在 resume 时就乐观置真），lastError（连接类错误）在 Helper 回话后清除（旧实现一旦置上永不清除）。
- 凭据在掉线重连中被拒（防锁号，驱动停住）时，pf 封堵集与路由仍原地保持（故障关闭），但状态是 Disconnected：面板写"已断开（本地网络）"、开关为关，用户既被挡在网外、又找不到恢复入口。Helper 重启后按 pf-state 重装封堵集、却没有引擎时同理（§20.4 的无引擎恢复因此无 UI 入口）。新增 XPC 方法 getNetworkHeld（磁盘上存在 pf-state 或 route-state 即为真；App 侧 3 秒超时回落为假，老 Helper 维持旧表现）。App 在 Disconnected 时查询：为真则图标红空心、状态行"未连接，网络仍处拦截（断开即恢复本地网络）"、开关保持开，关掉走同一内联确认 → disconnect → 恢复。disconnect 回包后 App 重新取状态（无引擎恢复不推送）。
- Helper 崩溃被 launchd 拉起（XPC interruption）后，新守护进程重装封堵集但没有引擎，旧实现不重连，用户一直被挡。现在 interruption 2 秒后 App 重新接入；若中断前会话在进行（非手动断开）且 Helper 报 Disconnected，App 重发一次 Keychain 凭据。每次中断只一次，Helper 缺失（invalidation）不重试，不会形成静默循环。
- 通知授权改在启动时请求：旧实现在第一条通知要发时才请求，授权弹框与那条（掉线或等批准）通知赛跑。
验证级别：本机编译；getNetworkHeld 经 §20.1 的用户域 XPC 实测往返（无磁盘状态时为假）；App 侧行为（启动接入、红空心、Helper 重启重连）需签名构建 + Mac 实测（C1/C3、B1）。

### 20.10 分流模式现状：整条链未通，界面如实说明
走查结论：分流（"仅名单走 VPN"、应用/域名直连规则）在运行时从未生效，断点不止一处——① App 从未创建 NETransparentProxyManager 配置，代理扩展不会被系统加载；② 代理 startProxy 没调用 setTunnelNetworkSettings 声明 includedNetworkRules，透明代理只收它声明的流，即便被加载也一条流都收不到；③ 域名规则的另一条机制 dns_routes.rs（DNS 驱动的动态路由）没有任何调用方；④ 分发上，macOS 的 NE 提供者需付费开发者团队的 entitlement（Developer ID 分发须做成系统扩展），本机无开发者证书，无法装载验证。网段规则同理只在代理里判定，没有走 §4.1 设想的路由表。
本轮处理：②补上（声明全部出向 TCP、UDP，handleNewFlow 照旧只接直连流、其余返回 false 走系统路由）；活动泵表在 handleNewFlow 与各泵 onDone 两个队列上并发读写，加锁；规则引擎域名匹配改为大小写不敏感并忽略末尾点。①④属方向性取舍（要不要上付费账号 + 系统扩展），未擅自做；在此之前界面不再默认它生效：默认模式选择处与规则页显示"分流需要透明代理扩展，当前版本未启用：所有流量仍走 VPN"，规则仍可编辑保存、规则测试器照常可用（它只经 Helper 调 Rust 引擎判定，不依赖代理）。引擎已连接时保持封堵态（§20.7），与"所有流量走 VPN"一致。
验证级别：本机编译（Proxy 目标 swiftc 编过）；代理的加载、收流、泵出物理口全部需付费账号签名 + Mac 实测（D1）。

### 20.11 无开发者团队时的本机安装与救急恢复
SMAppService 只为正式签名的 App 注册守护进程，ad-hoc 构建用不了；而本机实测（Mac proof A/B/C）不能等付费账号。`scripts/dev-helper.sh`（root）以传统方式装同一个守护进程：Helper 拷为 root 所有的 /Library/PrivilegedHelperTools/com.alwaysconnect.app.helper，LaunchDaemon plist 声明同一 Mach 服务名（App 侧代码无需改动），日志写 /Library/Logs/AlwaysConnect/helper.log（目录 0700）。子命令：install、uninstall（先恢复网络再卸）、recover（只恢复本地网络：按 route-state 跑脚本 restore、清空 pf 锚点、删持有状态文件——真实实测出岔子时的退路）、status、log。
配套改动：守护进程把每次状态迁移与终态写入 stderr（带时间戳；只有引擎文案，无凭据、无子进程原文）；plist 设 ALWAYSCONNECT_DEBUG_CHILD_OUTPUT=1 时再把脱敏后的子进程输出写入日志——用来记录真实网关的等批准与拒绝文案（§16.5、Mac proof A3/F3 等的就是它），只在 dev 安装中打开。首次向导的"装 Helper"一步：Helper 已能经 XPC 回话即视为已装（不论经 SMAppService 还是 dev 安装）。
安全边界（明说）：未签名的 Helper 无团队标识，会接受同样无团队标识的任意本地客户端（§16.9 的开发态放行）；dev 安装只用于自己的机器，用完 uninstall，不与 SMAppService 安装并存（同一 label）。
验证级别：脚本语法检查 + 非 root 拒绝路径本机实跑；守护进程日志经用户域 XPC 实测可见；root 安装与恢复属 Mac proof（需用户 sudo）。

### 20.12 真实网关的首批观测（本机，2026-11-03，未登录）
以无凭据的 `openconnect --authenticate --non-inter` 只取登录表单（不提交任何凭据），并读本机 Cisco Secure Client 自己的界面历史（只取字段，不记地址），得到三条一手事实，按"不猜真实网关行为"的规矩记下、未据此改行为：
- 网关在 TLS 握手中请求客户端证书；不出示证书时，登录表单附带 "Certificate Validation Failure"，随后仍给出用户名/密码表单与 Group 选择（Staff 在列）。本机钥匙串里有公司 CA 签发、EKU 为 TLS 客户端认证的用户证书身份（Cisco 设置为 CertificateStoreMac All，自动从钥匙串取）。openconnect（GnuTLS）不能直接用 macOS 钥匙串里的身份，只能用证书文件或 PKCS#11。证书是否为必需、私钥能否导出，需用户带凭据实测一次才能定——这决定 CLI 路线在本机能否通过认证，是当前最大的未知。
- Cisco 客户端连接时的隧道模式：IPv4 为 Split Exclude（全隧道 + 网关下发的排除网段），IPv6 为 Drop All Traffic。本项目的全隧道、IPv6 只放行链路本地与之方向一致；网关下发的排除网段（CISCO_SPLIT_EXC）目前只记日志不执行，若实测发现被排除的目的地经隧道不通，再决定是否按网关策略放行（需同时改路由与 pf 放行，见 §20.4）。
- 数据通道协议为 DTLS 1.2（openconnect 同样支持）。

### 20.13 实测结论：网关强制客户端证书，钥匙串私钥不可导出（2026-11-03）
用户带账号跑 `scripts/probe-gateway.sh`（不建隧道）：网关在 TLS 握手与聚合认证 XML（`<client-cert-request>`）里两次要证书；openconnect 无证书回 `<client-cert-fail/>` 后，网关返回 error id 86 "Certificate Validation Failure"，表单里只剩 Group 下拉，**没有用户名/密码字段**——密码从未提交，手机未收到推送。即：没有证书，连密码这一步都到不了。隧道组配置回显 auth-method single-sign-on-v2。
本机钥匙串里公司 CA签发的用户证书身份共 4 个，经 Security 框架读私钥属性：全部 extractable=false、sensitive=true（MDM 下发，不可导出）。openconnect（GnuTLS）只能用证书文件或 PKCS#11，用不了钥匙串里不可导出的私钥，所以现行"Helper 以 root 直接跑 openconnect"的认证路径在本机走不通。可行方向（待用户定）：① 以 Cisco 自带 CLI（/opt/cisco/secureclient/bin/vpn，支持 `-s` 非交互）为隧道引擎，证书与协议交给 Cisco，本项目负责自动填凭据、断线重连、pf 封堵、局域网放行与界面；② 保留 openconnect，新增用户会话内常驻的证书代理（用钥匙串身份替 openconnect 做 TLS 客户端认证，openconnect 以 --resolve 指向本地代理、关 DTLS），并相应改造网关 IP 来源、路由与 pf 放行；③ 暂停。


## 二十一、Cisco 引擎（2026-11-03，用户选定方案 A）

§20.13 实测：公司网关强制出示钥匙串里不可导出私钥的用户证书，openconnect 过不了认证。用户在"借用 Cisco 连接 / 自建证书转接 / 暂停"三条路里选了 A：隧道交给本机已装的 Cisco Secure Client，AlwaysConnect 负责自动登录、断线重连、故障关闭、局域网放行与界面。openconnect 引擎（§十六–§二十）原样保留，用于不要求客户端证书的网关；Cisco CLI 存在时自动选 Cisco 引擎，无界面开关。

### 21.1 一手事实（2026-11-03 本机实测，不猜）
- CLI：/opt/cisco/secureclient/bin/vpn（5.0.03072），子命令 state / stats / connect / disconnect / hosts，`-s` 从 stdin 读应答。
- 同一时刻只能有一个 Cisco 客户端持有"连接能力"：GUI 程序开着时 CLI 报 "Connect capability is unavailable. Another Cisco Secure Client application acquired it."。GUI 随登录自启。
- 连接提示序列：`connect VPN-A` → "Please enter your username and password." → `Group: Staff` → `Username: [<预填账号>]` → 密码（`-s` 下从 stdin 取；CLI 同时向终端打印 "Password:"，那一行不用回答）→ 手机推送等待（无输出）→ `>> state: Connecting` 与若干 "Establishing VPN" 通知 → `>> state: Connected`。错密码：`>> Login error.`。证书由 Cisco 自动出示，CLI 路径无需任何证书配置。
- 连接后：默认路由经 utunN；`vpn stats` 给 Server Address、隧道模式（IPv4 Split Exclude，IPv6 Drop All Traffic）、Non-Secured Routes（本次 75 条，含 192.168.0.0/16——家里局域网本就由 Cisco 放行直连）；网关有经物理口的主机路由；协议 DTLS 1.2。
- `vpn disconnect` 由普通用户执行即可断开。

### 21.2 分工
- App（CiscoEngine，用户会话内，因为钥匙串证书只在用户会话可用）：以 Keychain 密码经 `vpn -s` 登录；每 4 秒 `vpn state` 监视；Connected → 报已连接并让 Helper 装连接态；Cisco 自己 Reconnecting → 报重连中并让 Helper 封网，不另起登录；会话丢失（Disconnected 且未手动断开）→ 封网、报重连中、按 1/2/5/10/30 秒（±20%）退避无限重新登录（每次重新登录都会触发一次手机推送）；`Login error` → 停住不重试（防锁号），掉线期间被拒则网络保持拦截（§20.9 的"网络仍处拦截"）；手动断开 → 立即终止进行中的登录、`vpn disconnect`、经 Helper 卸 pf。登录前若 Cisco GUI 在运行，礼貌请求其退出（terminate，不强杀）。App 重开或打开面板时若 Cisco 已连着，直接接管。
- Helper（root）：新增 XPC 方法 setKillSwitch(mode, tunnelIf, gatewayIps)（App 侧 3 秒超时回落为面板红字"Helper 未响应：断线封网未生效"）。mode 1 连接态：物理口出向放行（Cisco 按公司策略让 75 个排除网段走物理口，连着时封它们就坏了），并起看门狗——每 2 秒查隧道口，消失即自行转封堵态，App 不在也生效；mode 2 封堵态：隧道口、lo0、DHCP、网关（stats 的 Server Address + 网关主机名解析出的全部 IP）、放行网段、mDNS、fe80 之外一律挡，另放行 DNS（端口 53：重新登录要解析网关主机名，办公网的解析器不在放行网段里；只漏查询、不漏流量）；mode 0 卸载。物理口取路由表里通往网关的接口。与 openconnect 引擎共用锚点、pf-state 文件（新增 allowDNS 字段）、守护进程启动重装与 getNetworkHeld，因此 Helper 重启后照样故障关闭，App 重连后重新下发。
- Helper 引擎状态在 Cisco 模式下被忽略（它的推送只用来证明 Helper 在线）；重连次数与终态原因来自 CiscoEngine。

### 21.3 已知限制与待验证
- 依赖本机 Cisco Secure Client（vpnagentd 后台服务 + CLI）一直安装；Cisco GUI 不能同时开着。
- 会话丢失后的每次重新登录都需要在手机上批准；用户不在时批准会超时，网关表现已实测为 `Login failed`（区别于错密码的 `Login error`），引擎按 §21.19 自动重新发起。
- 连接态期间不封物理口（与 Cisco 自身行为一致）；断线的封堵延迟上限约 2 秒（Helper 看门狗）或 4 秒（App 监视）。
- 分流（透明代理）仍按 §20.10 未启用；Cisco 自身的 Split Exclude 照常生效。

### 21.4 验证级别
- 引擎逻辑：`scripts/cisco-engine-test.sh` 把 CiscoEngine.swift 与 `core/scripts/fake-cisco-vpn.sh`（按 21.1 的真实输出形状仿写）一起编译运行，断言 6 个场景：登录 → 等批准 → 连上 → 下发连接态；断线 → 封网 → 自动重新登录 → 恢复；手动断开；被拒不重试；暂时性失败按退避重试；接管已连会话。已进 CI 与 local-checks。
- Helper：setKillSwitch 经用户域 XPC 实测往返（非 root 时 pf 装载失败并如实回报，mode 0 成功）；`generate-pf --allow-dns` 输出经 `pfctl -n` 解析通过（CI 与 local-checks）。
- 真实 Cisco 连接、断线封网、手动断开恢复、Helper 看门狗：需 dev Helper（sudo）+ 用户在场实测（mac-proof 清单 H 节）。

### 21.5 退出 = 不开 VPN、直连网络、进程全回收（用户定，2026-11-03）
用户从实际使用出发纠正了"退出只关菜单、VPN 留在后台"的旧语义（§18.1/§20.1 的"App 退出不影响隧道"）：没有界面却仍在跑的 VPN 不符合直觉，断线时还会把人困在"突然没网"里。现在：任何退出路径（面板 [退出 AlwaysConnect]、设置窗口 ⌘Q、注销）都经 applicationShouldTerminate 先断开 VPN（Cisco `vpn disconnect` / openconnect 引擎手动停）并经 Helper 恢复直连网络，再断开 XPC 连接后退出；连着时面板先内联确认"退出会断开 VPN，网络恢复直连"；Helper 15 秒不回包也照样退出。Helper 守护进程在"无 App 连接、无会话、杀开关关闭、无持有状态"连续两次检查（15 秒一次）后自行 exit(0)；launchd plist 的 KeepAlive 改为 {SuccessfulExit: false}——只在崩溃后重启，空闲退出后由 MachServices 按需拉起；RunAtLoad 保留，用于开机时按 pf-state 重装封堵集（有持有状态就不会空闲退出）。Cisco 自己的 vpnagentd 不归本项目管。
只有非本意的崩溃保持故障关闭：App 崩溃时 Helper 维持当时的杀开关（Cisco 引擎下看门狗照常），重开 App 即接管并给出恢复入口。§20.1 的"会话归守护进程、不随 XPC 连接消亡"仍成立（它防的是崩溃与重连），只是用户主动退出时由 App 显式断开。

### 21.6 断线保护开关与批准推送限频（用户定）
- 用户要求在界面上给"断线保护"（掉线不漏网）一个开关。设置 → 通用，默认开；仅在 Cisco 引擎下显示（openconnect 引擎的路由持有与 pf 不受它控制，显示一个不起作用的开关是假控件）。关：App 给 Helper 的杀开关请求一律映射为 0（pf 不装），断线后流量走本地网络，面板写"已断开，正在重连（断线保护已关，流量走本地网络）"；切换即时生效（rearm 或卸载）。这取代了 §18.8 里"pf 关闭开关需单独安全设计、不做"的决定：用户明确要这个开关，说明文字讲清开与关的后果。
- 面板在重连中、等批准、网络仍拦截时给 [恢复正常网络（断开 VPN）]：任何时候一键回到直连，不会被断线保护困住。
- 批准推送限频：一次登录若已走到提交密码（手机被推送过）仍失败，下次重试按 30/60/120/300 秒（±20%）退避，封顶 5 分钟；未到密码就失败（网关不可达等）仍按 1/2/5/10/30 秒。连上后两条退避都清零。Login error 仍是停住不重试。

### 21.7 设置与向导按用户视角精简（用户定）
- 开机自动打开 App 默认关（用户定，从不自动注册登录项）；"打开 App 时自动连接 VPN"保留默认开——打开即连、退出即断，对称。
- 设置窗口四页：通用（自动连接、断线保护、开机打开、通知、快捷键）/ 账号（服务器为下拉：本机 Cisco 配置里的条目 + "其他…"手填地址）/ 网络（家里局域网状态与开启引导、断线保护期间仍可访问的网段）/ 诊断（含原统计）。规则页在分流未生效期间不显示（§20.10），代码保留；分流模式不再提供选择，向导完成时固定为全部走 VPN。
- 家里局域网：Cisco 引擎下连着 VPN 时能否访问 192.168 取决于 Cisco 的"Allow local (LAN) access"用户偏好（公司配置 LocalLanAccess UserControllable=true、默认关；用户反馈此前在家访问不了 192.168）。App 读取 Cisco 写在 ~/.anyconnect 的偏好显示已开/未开，未开时给一次性开启步骤与 [打开 Cisco]；不替用户改 Cisco 的偏好文件（格式非我方所有，不猜）。向导第四步由"选模式"改为这一步，可跳过。
- 验证级别：本机编译与启动；引擎 harness 7 个场景（新增"已推送后失败按长退避"）；Helper 空闲退出与 KeepAlive 语义、退出断开、偏好检测需 dev Helper + 用户实测（mac-proof H 节）。

### 21.8 后台服务的安装集成进 App（用户反馈："为啥每次都要我执行命令"）
没有开发者团队签名的构建用不了 SMAppService（§20.11），此前只能让用户在终端跑 `sudo scripts/dev-helper.sh install`，而且装好后向导不会自己发现（它只查 SMAppService 状态），看起来像"没反应"。现在：
- 构建把 scripts/dev-helper.sh 放进 App 包的 Contents/Resources；无团队签名时，[安装后台服务] 经 NSAppleScript `do shell script … with administrator privileges` 以 root 运行包内脚本、安装包内的 Helper，用户看到的是 macOS 标准的管理员密码框（取消即"已取消：需要输入电脑密码才能安装"）。有团队签名时仍走 SMAppService。
- 向导"安装后台服务"一步每 2 秒向 Helper 取一次状态，并在 App 回到前台时也取，后台服务一旦在跑就显示"✓ 后台服务已在运行，可以点「下一步」"，无论它是怎么装上的。
- 本机自建版本重新构建后，若已装的 Helper 与包内的不一致，面板显示"后台服务有新版本" [更新]（同一密码框）。
- 验证级别：本机编译；AppleScript 拼装经非 root 子命令（status）实跑通过；管理员密码框安装与更新需用户实测。终端脚本保留，作为 recover/uninstall 的救急入口。

### 21.9 真实连接跑通后的第一轮用户反馈（2026-11-03）
用户经 App 完成首次真实连接（Cisco 引擎，面板"已连接 · VPN-A（经 Cisco）"；Helper 报 getNetworkHeld = true，即杀开关已以连接态装上）。随后的反馈与处理：
- "家里局域网"误报未开启：Cisco Secure Client 5 把用户偏好存在机器级的 /opt/cisco/secureclient/vpn/.anyconnect_global（实测其中 LocalLanAccess = true），§21.7 只读了旧版的 ~/.anyconnect。现在依次读 .anyconnect_global、~/.anyconnect、旧版 /opt/cisco/anyconnect/.anyconnect_global。由此也排除了"开关没开"这一原因：用户此前在家访问 192.168 失败另有原因。诊断页新增"测试访问本地路由器"（App 内、无需 root）：对每个物理口的 DHCP 路由器，报告路由表把它交给哪个接口、ping 或 80/443/53 端口能否连通，供下次在家复现时取证，不猜原因。
- 面板看不出 VPN 开没开：弹出面板里 macOS 小开关开与关几乎同色。面板顶部改为大号彩色状态（图标 + 标题 + 一行说明），下方一个写明动作的按钮："连接 VPN"/"断开 VPN"（连着时内联确认）/"取消连接"/红色态"断开 VPN，恢复直连网络"（不确认，一键回直连）。原小开关与单独的恢复按钮取消。
- 图标难看：圆点换成盾牌一族（StatusLook，菜单栏与面板共用）：已连接 checkmark.shield.fill 绿；连接中 shield.lefthalf.fill 黄；等批准 iphone.radiowaves.left.and.right 黄（提示去看手机）；断线拦截/网络仍暂停 exclamationmark.shield.fill 红；未连接 shield.slash 灰。形状与颜色双编码。
- 切屏后图标消失：本机为带刘海的内建屏 + 外接屏；刘海屏上状态栏图标只能放在刘海右侧，与前台程序溢出的菜单共用空间，最新加入（最靠左）的状态项最先被系统隐藏，切到另一块屏常伴随前台程序切换。处理：状态项改为方形定宽；首次启动时把它的首选位置设在靠右（与电池、Wi-Fi 相邻，NSStatusItem Preferred Position），用户 ⌘ 拖动后以用户位置为准。是否根治需用户在双屏下复看（若其他图标也一起消失，则是系统菜单栏行为，非本 App 可控）。
- 验证级别：本机编译与启动；本地局域网检测与路由器测试本机实跑（办公网路由器 ping 不回、80/443/53 之一可连）；图标与面板外观、切屏表现需用户目测。

### 21.10 首次真实断线测试：重连被自家封网挡住、断开迟迟无反应（已修）
用户以 `vpn disconnect` 模拟断线：面板正确转红（断线保护生效），但自动重连卡在"第 1 次"，点"断开 VPN，恢复直连网络"也迟迟没反应。原因与修法：
- 网关域名解析出不止一个地址（本机实测两个），而封堵集只放行了连接时 `vpn stats` 的 Server Address 与当时（经隧道 DNS）解析到的地址；Cisco 重新登录时选了另一个地址（或备用网关），被我们自己的 pf 挡住。现在放行"当前会话的 Server Address + 本机 Cisco 配置里所有网关主机名解析出的全部地址 + 之前放行过的地址"，并在掉线期每次重新登录前经封堵集放行的 DNS 重新解析、重下发封堵集。
- 断开要等引擎队列里那次被挡住的登录结束（CLI 可能等上很久），用户看到的就是"没反应"。现在点断开立即：界面先显示"正在断开…"、经 Helper 先卸 pf 恢复直连，再在后台终止登录与 `vpn disconnect`，结束后再卸一次以防中途重装。
- App 新增统一日志（subsystem com.alwaysconnect.app，category cisco）：状态迁移、杀开关下发、Cisco 的 state/notice/error 行（不含密码，Cisco 本就不回显），以后实测失败可直接取证：`log show --last 30m --predicate 'subsystem == "com.alwaysconnect.app"'`。
- 图标改为代码绘制的 GlobeIcon（地球 + 状态角标，造型见 §34.4 与 UI-DESIGN §App 图标）：已连接 = 地球 + 绿锁；连接中/等批准 = 地球 + 黄色省略号；掉线拦截/网络仍暂停 = 地球 + 红色感叹号；未连接 = 半透明地球无角标。菜单栏与面板头部共用，随浅色/深色菜单栏自动适配（预览图本机渲染核对）。
- 验证级别：本机编译、引擎 harness、local-checks 全绿；重连放行与即时断开需用户再做一次断线实测（mac-proof H2/H3）。

### 21.11 设置窗口与面板的视觉重做（用户："太挫了，比例都不对"）
第一版设置页把控件直接堆在窗口中部（上下大片留白）、标签与输入框不对齐、说明文字又长又散。重做为 macOS「系统设置」式的分组表单（Form + .formStyle(.grouped)）：每组一张圆角卡片，标签在左、开关/输入在右，卡片下一行简短脚注；窗口固定 620×560，四页（通用/账号/网络/诊断）带图标标签。账号页：服务器下拉 + 实际地址 + Group 一组，用户名/密码一组，[保存]（默认按钮）与 [保存并连接] 一组并显示当前状态；网络页：家里局域网状态卡（绿勾/橙色提醒 + 一次性开启步骤）与"断线时仍可访问的网段"列表（行尾红色删除、末行添加）；诊断页合并原统计：当前连接（状态、时长、流量 + 刷新）、掉线记录（原为最近 8 次，§21.21 起列出全部已存记录并可删除）、自检（泄漏自检、访问本地路由器）、诊断包导出。面板：头部不变，下方一行图标化信息（服务器、断线保护开/关、上次掉线），底部一行安静的工具按钮（设置 / 诊断包 / 退出），去掉长提示文字。首次向导：欢迎页（大图标 + 三条要点）、后台服务卡片、账号表单、家里局域网卡片，底部统一的步骤圆点 + 上一步/下一步。
验证级别：离屏渲染（NSHostingView 置于离屏窗口、CALayer 渲染成 PNG，无需屏幕录制权限）逐页核对布局；离屏渲染下窗口非活跃，强调色按钮显示为灰色，实际窗口中为蓝色。

### 21.12 反复弹出的钥匙串密码框
用户反馈授权/密码框弹了好几次。来源有二：① App 读钥匙串里的 VPN 密码——面板每次打开都调用 hasCredentials，它用 SecItemCopyMatching 取了密码数据；本机自建版本为 ad-hoc 签名，每次重新编译代码身份都变，系统按"新程序"再次要求授权。② Cisco 命令行使用登录钥匙串里的公司证书私钥——钥匙串会问"vpn 想使用密钥"，需用户选"始终允许"一次（Cisco 的 CLI 签名稳定，选一次即长期有效）。修法（针对①）：新增 KeychainStore.exists（只取属性、不取数据，不触发授权），所有"有没有存密码"的判断改用它；真正读密码只在连接时，经 HelperClient.storedPassword 每次运行每个账号最多读一次并缓存在内存（掉线期的重登录不再读钥匙串），编辑账号即清缓存。仍会出现的情形：每次重新编译后的首次连接一次（选"始终允许"后本次构建不再问），本地构建的这一次已由 §21.15 消除；带团队签名的正式构建身份稳定，不会因更新反复询问。

### 21.13 面板放常用开关、服务器可增删改、设置窗口到最前（用户反馈）
- 点"设置"后设置窗口出现在其他程序后面：菜单栏（LSUIElement）程序被点状态项时并不处于活跃状态，单纯 makeKeyAndOrderFront 不会越过前台程序。现在打开设置（及首次向导）前先 NSApp.activate，再 makeKeyAndOrderFront + orderFrontRegardless，并先收起面板；设置窗口带标题"AlwaysConnect 设置"，可指定打开的页签（"管理服务器…"直达账号页）。
- 常用功能进面板：状态与主按钮下方一张小卡片——"服务器"下拉（列出全部服务器，选中即切换；连着时先断开再连新服务器）+ 管理服务器…；"断线保护"开关（仅 Cisco 引擎显示，即时生效）。
- 服务器增删改：Profile 新增 servers（ServerEntry：名称、地址、来自 Cisco 配置时的条目名）。首次使用时从本机 Cisco 配置导入（VPN-A、VPN-B、VPN-C、VPN-D），且总包含当前所选服务器（老配置原样带过来）。账号页"服务器"卡：圆圈选用、铅笔就地编辑名称/地址、红色减号删除（至少保留一台）、末行"添加服务器"。来自 Cisco 的条目按 Cisco 条目名连接（Cisco 套用自己的按主机设置与证书）并带"Cisco"小标；手改地址后变为普通条目、按地址连接。手加服务器的地址也纳入断线封网的网关放行。
- 密码改为按账号存（钥匙串 server 键固定为 "account"），所有服务器共用，切换服务器不用重输；旧版按服务器存的条目在首次读取时迁移过来。
- Profile 解码改为逐字段 decodeIfPresent：此前文档称"合成 Codable 对缺失键回落默认值"不成立（合成实现会抛错，整个配置会被静默重置成默认），新增字段时老配置因此不会丢。
- 验证级别：本机编译、local-checks 全绿、离屏渲染核对面板与账号页；切换服务器重连、窗口置前需用户目测/实测。

### 21.14 开关"开着却是灰的"：统一的开关样式 + 面板激活
用户两次反馈开关打开了颜色却不对。原因：系统开关（及强调色按钮、菜单）在非活跃窗口中一律画成灰色；菜单栏程序点开状态项时并不处于活跃状态，面板窗口不是 key，于是"断线保护"开着也显示为灰。修法两层：① 全 App 只用一个自绘开关样式 AlwaysSwitchStyle（开 = 强调色轨道、关 = 灰色轨道，不随窗口活跃与否变化；带无障碍值与动作），在面板、设置窗口、首次向导的根视图统一应用，不再逐个修；② 弹出面板前 NSApp.activate、弹出后让面板窗口成为 key，使其余原生控件（主按钮等）也以活跃颜色绘制。验证级别：离屏渲染（非活跃窗口）下开关已呈强调色；面板实际颜色需用户目测。

### 21.15 本地构建换成固定签名身份："始终允许"不再因重新编译失效
用户反馈点了多次"始终允许"仍弹"AlwaysConnect 想使用钥匙串中的 com.alwaysconnect.app"。原因：build-local.sh 默认 ad-hoc 签名，其指定要求（designated requirement）就是二进制的 cdhash；钥匙串条目的访问控制按这条要求记住"始终允许"的程序，重新编译后 cdhash 变了，系统当作新程序再问一次，开发期一天多次重编就一天多次弹窗。修法：`scripts/dev-signing-identity.sh` 一次性生成自签代码签名证书"AlwaysConnect Local Dev"（私钥进 login 钥匙串，仅授权 /usr/bin/codesign 使用），build-local.sh 发现该身份即用它签名（显式 SIGN_IDENTITY 优先，没有身份仍回到 ad-hoc）。指定要求变为 identifier + certificate leaf，跨构建不变：换签名后的第一次连接再选一次"始终允许"，此后重编不再询问。证书没有团队标识，Helper 的同团队校验与 HelperInstaller 的走向与 ad-hoc 构建完全相同。
验证级别：临时钥匙串 + 禁止交互读取的探针程序实测——ad-hoc 签名的探针重编后读取被拒（errSecAuthFailed，交互模式下即弹窗），自签身份签名的探针重编后仍直接读到；build-local.sh 实测产物的指定要求为 identifier + certificate leaf。

### 21.16 清理钥匙串里的"脏"签名记录（用户问"脏的签名要不要清理"）
实查登录钥匙串（只读属性、不取密码）：AlwaysConnect 有两条密码记录——旧的按服务器存（用户名@VPN-A，§21.13 后已不用）与现用的按账号存；每条的访问列表里堆着历次 ad-hoc 构建的"始终允许"条目，分区列表里是对应的一串 cdhash，换成固定签名（§21.15）后全部失效。另有一个重复的本地签名证书（本 Thread 中途建过，已删），现只留在用的"AlwaysConnect Local Dev"。
清理交给 App 自动完成：固定签名下第一次成功读到密码时（即用户最后一次点"始终允许"那次），先把密码写入临时账号的新条目（新条目的访问列表只有当前签名），再删旧条目、把新条目改名为正式账号；改名失败则直接重写正式条目再删临时条目——任何一步失败，密码都仍存在能被找到的位置。随后删除服务器列表里各服务器的旧按服务器条目。按签名证书哈希记一次标记，同一签名不重复做；ad-hoc 构建没有稳定签名，不做。验证级别：本机编译；实际清理在用户下次连接时发生，可用 `security dump-keychain -a` 查看访问列表只剩一个条目。

### 21.17 断线保护到底验证到哪一步（用户问"验证过了吗"）
如实分级：
- 已在本机真实验证：连上后杀开关以连接态装上（Helper getNetworkHeld = 真）；首次真实断线时面板转红，且 pf 封堵确实生效——证据是它挡住了 Cisco 重连要用的另一个网关地址（§21.10 的问题正由此暴露）。
- 尝试过但测不出：VPN 连着时把杀开关临时切到封堵态、从 en0 绑定发包探测——连接态与封堵态结果相同（物理口出向都被挡、DNS 与网关放行）。原因是 Cisco 连接期间自己的过滤器就挡住所有不走隧道的流量，探测分不出是谁挡的；只有 Cisco 会话真正断开后，挡流量的才是我们的 pf。
- 尚未验证：会话丢失后普通上网被挡住（逐秒实测）、修复后的自动重连、App 不在时 Helper 看门狗自行封网。
为此：泄漏自检在 Cisco 引擎下改用杀开关记录的隧道口与网关（此前没有引擎即一律"未连接"），并新增"pf 已开启"一项、锚点项注明当前是连接态还是封堵态；App 日志改为 notice 级（info 级不落盘，上次失败时无日志可查）；新增 `scripts/drop-test.sh`：在已连接、App 运行时丢弃 Cisco 会话，每 3 秒测一次默认路由上网（应失败）、系统 DNS（应可用）、本地路由器（应可达），直到用户批准后重新连上或 150 秒超时（超时则让 App 正常退出以恢复直连），最后给出"有无泄漏、封了多久、多久重连"。需用户在场批准一次推送。
- 2026-11-03 真实断线实测（`scripts/drop-test.sh`，用户在场）：基线 已连接、上网 200、DNS 正常、本地路由器可达；丢弃 Cisco 会话后两次探测均为 Cisco 已断开、默认路由上网失败（000）、DNS 正常、本地路由器可达；用户批准推送后第 25 秒重新连上、上网恢复 200。结论：会话丢失期间无一次网页请求经本地网络出去（NO LEAK），DNS 与局域网按设计放行，§21.10 修复后的自动重新登录成功。泄漏自检同时实跑：默认路由经隧道 ✓、锚点 6 条规则（连接态）✓、pf 已开启 ✓。泄漏自检的"网关经物理口直连"此前把放行表里所有备用网关都算进去而误报 ✗，现只判当前会话的服务器。未验证：App 不在时 Helper 看门狗自行封网（mac-proof H4）；App 统一日志在本机 `log show` 中查不到条目（原因待查），断线排查暂以 drop-test 输出与泄漏自检为证。


### 21.18 Cisco 会话流量与自检误报修复

Cisco 模式的流量不再调用 Helper 的 getStats：该方法只认识 Helper 自己的
openconnect 引擎，因此 Cisco 已连接时也回空接口。App 在后台线程执行只读
`vpn stats`（8 秒超时；本机正常执行约 3 秒），严格读取 `Connection State: Connected`、
`Bytes Received`（下行）与 `Bytes Sent`（上行），使用非负 Int64；字段缺失、
格式错误或已断开均不显示旧计数。隧道口仍按 Cisco 引擎既有的默认路由探测确认。
这是 Cisco 报告的本次会话累计字节，不含直连流量，也不受断线保护开关或 Helper
版本影响。OpenConnect 仍走原 getStats XPC 与 3 秒回落，协议签名不变。

诊断页打开时和连接状态变化时采样，手动刷新再次采样，无后台流量轮询。
读取中、未连接、读取失败均显示具体状态；连接状态变化时清除旧流量与旧自检，
用请求标识忽略迟到的流量结果。泄漏自检沿用 §21.17 的当前会话服务器判定；
安装的旧 Helper 仍可能检查全部备用网关，须更新后台服务才能生效。

验证：`scripts/cisco-traffic-test.sh` 覆盖上下行对应、超过 32 位、零流量、
断开后残留计数、缺失/非法/负数/溢出；纳入 macOS CI 与 local-checks。
本机 swiftc 四目标构建、41 项 Rust 测试及 local-checks 全通过。真实会话中已确认
诊断页流量显示、手动刷新后计数更新；用户更新后台服务后核对安装产物一致，
重新自检的默认路由、pf 锚点、pf 开启、当前网关物理口四项均绿，原红项消失。
DNS 仍为灰色信息项，不判通过。截图保留在本地构建目录，不提交实际网络信息；
远端 CI 以 GitHub Actions 对应提交的两路结果为准。以上不替代真实断线验证。

### 21.19 审批超时：实测文案与重试策略
用户在场实测（`scripts/probe-cisco.sh`，故意不点手机批准）：推送过期后 Cisco CLI 打印 `>> Login failed.`；此前密码错误的实测打印 `>> Login error.`。两者可区分。旧逻辑把两者都当"凭据被拒"而停住，意味着用户不在手机旁时，一次没点的批准就让"无限重连"终止（断线期间还会一直封网等人回来）。
现在：`Login error` 照旧立即停住（防锁号）；`Login failed` 且距提交密码已超过 20 秒（过期的批准不可能在提交后瞬间返回，瞬间的 `Login failed` 仍按被拒处理）视为"批准已超时"，按 30/60/120/300 秒（±20%）重新发起，状态行写"手机上的批准已超时，N 后重新发起批准"，每次重新发起都会再推一条"请在手机上批准"的通知；自第一次未批准起满 1 小时，间隔放慢为 15 分钟一次，避免整夜推送。连上、手动断开或重新连接即清零。验证级别：超时与错密码的文案为真实网关实测；重试与限频逻辑由 Cisco 引擎 harness 断言（新增"批准过期 → 重新发起、不终止"与"瞬间 Login failed → 按被拒停住"两个场景）；长时间无人批准下的真实表现属 mac-proof H5。

### 21.20 启动时不再弹出设置窗口（用户："启动时不要默认打开设置页"）
现象：App 一启动设置窗口就在屏幕上。代码里启动路径本身不开设置窗口（首次使用、还没存用户名时才弹向导），唯一的入口是"App 已在运行时再次打开它 → 弹设置窗口"这条兜底（菜单栏图标被挤掉时的入口，UI-DESIGN §一.10）。
本机日志实测（2026-11-04）：那次启动在 90 毫秒内有三次 `open`，系统只启动一个 App，把后两次当成"再次打开"事件送进来，于是设置窗口在启动瞬间弹出；用最小探针 App 复现了同样的"一次启动 + 两次再次打开"。连点、登录项启动时又点一下、脚本重复启动都会这样。
现在：启动后 5 秒内收到的"再次打开"视为同一次启动的一部分，直接忽略；5 秒之后再打开 App 仍弹设置窗口（兜底入口不变）。首次使用的向导保留（没存凭据时没有别的途径完成配置）。
验证级别：根因为本机日志 + 探针实测；修复后用同结构探针重复"三次 open"确认不再弹窗；真实 App 上的启动表现需实测（mac-proof）。

### 21.21 掉线记录：写明最多存几次，支持删除（用户："最多保存几个啊？我都看不懂"）
原来有三个对不上的数：存最近 50 次、诊断页只列最近 8 次、标题"共 N 次"是本次运行内存里的条数（可超过 50，重启后又变回最多 50）。用户看不出到底存了多少、上限是多少。
现在统一为一个数 `ProfileStore.dropHistoryLimit = 20`：存储、内存列表与诊断页都按它截取（新掉线追加时就截，不再等重启），诊断页列出全部已存记录。标题写"掉线记录（已存 N 次，最多存 20 次）"，脚注说明"超过 20 次时自动删掉最早的一条"。每行行尾红色删除按钮删单条，标题右侧"清空"经确认框删全部；删除后面板"上次掉线"跟着变成剩下的最新一条（全删则不显示）。旧版存的超过 20 条的历史在首次读取时只留最近 20 条。诊断包里的掉线历史即已存记录。
验证级别：本机 build-local 编译与断言全过（App 层无单元测试）；诊断页离屏渲染核对了标题、行尾删除按钮、"清空"与脚注的布局。2026-11-04 在用户 Mac 上不启动 App（当时 App 设为自建连接 + 启动自动连接，启动会与正在使用的 Cisco 连接抢路由），用临时小程序链接真实 App 代码、读写真实 App Groups 存储（先备份、测完原样写回并核对一致）：存 25 条读回 20 条且为最新 20 条；HelperClient 载入 20 条、"上次掉线"为最新一条；删最新一条后内存与存储均为 19 条、"上次掉线"变为次新；删中间一条正确；清空后内存与存储均为空、"上次掉线"为空；三种状态离屏渲染正确（空时"清空"置灰）。尚未实测：真实运行的 App 里点按钮、确认框弹出与面板实际刷新（mac-proof D6）。

### 21.22 掉线记录写清"怎么断的、怎么好的"，只存 10 条（用户："保存最多 10 个就够了……现在这里任何关键信息都没有"）
§21.21 之后每条记录仍只有"几点掉线、几秒后恢复"，而且只记最后连回来的掉线：重连中被拒、用户中途断开、退出 App 的掉线根本不进记录。用户要看的是这次断了多久、重试了几次、最后好了没有。
现在（`Sources/App/DropHistory.swift`，只依赖 Foundation）：
- 一次掉线 = 从已连接进入重连开始，到下面四种结局之一结束：连回来（已恢复）、引擎停止重试（没恢复）、用户在重连中点了断开（你断开了）、重连中退出 App（退出了 App）。`DropEpisodeTracker` 跟随 HelperClient 的状态流判定开始与结束；重复推送同一状态不会重复计数。顺带修了旧逻辑的漏记：重连途中经过"等手机批准"再连上时，旧代码要求上一状态必须是 reconnecting，这类掉线不记。
- 每条记下：断了多久、重新登录次数（Cisco 引擎与后台服务 openconnect 引擎各自的 episodeRetries，自建连接的次数经 getSessionInfo 异步到达，取过程中的最大值；0 表示连接自己续上了）、等手机批准的次数、走 Cisco 还是自建连接、没恢复时的原因（引擎在"已断开"之后报的终止原因：2 = 账号或密码被拒绝，3 = 重试次数用完；1 = 手动停止，归为"你断开了"）。
- 新字段都是可选，旧记录照常解码，显示"断了 N 秒后恢复（旧记录，没有重试详情）"。
- 上限改为 `ProfileStore.dropHistoryLimit = 10`。诊断页每条两行：时间 + 连接方式，下面一句话（如"断了 37 秒，重新登录 2 次后恢复；其中 1 次等你在手机上批准"），行尾彩色结果（已恢复绿、没恢复红、你断开了 / 退出了 App 灰）+ 删除按钮。面板"上次掉线"一行同样写结果与次数，诊断包每条带结果与这句话。
验证级别：`scripts/drop-history-test.sh`（CI 与 local-checks）断言过程判定、四种结局、终止原因、旧记录解码与显示文案；本机 build-local 全过；诊断页用 5 条样例记录离屏渲染核对（临时小程序，真实 App Groups 存储先备份、测完逐字节还原）。真实掉线时 App 实际记下的次数与结局需实测（mac-proof D6）。

## 二十二、后续方向：自定义"哪些域名不走 VPN"（方案 B，待做）

### 22.1 问题
用户希望自己配置一份域名名单（例如 `*.example.com`），名单内流量不走公司 VPN。当前做不到，原因是 Cisco 引擎的结构性限制（§二十一）：本机公司网关强制出示钥匙串中不可导出私钥的公司证书（§20.13），现有已跑通的真实认证路径是 Cisco Secure Client，所以隧道由 Cisco 承担；Cisco 连接期间由它自己的过滤器执行公司下发的 Split Exclude 名单，名单外凡是不走隧道的流量都被挡掉（2026-11-03 实测：连接态下从物理口直出的 HTTPS 一律失败，与我们 pf 的放行与否无关），并会检测、还原路由表改动。在 Cisco 引擎下实现自定义域名直连，只能靠破坏这道公司装的管控，本项目不做。
现有的合规途径：请公司 IT 在网关上配置 Cisco 原生的按域名排除（Dynamic Tunnel Exclusion，连接信息里该项目前为 None），配好后无需改动本 App 即生效。

### 22.2 方案 B：自建连接，由 AlwaysConnect 掌握路由
不经 Cisco，回到 openconnect 引擎（§十六–§二十，已实现并在 CI 与本机 harness 验证），补上两块：
1. **证书转接**：用户会话内常驻一个小服务（LaunchAgent，因钥匙串身份只在用户会话可用），用钥匙串里的公司证书身份（SecIdentity，私钥不出钥匙串、只做签名）与网关完成 TLS 双向认证；openconnect 以 `--resolve <网关主机>:127.0.0.1` 连到这个本地服务、以 `--servercert` 钉住本地服务的自签证书，由它把字节转发到真实网关。数据通道走 TLS（`--no-dtls`）。连带改动：网关真实 IP 由转接服务回报给引擎，用于 vpnc-script 的主机路由与 pf 放行（不能再用 openconnect 看到的 127.0.0.1）。
2. **按域名分流**：引擎接收用户名单，走 DNS 触发的动态路由——名单域名解析出的地址加经物理网关的主机路由、并加入 pf 放行（core/src/dns_routes.rs 已有骨架，当前无调用方，§20.10）；或在付费开发者账号到位后用透明代理（§十七）。名单与规则页 UI（RulesPage，当前隐藏）复用。
风险与前提：网关是否接受经转接的会话、聚合认证里的证书二次请求能否由转接层应答、单点登录类表单（隧道组回显 single-sign-on-v2）是否出现，均需实测；不使用公司官方客户端连接公司 VPN 可能不符合公司 IT 规定，动手前需用户确认（2026-11-04 用户确认：已向公司 IT 核实，允许）。工作量明显大于此前各批，属独立里程碑。

### 22.3–22.14 可行性验证摘要（2026-11-03 至 11-04；验证用的一次性 PoC 脚本与报告未进公开仓库）

方案 B 先用独立于 App 的一次性 PoC 验证，结论如下，产品实现见 §二十三、§二十六：
- 证书转接可行：OpenConnect 经本机转接、以钥匙串身份（SecIdentity，私钥不可导出、只做签名）与真实网关完成双向 TLS；
  本地一段也要双向 TLS（OpenConnect 出示临时客户端证书），否则网关的二次证书请求会让 OpenConnect 回 `client-cert-fail`。
  真实账号认证成功，手机确认登录照常出现（真实 Mac + 真实网关）。
- 两段 TLS 与 STRAP 不兼容：OpenConnect 9.21 的 `append_strap_verify` 用当前 TLS 的通道绑定数据签名，两段 TLS 下网关回 401；
  改用 `--no-external-auth`（原生认证）后真实隧道建立成功。依据：
  [gnutls.c:3189](https://gitlab.com/openconnect/openconnect/-/blob/v9.21/gnutls.c#L3189)、
  [cstp.c:257](https://gitlab.com/openconnect/openconnect/-/blob/v9.21/cstp.c#L257)、
  [auth.c:1499](https://gitlab.com/openconnect/openconnect/-/blob/v9.21/auth.c#L1499)。
- 网关域名解析出两个轮换的 IPv4 地址：一次会话要固定一个地址并保留原主机名校验（§30.0）。
- CSTP 包边界：OpenConnect 按 TLS 记录检查完整 CSTP 包，两段 TLS 会改变记录边界；转接在 CONNECT 成功后必须按包重组、
  每包完整发送（本机回环对照：关闭重组时双向错位）。修正后真实隧道内 HTTPS 正常。
- Cookie 只从 CSTP 请求头取、留在内存；强制结束 OpenConnect 后用它重建隧道成功，期间绑定隧道的请求失败、不回落物理口。
- DNS：隧道下发的第一台 DNS 的 UDP 查询会超时，TCP 与第二台正常；解析必须支持换服务器与 TCP 回退（§26.5 的转发器已做）。
- 按应用、按单条连接分流在没有 Apple 开发者签名时只能借第三方用户态分流核心实现，复杂、要全机接管路由；
  架构审查后放弃（docs/architecture-review-2026-11-05.md），只保留按域名分流（§二十六）。

## 二十三、自建连接：App 内证书转接（分流接入第 1 批，2026-11-04）

按用户确认的分批计划（后由方案二取代，见 docs/split-plan-v2.md），本批只做"自建连接"本身：
不经 Cisco，由 AlwaysConnect 自己连公司网关，全部流量走 VPN，**还没有分流**；App 不宣称支持分流。
"经 Cisco 连接"仍是默认方式，行为不变。用户已向公司 IT 核实允许这种连接（§22.2）。

### 23.1 结构
- **证书转接在 App 进程里**（`Sources/App/CertificateRelay.swift`）。钥匙串身份只在用户会话可用，App 本来就在用户会话；
  退出 App 等于断开 VPN（§21.5），转接随 App 结束，不需要另装常驻服务。App 崩溃时转接消失，
  openconnect 连不上网关，后台服务保持封网——符合"只有崩溃才保持封网"。
- 转接直接监听 **127.0.0.1:<网关端口>**（通常 443）：macOS 10.14 起普通用户可绑定 1024 以下端口，本机实测
  NWListener 以用户身份绑定 127.0.0.1:443 成功，因此不需要 PoC 里的 root 端口转发。端口被占用时面板显示具体原因。
- openconnect 由后台服务以 root 运行，参数在 `RelaySettings.arguments`：`--resolve=<主机>:127.0.0.1`、
  `--servercert=<转接监听证书的 pin-sha256>`、`--certificate/--sslkey`（后台服务生成的本地客户端证书）、
  `--no-external-auth`（STRAP 绑定当前 TLS 通道，过两段 TLS 必失败，§22.6）、`--no-dtls`、`--base-mtu=1500 --mtu=1300`
  （与真实网关验证时一致，§22.14）。网关 URL、SNI、端口都不变。
- **本地双向 TLS**：转接的监听身份是每次连接用系统 `/usr/bin/openssl` 现做的一次性自签证书，只导入内存
  （`kSecImportToMemoryOnly`，需 macOS 15），文件立即删除；openconnect 钉住它的公钥。openconnect 出示的客户端证书由
  后台服务生成在 root 专属目录（私钥 0600，不出后台服务，30 天有效、到期前一天换新），证书经新 XPC 方法交给 App，
  转接只接受这一张（逐字节比对，握手本身证明对方持有私钥）。本机实测：RSA 2048 + PBE-SHA1-3DES 的 PKCS#12 可内存导入；
  EC 私钥或 LibreSSL 默认编码会让内存导入直接崩溃，所以固定用前者。
- **上游**：转接用钥匙串身份（`SecIdentity`，私钥只签名不导出）与网关做 TLS，系统信任 + 网关主机名校验照常；
  每次连接只解析并固定一个网关 IPv4，回报给后台服务。
- **网关真实地址**：openconnect 只看到 127.0.0.1，主机路由与 pf 放行需要真实地址。后台服务给 openconnect 子进程设
  `ALWAYSCONNECT_GATEWAY_IP`，vpnc-script 开头用它覆盖 `VPNGATEWAY`；connect 钩子里的 `gateway=` 随之是真实地址，
  pf 放行、诊断自检都用它。
- **CSTP 包边界**：CONNECT 得到 200 之后，两个方向都先重组完整 CSTP 包，再一包一次 TLS 写入（§22.13）。
  CONNECT 之前原样转发，只看请求头（带密码的请求体跳过、不留存）。
- **新 XPC 方法** `prepareRelay(gatewayIp:serverPin:)`：后台服务记下转接参数并回复客户端证书 PEM；空地址=直连网关。
  App 侧 3 秒超时回落为"后台服务需要更新"。Phase 1 的 connect/disconnect/getStatus 签名不变；connect 比较参数时
  把转接的地址与 pin 算进去，App 重启后换了新转接会让引擎重启。
- **App 流程**：连接 = 选证书 → Cisco 若已连接先 `vpn disconnect`（同一时间只能一个 VPN，否则 Cisco 的过滤器会挡掉）
  → 做转接（证书、解析网关）→ prepareRelay → 转接开始监听 → connect。断开、退出时在后台服务放手之后停掉转接，
  下一次连接前换掉旧转接；会话自己结束（被拒等）时转接闲置、只接受后台服务的证书，不跟着"已断开"推送停掉——
  切换服务器时上一会话迟到的推送会误停刚起的新转接。准备过程中用户断开则放弃这次准备。
  后台服务重启后 App 照 §20.9 重发连接，会重新做转接。
- **设置**：通用页"连接方式"（经 Cisco / 自建连接）与"证书"（自动 / 指定 / 不使用证书）；见 UI-DESIGN §五。
  不使用证书时后台服务直连网关（原 openconnect 引擎路径，适用于不要求客户端证书的网关）。
- **断线保护**：沿用 openconnect 引擎的全机 pf（§16、§20），始终开启；自建连接下不显示开关。

### 23.2 与 PoC 不同、需要说明的取舍
- Cookie：仍按 §16 由后台服务存在 root 专属文件（0600），后台服务重启后可不经手机批准用 Cookie 重连；
  PoC 为了隔离只放内存。Cookie 来源不变：只取 CSTP CONNECT 的 `Cookie: webvpn=` 请求头。
- 转接不再有 PoC 的连接寿命上限，只保留 20 秒握手超时；会话期间一直保持。
- 没有 PoC 的 root 端口转发（见上）。

### 23.3 验证级别
- CI harness（`scripts/relay-test.sh`，本机与 CI macOS 路都跑）：CSTP 重组与 CONNECT 识别单测；转接端到端——
  分段的 CONNECT、两个方向一包一个 TLS 记录、测试网关确实收到"公司"客户端证书；本地双向 TLS——
  后台服务的证书能过（对照），无证书、陌生证书、甚至公司证书本身都被拒；后台服务的 openconnect 引擎经转接登录
  要求客户端证书的模拟网关，取得并复用 Cookie，输出里没有密码；不经转接直连同一网关被拒。
- 脚本级断言：vpnc-script 用 `ALWAYSCONNECT_GATEWAY_IP` 覆盖网关（钩子与主机路由计划）。
- 本机实测：**需实测**（mac-proof I 节）——真实网关经 App 转接登录与手机批准、真实隧道、断线不漏、Cookie 重连、
  断开/退出恢复直连、Cisco 与自建连接来回切换。PoC 的真实网关结论（§22.5–§22.14）证明路线可行，不等于 App 已验证。

### 23.4 已知限制与待观察
- 需要 macOS 15（内存导入）与 Homebrew 的 openconnect；设置页缺条件时红字提示。
- openconnect 原生认证下等待手机批准时没有可识别的输出（`approvalPatterns` 仍为空，§16.5），状态停在"登录中"，
  文案提示去手机批准。批准超时在原生认证下是否也是 `Login failed`（PoC 见过错误 15 / Login failed，原因未确认，§22.6）
  需实测；在此之前引擎按被拒处理、立即停下（防锁号），不自动重试。
- 网关只固定 IPv4；网关只有 IPv6 时连接失败并提示。

### 23.5 首次真实运行：vpnc-script 从未被真实 openconnect 正确调用（已修）
2026-11-04 用户在场的第一次自建连接：经转接认证、手机批准都成功，CSTP 已建立（转接上每 15–30 秒有 30 字节的
保活包往返），但面板一直"正在连接"，utun 没有地址、默认路由仍在 en0、pf 未装。原因两处，都在本批之前就存在：
- openconnect 把 `--script` 当作一行 shell 命令交给 `/bin/sh -c`（`--help`："Shell command line for using a
  vpnc-compatible config script"），而安装路径 `/Library/Application Support/...` 带空格，命令被拆断，脚本根本没运行；
- openconnect 用环境变量 `$reason` 传 connect/disconnect（库里可见 `reason` 与 `/bin/sh`），脚本却按 `$1` 分支。
两处都被测试替身掩盖：假 openconnect 用 `"$script" connect` 直接执行。修正：引擎把脚本路径按 shell 单词加引号；
脚本读 `${1:-$reason}`（测试仍可传参）；假 openconnect 改为与真实一致的 `reason=connect /bin/sh -c "$script"`，
且 run-once 默认安装路径 `~/Library/Application Support/...` 本身带空格，掉线整环测试因此覆盖这两点。
此前 openconnect 引擎的真实隧道从未在本机端到端跑通过（mac-proof B1 未勾），本节是第一次。
验证级别：问题为本机实测；修正由 CI harness（忠实的假 openconnect）覆盖；真实重跑见 mac-proof I1。
期间网络始终直连可用：钩子没有触发，pf 没有装载。

### 23.6 第二次真实运行："连上就断网"——pf 掐断了装规则前建立的连接（已修）
2026-11-04 修完 §23.5 后，自建连接能连上（面板"已连接"），但用户随即断网。用户在场、断网期间由本机脚本离线采集
（采集完自动退出 App 恢复直连），三轮结果：
- 隧道建立后的第一条转接连接：55 秒内 openconnect 发出 1292 个包、只收到 6 个，最后以
  `receive from gateway: Operation timed out`（TCP 超时）结束；openconnect 日志里先是自己发 DPD（30 秒没收到任何数据），
  再收到网关两次 DPD 请求（网关也 30 秒没收到客户端数据），随后读到 EOF 并自行用 Cookie 重连。
- 重连后新建的转接连接一切正常：82 秒往返约 1.2 万个包、12 MB，按 IP / 按域名访问 0.3 / 1–2 秒。
- 原因：pf 的 pass 规则隐含 `flags S/SA keep state`，只有 TCP 的首个 SYN 能匹配。转接到网关的连接在隧道建立
  （装载 pf 锚点）之前就已建好，之后它的每个包都落到最后的 `block drop out quick on en0 all`。新连接从 SYN 开始，
  所以重连那条能过。PoC 不写 pf，因此没遇到。
- 修正：网关、放行网段、DNS 三类 pass 规则改为 `no state`（逐包按规则判断，不依赖状态表），装载前已建立的连接
  不再被掐断；pfctl 解析三套规则通过，Rust 测试固定了新文本。这一点同样适用于连接中途重新装载规则的情况。
顺带的修正与加强：
- 转接连向网关的连接禁止走任何隧道（`prohibitedInterfaceTypes = [.other]`），避免默认路由变成隧道后被系统改走隧道；
  采集中这条连接始终 `viable=true`，单靠它不能解释断网，作为防御保留。
- 转接把每条连接的开启、可用性变化、结束原因与包数写入 `~/Library/Logs/AlwaysConnect/relay.log`（不记地址与内容），
  普通用户可读；后台服务日志只有管理员可读，这次定位靠用户输一次密码复制出来。
- vpnc-script 识别 openconnect 9 的 `reconnect` 原因（内部重连后隧道复用同一 utun，路由与 DNS 保持）。
- 本机采集里转接链路吞吐正常；本地压测 3000 个包一包一记录、0.11 秒，排除了转接分包问题。
验证级别：问题与根因为本机实测；修正由 Rust 测试、pfctl 解析与本机全套检查覆盖；真实重跑见 mac-proof I1。

### 23.7 第三次真实运行：连通确认；退出与更新时 openconnect 收尾不干净（已修）
修完 §23.6 并更新后台服务后，用户在场的第三次运行：隧道持续 92 秒（采集结束时由脚本退出 App），
期间往返约 1.3 万个包、6 MB 多，每 5 秒探测一次，按 IP 0.26–0.94 秒、按域名 0.8–3.2 秒，全部成功，没有再断。
"连上就断网"确认修好。验证级别：本机实测（mac-proof I1 的连接部分）。
同时发现收尾问题：采集结束时 openconnect 有两个进程，其中一个父进程是 launchd，是更新后台服务时被遗留的
旧会话子进程——launchd 用 SIGTERM 停后台服务，不会连带结束 openconnect；它带着旧转接的 pin 每 10–30 秒
连一次新转接（转接日志里的 `-9816`），最多重试 5 分钟才自己退出。另外两处同类隐患：
- 后台服务替换引擎时先 `stop()` 再丢弃引用，而 `stop()` 弱引用自身，引擎一释放就跳过了结束子进程；
- 手动断开时 App 收到回复就停转接，openconnect 在 SIGTERM 后要经转接向网关注销，转接没了就可能卡住。
修正：`stop()` 强引用自身，SIGTERM 后 8 秒仍在就 SIGKILL；后台服务收到 SIGTERM 先结束 openconnect 再退出
（路由与 pf 保持，下次启动按 §17.5 恢复封网集）；`dev-helper.sh install` 替换前清掉遗留的本项目 openconnect；
App 断开后把转接再保留 6 秒供注销，期间新的连接会立即停掉它（同一端口）。
验证级别：本机全套检查；真实收尾见 mac-proof I3。

### 23.8 "点退出没反应"（用户反馈，2026-11-04，已修）
切回"经 Cisco"后 App 自动连接、停在等手机批准时，用户点面板"退出"，看起来没有反应。原因：退出要先让 Cisco 收尾
（退出 = 不开 VPN，§21.5），而 Cisco 引擎的队列正被等待批准的 `vpn -s` 登录占着，`vpn disconnect` 也要等它，
于是一直拖到 15 秒的强制退出上限；这期间菜单栏图标和面板都不变，用户以为没生效（App 最终按上限退出，网络直连、
Cisco 已断开，无残留）。修正：点退出立刻隐藏菜单栏图标与窗口；Cisco 模式下先请后台服务恢复直连，再等 Cisco 收尾
（与断开按钮一致，§21.10），15 秒上限保留。验证级别：本机构建与全套检查；真实点击需用户复测。
另：本地测试版位于工作目录的 `.local-build/AlwaysConnect.app`，不在"应用程序"里，用户退出后找不到入口。
同批：面板"后台服务有新版本"改为比较代码目录哈希（CDHash）而不是整个文件——每次重新构建都会以新的签名时间
重签，代码相同也会被判为新版本，平白要一次管理员密码。
后续（用户反馈，2026-11-05，已修）：退出时隐藏图标用的是 `isVisible = false`，而状态项设了 autosaveName，AppKit 把
"已隐藏"存进了偏好（`NSStatusItem VisibleCC AlwaysConnectStatusItem = 0`），下次启动 App 在跑、菜单栏却没有图标。
修正：启动时总把状态项设为可见（图标是 App 唯一入口）。验证级别：本机重装后偏好已回到 1；菜单栏是否显示需用户看一眼。

### 23.9 第 1 批真实验收结果（2026-11-04，用户在场）
- 连接（mac-proof I1）：§23.6/§23.7 修正后，自建连接两次分别持续 92 秒、95 秒（约 15 MB），期间按 IP 访问 0.3–0.9 秒、
  按域名 0.8–3 秒，浏览器正常；网关下发 MTU 1159、DPD 30、Keepalive 20。
- 断线不漏（I2，`sudo scripts/own-drop-test.sh`）：SIGKILL openconnect 后，掉线期间网页请求被拦（000），默认路由回到
  本地网卡但流量出不去，局域网可达；8 秒后后台服务用 Cookie 重连成功，不需要手机批准。零泄漏。
  当时装载的规则即 §23.6 修正后的 `no state` 放行集。
- 退出（I3）：App 1 秒内退出，openconnect 2 秒内退出，127.0.0.1 上不再监听，默认路由回到本地网卡、网页正常，无残留进程。
- 切回 Cisco（I4 部分）：改设置项切回"经 Cisco"后重新打开，Cisco 连接与批准正常。界面点选切换未单独测。
- 尚未实测：面板"断开"按钮、诊断页自检、批准超时在原生认证下的表现（I5）、睡眠唤醒/换网络（第 4 批）。
验证级别：以上均为真实 Mac + 真实网关本机实测，由脚本离线采集（断网期间本机代理无法联网对话）。

### 23.10 证书改为自动选择（用户："这个证书功能是干嘛的，看不懂"）
原来的"证书"下拉把钥匙串里所有能做客户端认证的身份都列出来：本机有 4 张同名续期的公司证书和 4 张设备管理（MDM）
自签身份，用户看不懂。改为：只把非自签的证书当登录候选（自签的是设备自己的身份，不会是 VPN 登录证书），
默认自动选到期最晚、同到期再看签发最晚的一张；设置里只显示一行"自动：名称（到期 …）"，"更改"菜单才列出候选、
"自动选择"与"不使用证书"。本机核对：8 张身份中 4 张被识别为自签排除，自动选中的正是 PoC 与 §23.9 实测用过的那张。
验证级别：本机运行识别逻辑；界面为编译验证，未截图复核。

### 23.11 退出 = 本项目的进程一个不留（用户："退出时把后台残留的相关进程全杀掉，彻底干净"，2026-11-04）
§21.5 的退出已经断开 VPN、恢复直连，但还有三处会让进程比 App 活得久：macOS 上子进程不随父进程结束，
15 秒强制退出上限截断的 Cisco 命令行调用（等批准的 `vpn -s`、卡住的 `vpn disconnect`）会被 launchd 收养继续跑；
后台服务要空闲 30–45 秒才自退；更早版本的后台服务被替换时留下的 openconnect 只在重装时清。用户定的取舍：
本项目的全部清掉，Cisco 的窗口程序也请它退出；Cisco 的系统组件（vpnagentd、网络扩展）和别的软件（如 Clash Verge
的 mihomo）不动——前者一停 Cisco 自己就连不上，后者不归本项目。
- App（applicationShouldTerminate，正常收尾或 15 秒上限之后、真正退出之前）：请 Cisco Secure Client 窗口程序与其
  登录浏览器（com.cisco.anyconnect.gui、com.cisco.anyconnect.acwebhelper）退出（只请求、不强杀）；对自己的全部
  子孙进程（`proc_listchildpids` 逐层收集）先 SIGTERM，2 秒内不退的 SIGKILL。证书转接在 App 进程内，随 App 结束。
- 后台服务：最后一个 App 连接断开（退出会使 XPC 连接失效）即启动每秒一次的空闲检查，连续两次空闲（无 App、无会话、
  断线保护关、无持有状态）就退出——openconnect 还在注销时会话不算空闲，等它结束（最长 8 秒后 SIGKILL，§23.7）。
  原 15 秒一次的检查保留作兜底（开机拉起、没有 App 连上的情形）。服务不卸载，下次打开 App 由 launchd 按需拉起，
  不需要管理员密码。App 崩溃时断线保护仍在装着，不算空闲，照旧故障关闭。
- 后台服务每次退出前（空闲自退、launchd 的 SIGTERM）结束自己的子孙进程，并按命令行里本项目安装的 vpnc-script
  完整路径找出前任后台服务遗留的 openconnect 一并结束（只在 root 下匹配该路径，测试与 CLI 子命令不会误伤）。
- 验证级别：脚本级断言 scripts/process-sweep-test.sh（真实子进程：列出子孙、按命令行查找、SIGTERM 不理的被 SIGKILL、
  受宽限期约束、清完无残留；本机与 CI macOS 跑）；本机编译与全套检查。真实退出后 `ps` 无本项目进程、后台服务
  几秒内退出、Cisco 窗口程序被关，需实测（mac-proof I6）。

### 23.12 重启后整机断网：开机时按上次残留状态封网（用户实际受害，2026-11-04，已修）
现象：用户连着 VPN（经 Cisco）时重启电脑，开机后只有 DNS 能通，所有 80/443 超时，手机同一 Wi-Fi 正常；
`sudo pfctl -d` 一关立即恢复。用户自查了很久（`pfctl -sr` 顶层看不到 block、pf 在网卡前丢包 tcpdump 抓不到），
其间被其他排查方向误导。原因在我们：关机时 launchd 先 SIGTERM 后台服务，它按 §23.7 的设计"路由与 pf 保持、
下次启动恢复封网集"留下 pf-state；开机 RunAtLoad 拉起后台服务，§17.5 的启动恢复把它当成"后台服务崩溃后重启"，
装上封网集（只放 DNS）并 `pfctl -E` 开启 pf。可此时 App 没开、也没有任何隧道，用户手里没有一键恢复的入口——
违反"不能把用户困住"的硬规则。后台服务因持有状态也不会空闲退出，下次重启还会再断。
修正：启动恢复只认"本次开机内"写下的状态。pf-state 与 route-state 的修改时间早于 kern.boottime（读不到开机时间
也按过期算）即删除、清空本项目锚点，不封网；路由不动（重启已重置）。关机等同退出（§21.5）：网络直连。
同一次开机里后台服务崩溃或被更新替换，仍按 §17.5 故障关闭。
验证级别：脚本级断言 scripts/boot-session-test.sh（开机时间可读、早于/晚于开机的判定、读不到按过期、
真实文件的修改时间判定；本机与 CI macOS 跑）；本机编译与全套检查。真实"连着 VPN 重启后网络直连、后台服务自退"
需实测（mac-proof I7）。
教训：故障关闭的状态要说清楚"对谁、在什么时间范围内"有效；任何封网都必须同时有一个用户够得着的恢复入口。

## 二十四、全机接管（分流接入第 2 批，设计，2026-11-04 用户确认开工；2026-11-05 已撤销，见 §二十六）

目标：自建连接下，全机流量先进分流核心 mihomo，再由它决定出口；本批规则只有一条"全部走 VPN"，用户可见行为
与第 1 批相同，验收的是"经核心不漏、各种崩溃下不漏、恢复干净"。第 3 批在此之上加三类规则与界面。
"经 Cisco"模式不启用核心，不改 Cisco 的路由与过滤器（§22.1）。

### 24.1 结构与生命周期（后台服务，root）
- 核心：Homebrew 的 `mihomo`（用户安装，不打包，§22.14 与计划一致），后台服务以 root 启动，配置与工作目录在
  `/Library/Application Support/AlwaysConnect/core/`（0700），日志级别 warning，不记录地址以外的内容。
- 启动：openconnect 的 connect 钩子之后（已知 utun 名与物理口）。配置：普通 TUN（stack gvisor，与 PoC 一致）、
  自选一个空闲 utun 名、`auto-route: false`、`auto-detect-interface: false`、核心 DNS 关闭、`find-process-mode: off`
  （本批无应用规则）；两个出口：A=直连并绑定物理口（本批不用），B=直连并绑定 openconnect 的 utun；规则 `MATCH,B`。
- 路由由后台服务自己加：`0.0.0.0/1`、`128.0.0.0/1` 指向核心 TUN（比 openconnect 的默认路由更具体），网关主机路由
  与局域网路由保持原样（更具体）。核心 TUN 消失时这两条路由随接口一起消失，流量自然回落到 openconnect 的默认路由，
  仍走 VPN——核心挂掉不会漏。
- 重连：openconnect 内部重连复用同一 utun，无需动作；后台服务重启 openconnect 换了新 utun 时，用新 utun 名重写配置
  并重启核心。手动断开、退出、终态、后台服务退出：先停核心、删两条路由，再走原来的恢复。
- 核心异常退出：后台服务看门狗发现即重启（有限次数），失败则保持回落到 openconnect 路由并在面板提示。

### 24.2 故障关闭
- pf：放行集增加核心 TUN（`pass out quick on <核心 utun> all`）；物理口仍只放行网关、放行网段、DHCP 等（§23.6 的
  `no state`）。隧道断、核心被杀、App 被强退、后台服务被重启四种情况都必须不漏：前两种由路由回落 + pf 保证，
  App 被强退时转接消失、openconnect 连不上，pf 保持封网（§23.1），后台服务重启按 §17.5 恢复封网集。
- 一键恢复直连：面板现有"断开/恢复正常网络"走同一条停核心 → 删路由 → 原恢复流程。

### 24.3 DNS
- 系统 DNS 仍由 vpnc-script 设成隧道 DNS（§20.4），查询经核心 → B → 隧道。第一服务器 UDP 超时时的服务器切换与
  TCP 回退（PoC §22.9 实测需要）由系统解析器完成：两台隧道 DNS 都写入，系统按顺序换服务器；TCP 回退待实测，
  不行再在核心里开 DNS 模块做回退。

### 24.4 验收项（本批）
- CI：配置生成断言、`mihomo -t` 语法检查（CI 安装 mihomo）、路由计划桩命令断言。
- 本机实测（用户在场）：全机流量经核心再进隧道（核心统计与接口计数可见）；结束 openconnect、结束核心、强退 App、
  重启后台服务四种情况零泄漏；断开/退出后核心、两条路由、pf 都清干净，无残留进程。

### 24.5 实现（2026-11-04）
- `Sources/Helper/RoutingCore.swift`：生成配置（上文 24.1，`core-config` 子命令可打印）、选空闲 utun（230–249）、
  以 root 启动 mihomo、等其 TUN 出现后加 `0.0.0.0/1`、`128.0.0.0/1` 两条路由；意外退出时路由随之删除并最多重启 3 次，
  仍失败就停在 openconnect 路由上（仍走 VPN）并在面板提示；停止时先删路由，SIGTERM，3 秒后 SIGKILL。
- 接线：openconnect 的 connect 钩子（`onTunnelUp`）启动或换绑；终态、断开、后台服务 SIGTERM 都先停核心。
  只在经转接的自建连接里启用；没装 mihomo 时跳过并提示，连接照常全部走 VPN。
- pf 不需要新规则：锚点只封物理口，核心 TUN 不在其中；核心发往 VPN 的流量走 openconnect 的 utun（已放行）。
- 验证级别：配置由 `mihomo -t` 校验（本机检查与 CI）；实际全机接管与四种崩溃下不漏，需本机实测（24.4）。

## 二十五、生命周期审查与网络闸门（用户："彻底避免再被困在断网里"，2026-11-05）
§23.12 的整机断网之后，用户要求起一个不带上下文的审查员通读代码，逐个推演启动、连接、掉线重连、手动断开、退出、
App 崩溃、后台服务崩溃/更新、openconnect 或 mihomo 死掉、注销/关机/重启、睡眠唤醒、换网络、关断线保护、
密码被拒、Cisco 界面干扰、同时开两个 App 时，进程、pf 规则、pf 开启引用、路由、DNS、状态文件各归谁收拾。
用户要的效果：掉线自动重连且不漏；主动退出收尾干净无遗留；异常退出自动拉起或重试几次、期间不漏，但要有兜底规则；
真断网时给出提示和出路，不能陷入没有头绪的死胡同；架构从简。审查发现 18 条（F1–F18，致命 2 条），本章按批修。

### 25.1 切换过连接方式后"断开"失效（F1，致命，已修）
后台服务同一次运行里先用过自建连接、再切经 Cisco 连上，点断开或退出：停掉的旧引擎对象从不清空，断开走"有引擎"
分支调用它只生效一次的 `stop()`，Cisco 的断线保护没撤、pf 没清；`vpn disconnect` 后看门狗反而装上封网集（只放 DNS）。
红色按钮无效，退出后网一直封着、后台服务也不空闲退出——与 §23.12 同样的症状。修正：断开总是撤 Cisco 断线保护；
只有引擎还在跑时才交给它收尾，否则按"无引擎"恢复直连；引擎终止即清空引用。
测试缝：`ALWAYSCONNECT_TEST_ROOT`（只在非 root 时生效）把后台服务的状态目录、pfctl、openconnect 换成测试替身并关掉
路由/DNS 改动；scripts/session-test.sh 直接驱动后台服务的会话对象，用记录参数的 pfctl 桩断言"最后一次装载之后锚点
被清空、pf 开启引用全部归还、断线保护关闭、磁盘上无持有状态、之后不再装载"。场景：Cisco 断开、关断线保护、
自建断开、自建再 Cisco（修前失败、修后通过）。验证级别：CI harness 级（本机与 CI macOS）；真机"切换后断开"需实测。

### 25.2 网络闸门：后台服务里唯一写 pf 的地方（F2、F4、F5、F11、F15，已实现）
原来 Cisco 断线保护（KillSwitch）与自建引擎（CLIOrchestrator）各自装载/清空同一个锚点、写同一个 pf-state.json、
共用一个只在内存里的 pf 开启引用，没有谁统一决定"封还是不封"，封网也没有时限。现在 Sources/Helper/NetworkGuard.swift
是唯一的写入者：
- 持有者只请求：`apply`（连接集或封网集）与 `release`。自建引擎每个实例有自己的持有者名"own:<代次>"，新引擎一建好，
  旧引擎的名字就作废——它收尾时的装载与放开都被忽略，不会再撤掉接替它的引擎的规则（F4）；旧引擎先于新引擎建好前被停的
  空窗也去掉了（新引擎建好后才停旧的，且以"替换"方式停：不装手动断开标志、不恢复路由，交给新隧道）。
- 磁盘上只有一个记录 guard.json：本次开机的 `kern.bootsessionuuid`、pf 开启 token、持有者、规则输入。同一次开机里
  后台服务重启（崩溃、更新）就认领它：装封网集（连接集也改成封网集，隧道是否还在未知）、接管 token，不再漏引用（F11）；
  别的开机留下的直接作废、不封网（取代 §23.12 的文件修改时间比对，F15）。旧版本的 pf-state.json 视同作废并清锚点。
- 封网要有主人：有 App 连着。最后一个 App 断开而闸门仍在封（主动退出会先放开，所以这只会是崩溃或强制退出），
  就启动 120 秒宽限并尝试把 App 拉起来；宽限内有 App 回来就继续，否则按退出处理全部放开（停核心、撤断线保护、
  停引擎、恢复路由），把原因记在 last-release.json，App 下次启动时告诉用户（F2）。没有活着的 App，封网最多 120 秒，
  永不跨重启。
- 拉起 App（AppRelauncher）：从连上来的 App 进程取 .app 路径与用户，以该用户身份在其会话里 `open -g`；
  10 分钟内最多 3 次，防止启动即崩溃的 App 反复拉起。
- 关断线保护或手动断开：Cisco 断线保护撤销时总会放开 cisco 持有的规则，包括重启后被认领、本对象从没装过的那份（F5）。
- 断开/宽限到期统一走 `releaseEverything`：先放开 pf（返回时网络已直连），再撤断线保护、停核心、停引擎或按 route-state
  恢复路由（Cisco 模式没有 route-state 就不跑恢复，避免把过期的物理默认路由塞回去，F17）。
- 后台服务启动时先清前一次运行遗留的 openconnect 与 mihomo（命令行里带本项目 vpnc-script 路径或核心目录的进程，F6）。
- 新 XPC 方法 getLastRelease（App 侧 3 秒超时回落）。`scripts/dev-helper.sh recover` 同时归还 guard.json 里的 pf 开启引用。
- 验证级别：CI harness 级（scripts/session-test.sh 共 12 个场景：Cisco 断开、关断线保护、自建断开、自建再 Cisco、
  宽限到期（拉起一次、放开、原因 app-gone）、宽限内 App 回来、退出后不拉起、同次开机重启认领（归还被认领的 token）、
  别次开机作废、旧版 pf-state、换引擎不误放、启动清遗留进程）；以 root 运行的真实 pf、`open` 拉起 App 需实测。
- 测试替身：fake-openconnect 收到 SIGTERM 时连同 sleep 一起退出（孤儿 sleep 会占住调用方的输出管道，曾让测试挂 10 分钟）。

### 25.3 封网覆盖所有网卡（F3，已实现）
封网集原来只在连接时记下的物理网卡上放行/拦截。掉线期间换到网线、扩展坞、手机热点时，默认路由落到另一块网卡上，
完全不受限。现在放行项（网关、白名单网段、DHCP、mDNS、fe80、DNS）与最后的 `block drop out quick all` 都不再绑定网卡；
隧道与 lo0 照旧放行；自建连接的路由核心（mihomo）TUN 在 utun230–utun249 里取名，封网集对这一段整体放行（Rust flags 第 2 位），
否则核心接管后流量在核心 TUN 上就被拦。连接集不变（物理网卡出向全放）。代价：掉线期间虚拟机网桥、AirDrop 等其他网卡
也被拦——这正是"不漏"。验证级别：Rust 单测锁定规则文本（新增"封网集不绑网卡""核心 TUN 只在要求时放行且在拦截之前"）；
`pfctl -n` 在本机与 CI 解析四种组合（含核心 TUN 段）；真机换网卡不漏需实测。

### 25.4 退出先放开、只管自己的东西（F7、F8、F10、F13、F16，已实现）
- 退出总是先经后台服务放开网络，不再看 App 缓存的状态（它可能滞后：刚点断开就点退出时，旧版会跳过放开，F10）。
- 自建连接退出时，转接留到后台服务报告引擎已停、最多 6 秒，openconnect 能经它注销，不再被 8 秒后强杀（F16）。
- Cisco 会话归属（F8）：只有 App 自己发起（`vpn -s` 登录）的 Cisco 会话才由 App 管——记一个持久标志，App 崩溃后被拉起时
  据此接回；用户在 Cisco 自己窗口里连的会话，App 不接管、不装断线保护、不当掉线处理、退出时也不替它断开。退出时关
  Cisco 窗口程序与登录浏览器（§23.11 用户定）也只在 App 正管着 Cisco 会话时做。
- 单实例（F13）：第二个 App 启动即把前一个调到前台并直接退出——不走退出流程，否则会断开第一个的 VPN。
- 路由核心的 0/1、128/1 路由（F7）：添加检查结果，失败（前缀已被别的 TUN 占用，例如 Clash Verge 的 TUN 模式）就停核心、
  留在 openconnect 路由上并提示；删除只删 `route -n get` 显示确实指向我们 TUN 的那条，不误删别人的。
- 验证级别：Cisco 引擎 harness 新增"不接管别人连的会话"；session harness 新增路由归属解析；退出放开与转接保留、
  单实例为编译验证，真机需实测（mac-proof I8）。

### 25.5 封网时的提示与出路（F9、F12、F14，已实现）
- 通知（Notifier 成为通知中心代理，注册"network-held"类别与"恢复直连"动作，点了等同面板红色按钮）：
  掉线即推"网络已暂停"（说明原因与出路；属需要用户知道的事，不受聚合开关限制；Cisco 关了断线保护时只说走本地网络）；
  仍暂停（重连中或断开后仍持有）每 10 分钟提醒；被拒（2）与多次失败（3）的通知改说"可能是密码错误或没在手机上点批准，
  网络如仍暂停点恢复直连"——不改判定（不猜网关行为），只把出路说清（F14）。
- 恢复无回应（F9）：点恢复后 5 秒内后台服务没回包，面板给"强制恢复网络（需电脑密码）"，经管理员密码框以 root 跑包内
  dev-helper.sh recover（恢复路由/DNS、清锚点、归还 pf 开启引用、删持有状态），不依赖后台服务。
- App 被拉起后接回自建连接（F12）：后台服务仍在重试而 App 没有转接（旧转接随崩溃的 App 消失），每次运行至多一次
  重新建转接并连接，不再永远"正在重连"。
- 上次自动放开（§25.2 的 app-gone）：App 启动时经 getLastRelease 读一次，较上次已提示的更新就推一条说明。
- 验证级别：编译验证；通知与按钮、管理员密码框、拉起后接回需真机实测（mac-proof I8）。

### 25.6 后台服务不再开机自启（F15，已实现）与本章小结
- launchd：KeepAlive 由 {SuccessfulExit: false} 改为 {Crashed: true}，去掉 RunAtLoad。前者隐含开机运行（`man launchd.plist`），
  而 §25.2 之后开机没有任何要恢复的东西；现在只在崩溃后重启，平时由 App 经 MachServices 按需拉起。`dev-helper.sh install`
  装好后立即 kickstart：被替换的旧服务若留下封网，新服务马上认领，没有 App 时宽限期满即放开，不必等下次打开 App。
- AGENTS 硬规则同步改为"崩溃后最多封 2 分钟、绝不跨重启、封网必有一键出路"。§21.5 里"RunAtLoad 保留、开机按 pf-state
  重装封堵集"一句已被本章取代。
- 本章之后的生命周期（谁负责什么）：pf、pf 开启引用与持有记录只归网络闸门；Cisco 隧道归 Cisco（App 只管自己发起的会话）；
  openconnect、vpnc-script 路由、路由核心归自建引擎会话，统一经 releaseEverything 收尾；转接与 Cisco CLI 子进程归 App，
  退出时清干净。验证级别：脚本/harness 级全部通过（本机）；真机需整体复测（mac-proof I6–I8、H4）。

### 25.7 第二轮无上下文审查后的修正（2026-11-05）
改完后又起一个不带上下文的审查员只读审了 §25.2–25.6 的全部改动：没有找到会困住用户或掉线漏网的路径；指出 1 个中等、
9 个低级问题与 2 条加固，均已处理：
- 自建连接换服务器"保存并连接"连不上（中）：§25.2 的"新引擎建好再以替换方式停旧的"会留下旧网关的封网集和缺失的默认路由，
  新网关既无路由又被 pf 拦。改为：替换时先把旧引擎完整停掉（恢复路由、由它自己仍然有效的持有者放开 pf），停完（或 10 秒兜底）
  再启动新引擎；期间再来的连接或断开会让这次等待中的启动作废。`stop(replacing:)` 删除。
- 宽限期放开时 pf 清除失败：保留记录且没有 App 时重新计时重试，不再永久卡住。
- 没有 pf 记录但引擎仍在跑（例如登录中 App 崩溃）：同样计入宽限与拉起，否则会经已死的转接无限重试。
- 主动退出后误拉起：用户放开后记一个标志，下一次连接或装断线保护前，App 离开都不算崩溃、不拉起。
- 宽限到期与 App 回来的竞态：放开前在会话队列上再确认一次没有 App 连着。
- 退出时转接的保留（F16 未生效）：引擎一停就推送"已断开"，不能当信号；改为等 getSessionInfo 报告终态 1（openconnect 已退出），最多 6 秒。
- 强制恢复后仍在运行的后台服务以为自己还持有 pf 开启引用：recover 归还引用后 `launchctl kickstart -k` 重启它。
- Cisco 归属标志在登录被拒后未清：被拒时、以及 Cisco 已断开且 App 不再追连时清掉，用户随后在 Cisco 窗口连的会话不会被接管。
- 启动清扫可能误杀：改为同时匹配程序名与确切参数（openconnect + `--script='<我们的脚本>'`，mihomo + `-d <核心目录>`），
  `tail -f` 日志、正在跑的 recover 等不再被当成遗留。
- 掉线时 Cisco 换了 utun 编号：封网集原只放行已知隧道接口，新 utun 要等 App 重新下发才通。现在放行 utun0–utun63（进入 utun 的流量
  最终只能经物理网卡出去，而物理网卡除网关外都被拦，所以不漏），与 §25.3 前只拦物理网卡时对隧道的效果一致。
- 加固：启动时没有记录也清一次本项目锚点（加载与写记录之间崩溃不会留下看不见的封网）。未做：被 SIGKILL 的后台服务
  launchd 不按 Crashed 重启，宽限期内被杀则封网持续到 App 打开或重启——App 一打开即接管，面板有出路。
- 测试：清扫场景改用单进程替身并验证"无关进程不误杀"；旧的 bash + sleep 替身会留下孤儿 sleep 占住输出管道。
- 验证级别：session harness 13 个场景、Cisco 引擎 harness、Rust 测试与 `pfctl -n` 解析在本机全部通过；真机见 mac-proof I8。

### 25.8 方案二的 pf 部分：本地 DNS 放行与直连地址表（2026-11-05，接口供 §二十六 B3 接线）
方案二的断线保护只拦"本该走 VPN"的流量，连上与掉线用同一套规则（`apply(connected: false)`）。网络闸门新增：
- `Inputs.localDNSServers`：53 端口（UDP/TCP）只放行到这些地址（本地网络的 DNS，转发器向它们查名单域名），取代分流模式下
  "任何地址的 53 端口"（`allowDNS`）；本地网络换了 DNS 时用新输入再 `apply` 一次。
- `Inputs.directTable`：锚点里声明 `table <ac_direct> persist`（在规则之前）并放行 `pass out quick to <ac_direct> no state`。
- `addDirect(_:) -> Bool`、`removeDirect(_:)`、`flushDirect()`、`directAddresses`：同步调用，`addDirect` 返回 true 时
  pf 已放行这些地址（`pfctl -a <锚点> -t ac_direct -T add …`，不重载规则），转发器可在交回 DNS 答案前调用；任一条不是
  IPv4/IPv6 地址则整次失败、什么也不加；已有地址不重复调用 pfctl。没有持有规则集时先记下，下一次声明了表的 `apply` 一并装入；
  每次重载规则（会清空表）后自动重新灌回。内容写进 guard.json，同一次开机重启认领时重新灌回。
- 放开时除了清规则，还清本锚点的表（`-F Tables`，只限本锚点；不用 `-F all`，它会波及全局连接状态），并忘掉地址表。
- 兼容：旧版 guard.json 缺新字段时按默认值解码（自写 `init(from:)`，AGENTS 已知坑）。
- 职责边界：闸门只管 pf；直连地址的主机路由、系统 DNS 条目、隧道路由归改动台账（§26.3）。台账撤销时先调闸门 `release`
  （pf 放开即直连），再撤路由与 DNS；地址何时过期由转发器决定。
- 验证级别：Rust 单测（表声明在规则前、DNS 放行去重、无表时不出现、坏地址被拒）；`pfctl -n` 在本机与 CI 解析带表与 DNS 的封网集；
  session harness 新增 4 个场景（增删表与 pfctl 调用、无持有时先记下、重启认领后重新灌回、旧记录兼容），本机全部通过；
  真机见方案二 B 批实测。

### 24.6 第 2 批首次真实运行把整机网断了（2026-11-05，用户在场；核心已默认关闭）
现象：自建连接连上、分流核心启动后整机断网；mihomo CPU 约 183%；路由为 `0/1`、`128.0/1` → 核心的 utun230，
openconnect 的默认路由 → utun4；用户按自己的步骤（结束 mihomo/openconnect/后台服务、删两条路由、恢复 en0 默认路由、
清 DNS 缓存）恢复。事后检查：进程与路由已清，但 vpnc-script 写的 `State:/Network/Service/utun4/{IPv4,DNS}` 还在，
系统仍以已不存在的 utun4 为主服务、DNS 指向隧道里的服务器（在公司内网碰巧可达）。
判断（待验证，不当结论）：核心的 B 出口用 `interface-name` 绑定 utun4（IP_BOUND_IF），而 utun4 只有全局默认路由、
没有限定该接口的默认路由（PoC 运行时自己加过 `-ifscope`，产品没有）；绑定接口的查路失败后落回全局表，命中 `0/1`
回到核心自己的 TUN，形成环路。另一个缺口：openconnect 被强杀（SIGKILL）时 vpnc-script 的 disconnect 不会运行，
上述 scutil 条目会残留。
处理：
- 分流核心默认关闭：只有 `/Library/Application Support/AlwaysConnect/core-enabled` 存在时才启动（开发者显式打开），
  自建连接恢复为第 1 批行为（已实测可用）。
- 应急恢复工具 `scripts/reset-network.sh`（App 包内 `Contents/Resources/` 也有一份；用户桌面放了可双击的
  "AlwaysConnect 恢复网络.command"）：不依赖 App、后台服务与网络，结束本项目进程（App、后台服务、我们的 openconnect 与核心，
  不碰 Cisco/Clash 等），清掉保持封网的状态，删核心路由，删已不存在的 utun 留下的 scutil 条目，缺默认路由时经物理口恢复，
  清 DNS 缓存，清空我们的 pf 锚点并释放我们的 pf 引用，验证网页；仍不通才关 pf 作最后手段。`--dry-run` 只列动作。
- 规则（写入 AGENTS）：任何会动网络的实测之前，先确认恢复工具就位、并有自动回退（脚本或核心自身的连通性探测，
  失败即退回）；不再让用户在没有退路的情况下测。
重新启用核心之前必须完成：B 出口所需的 `-ifscope` 默认路由；核心启动后的连通性探测，不通立即删路由、停核心、
退回纯 VPN；运行中定时探测；强杀路径的 scutil 清理（后台服务启动时与 reset 工具都做）。
验证级别：故障现象为本机实测（用户报告 + 事后检查）；恢复工具 dry-run 在本机核对过将删除的残留条目；
实际恢复需用户运行一次确认。
同日用户要求把恢复集成进 App、并把 App 放进"应用程序"：面板常驻一行"上不了网、被 AlwaysConnect 卡住时 [恢复网络]"，
确认后 App 先断开自己的会话（Cisco 或自建），再经系统管理员密码框以 root 运行包内的 `reset-network.sh --from-app`
（不杀 App 自己），期间后台服务被停不触发 App 的自动重连，结果显示在面板。`scripts/install-app.sh` 把本地构建装到
`/Applications/AlwaysConnect.app`（先正常退出正在运行的那份）。用户反馈"每次断网后都没法跟你沟通"：恢复手段必须全在本机、
不依赖网络与助手，会动网络的测试必须自带自动回退。

## 二十六、方案二：一条隧道 + 按域名的系统路由分流（2026-11-05 用户选定）

架构审查（[docs/architecture-review-2026-11-05.md](docs/architecture-review-2026-11-05.md)）后用户选定方案二，
计划见 [docs/split-plan-v2.md](docs/split-plan-v2.md)：只保留 openconnect 一条隧道，按域名分流用"本机 DNS 转发 +
主机路由"实现，不再叠用户态分流核心；断线保护只拦本该走 VPN 的流量；所有系统网络改动记入改动台账、统一撤销。
分工（Coordinator 协调）：pf 由网络闸门（NetworkGuard）负责并提供直连地址表等接口；路由、系统 DNS、进程与 DNS 转发器在本方案。

### 26.1 A1：删掉 mihomo 分流核心（2026-11-05）
`RoutingCore.swift`、`core-config` 子命令与检查、CI 的 mihomo 步骤、`scripts/core-test.sh`、pf 的核心 TUN 段
（`pass_core_tuns` / `CORE_TUNS` / `Inputs.passCoreTuns`）、进程清扫里的 mihomo 标记、会话 harness 的相关场景全部删除。
恢复工具仍会结束旧版本可能遗留的我们的 mihomo（只认我们的配置路径）。验证级别：Rust 测试与本机全套检查。

### 26.2 A2：删掉从未启用的透明代理扩展与数据泵（2026-11-05）
`Sources/Proxy`（NETransparentProxyProvider 与 FlowPump）、`Sources/PumpCore`、`Sources/Bridge`、`Sources/PumpTest`
及其 Xcode 目标、本地构建与 CI 步骤删除。它们需要付费开发者账号才能运行，从未在产品里启用（§20.10）；
方案二不需要它们。§十七（Phase 2 数据泵契约）保留为历史记录。验证级别：本机构建与全套检查，CI 待推送后确认。

### 26.3 A3：改动台账——路由与系统 DNS 先记账、统一撤销（2026-11-05）
vpnc-script 的 route-state 文件改成真正的台账：
- **先记账再动手**：连上时先写入本次开机标识（`AC_BOOT`）、要恢复的物理默认路由、网关主机路由、隧道网卡，
  以及本次会话写过系统 DNS 条目的**所有**隧道网卡（`AC_TUNS`，重连换了 utun 也都记着），然后才改路由与 DNS。
  会话在任何一步被打断，台账都已在，撤销不会漏。
- **统一撤销**：`restore` 按台账删网关主机路由、删每个隧道网卡的 DNS/IPv4 条目、缺物理默认路由时补回，然后删台账。
  手动断开、无引擎时的放开、恢复工具（先调脚本的 restore 再清状态）都走它。
- **后台服务启动时**：台账若来自本次开机，说明上一个会话随旧后台服务死掉了，立即按台账撤销（今天这种
  "隧道已不在、系统仍以它为主服务、DNS 指向隧道"的残留由此消失）；来自别的开机则只删台账（路由与 DNS 条目不跨重启）。
  断线保护仍由网络闸门负责，这里只撤路由与 DNS，不放开封网。
- pf 的台账与撤销由网络闸门实现（guard.json，§25.2），撤销顺序：先闸门 release，再撤路由与 DNS。
验证级别：脚本级断言（路由计划桩测试：台账先于首个改动写入、每个隧道的 DNS 条目都被撤销、开机标识写入）；
会话 harness（启动时本次开机的台账被撤销、别的开机的只删不放）；真实效果需本机实测（A4）。

### 26.4 B1：本机 DNS 转发器（2026-11-05）
`Sources/Helper/DNSForwarder.swift`：在 127.0.0.1:53 收 UDP 与 TCP 查询。名单域名（后缀匹配，大小写与末尾点无关）
经物理网卡（IP_BOUND_IF）问本地网络的 DNS，**在把答案交回之前**用回调让其中所有 IPv4 地址走直连（主机路由进台账、
网络闸门的直连地址表）；名单域名的 AAAA 与 HTTPS(SVCB) 查询给空的 NOERROR 答复，只留 IPv4，避免从 IPv6 或地址提示绕出去
（2026-11-09 起 HTTPS/SVCB 改为照转、只删地址提示，见 §42）。
其他域名问隧道 DNS：逐台尝试，UDP 不通或被截断就对同一台改用 TCP（PoC §22.9 实测公司第一台 DNS 的 UDP 会超时）。
名单可在运行中更新。系统 DNS 会写成"127.0.0.1 + 隧道 DNS"，转发器挂掉时系统改问隧道 DNS，只是暂时不分流，不会断网。
验证级别：回环 harness（`scripts/dns-forwarder-test.sh`，本机检查与 CI；假的上游 DNS，覆盖直连先于答复、只给 IPv4、
换服务器、TCP 回退、TCP 客户端、名单即时生效）；接入会话与真实网络效果见后续小节与本机实测。

### 26.5 B2：转发器与直连路由接入自建连接（2026-11-05）
- 自建连接（经转接）的每个会话：引擎在第一次启动 openconnect 之前起转发器（占 127.0.0.1:53；被占用时不分流、
  面板说明，全部走 VPN）。起来了才让 vpnc-script 把系统 DNS 写成"127.0.0.1 + 隧道 DNS"（`ALWAYSCONNECT_DNS_FIRST`）。
- connect 钩子多报物理默认网关（`physgw=`）；引擎据此把转发器的上游设好：隧道 DNS、物理网卡上 configd 记录的本地 DNS
  （取不到时用 DHCP 的），名单查询绑定物理网卡。
- 直连路由（`DirectRoutes`）：名单答复里的地址经物理网关加主机路由，**先写台账 `direct-routes`（首行开机标识）再加路由**；
  手动断开时先停转发器、按台账删直连路由，再走 §26.3 的撤销；后台服务启动时撤销本次开机的遗留、丢弃别的开机的；
  恢复工具按同一台账删除。
- 名单：新 XPC 方法 `setDirectDomains`（App 侧 3 秒超时回落），运行中改动立即生效。
- **尚未生效的一环**：连接期间网络闸门只放行网关与局域网，直连地址在物理网卡上仍被拦，要等闸门的直连地址表接口（B3，
  另一个 Thread 实现）接上后，按域名分流才真正可用。在那之前转发器只多了"换服务器、TCP 回退"这一点作用。
验证级别：路由计划桩测试（钩子带物理网关、DNS 首选 127.0.0.1）；会话 harness（直连路由台账：先记后加、去重、停止/启动/别的开机）；
转发器回环 harness；真实效果需本机实测（B5）。

### 26.6 B4：设置里的"不走 VPN 的网站"（2026-11-05）
`AppSettings.directGroups`（早期的两个预置网站组，见 `Sources/App/DirectSites.swift`）+ `directCustom`（用户自加），
合成去重后的名单；每次自建连接前、每次改动后经 `setDirectDomains` 发给后台服务（3 秒无回复提示"后台服务版本过旧"）。
界面见 UI-DESIGN §五"网络页：不走 VPN 的网站"。验证级别：本机构建与离屏渲染核对布局；真实分流效果待 B3 接上后实测。

### 26.7 B3：防火墙接入网络闸门的直连表（2026-11-05）
网络闸门的新接口（§25.8，另一个 Thread 实现）接上：自建连接开了转发器时，连上与掉线都以 `connected: false` 装同一套规则，
`localDNSServers` 为连接时物理网卡上的本地 DNS，`directTable: true`。于是在隧道之外只放行网关、局域网、DHCP/mDNS、
本地 DNS 的 53 端口和直连表 `<ac_direct>`：名单网站在 VPN 掉线时照常可用，其余流量连上时走隧道、掉线时被拦。
转发器的直连回调先加主机路由（台账），再同步 `addDirect`，两者都在答复交回之前生效；断开时闸门 release 清表，
直连路由按台账删除。验证级别：`generate-pf --dns --direct-table` 核对规则文本、本机全套检查；真实效果需本机实测（B5）。

### 26.8 B5 第一次实测：连上即断网——分流规则掐断了本机回环连接（2026-11-05，已修）
现象：用户切到自建连接、打开分流后连接，面板显示已连接，但整机立刻上不了网；用户用面板"恢复网络"恢复。
证据（后台服务日志 + 转接日志）：隧道 10 秒内建好、钩子正常（默认路由进 utun、DNS 指向转发器），紧接着 openconnect
报 "Read error on SSL session"；转接那一侧这条连接一直开着，整整 62 秒上行 0 个包；之后 openconnect 重连
连本机转接直接 "Invalid argument" 失败。
原因：分流模式下网络闸门装的是"连着与掉线同一套"规则（§26.7），末尾是 `block drop out quick all`；而回环口与隧道口
的放行写的是带状态的 `pass out quick on lo0 all`。pf 隐含 `flags S/SA keep state`，只有 SYN 能匹配，规则装上之前
就建好的连接——openconnect 到 127.0.0.1 证书转接那条 TLS 正是如此——后续包落到末尾的封锁上，隧道的载体被自己
掐断。第 1 批没出事是因为非分流模式连着时末尾是"物理口全放行"、没有封锁行。与 §23.6 网关放行是同一个坑。
修正：隧道口（含 utun0–63）与 lo0 的放行改为 `no state`；单测要求末尾封锁之前的每条按接口/按地址放行都不带状态。
验证级别：单测；CI macOS 上用真实 pf 装载生成的规则（末尾封锁收窄到 lo0，不影响 runner 网络）——先建好的回环
连接在装载后仍能收发、新连接可建，且旧规则作为反证必须掐断（scripts/pf-loopback-test.sh）。CI 首跑即复现了现场：
旧规则下不仅已建好的回环连接被掐断，新建的回环连接也超时——正是现场 openconnect 重连转接失败的那一步；新规则两者都通。
真实网关需用户复测。

### 26.9 B5 第二次实测：隧道能走数据，但转接到网关的 TCP 链路堵死（2026-11-05，待定方向）
§26.8 修正并更新后台服务后，用户在公司网络再连：隧道 68 秒内上行约 2.4 MB、下行约 1.3 MB（§26.8 的"0 包"已消失），
但用户仍感觉断网，约 1 分钟后手动断开。证据（均为本机普通权限可读的系统日志与转接日志）：
- 转接连向网关的那条 TCP（Network 框架连接摘要）：平滑 RTT 15.9 秒、重传 114 KB、乱序 97 KB；
- 系统解析器：发往转发器与两台隧道 DNS 的查询仅约两成得到答复，其中约 30 秒（15:24:50–15:25:20）全部无答复，
  之后一批迟到的答复同时到达——隧道整体停顿，不是转发器单独的问题；
- 同一时段、同一网络的对照（断开后测）：到网关 ping 60 ms 无丢包，加 4 MB 上传压力时延迟仍在 135 ms 以内，
  上行约 20 Mbps——物理网络本身正常。
判断（未完全坐实）：自建连接为了经转接出示证书而关闭了 DTLS（§22.2，`--no-dtls`），全部流量走一条 CSTP over TLS
的 TCP 连接；TCP 套 TCP 在抖动下两层重传互相放大（TCP meltdown）。11-04 在家里的验收流量小未暴露；用户此前
"连上后网速变慢"也与此相符。Cisco 平时用 DTLS（§20 采集）。可区分的对照：自建连接不开分流在同一网络跑同样负载。
可选方向（待用户定）：① 转接增加 UDP 转发，让 openconnect 的 DTLS 经本机转发到网关（DTLS 走主密钥会话恢复、不需要
客户端证书；须把 CONNECT 里依赖 TLS 导出密钥的 PSK-NEGOTIATE 去掉，网关是否接受需实测）；② 先做对照测试；③ 暂停分流。
无论哪条，自建连接都应加"连上后自检，不通即自动断开并恢复直连"的保险，不再依赖用户手动救网。
验证级别：现象与数据为本机实测；原因判断为推断。

### 26.10 自建连接打开 DTLS：转接加一条 UDP 通道（2026-11-05，用户选定"补 UDP 通道"）
§26.9 的堵塞来自"全部流量一条 TCP"。AnyConnect 的数据通道 DTLS 不需要客户端证书：openconnect 在 CSTP CONNECT 里带
`X-DTLS-Master-Secret`，网关在答复里给 `X-DTLS-Session-ID` 与 `X-DTLS-Port`，双方用这把主密钥做会话恢复。所以 DTLS
可以端到端地跑在 openconnect 与网关之间，转接只需原样搬运数据报：
- 答复 200 时，转接在本机 127.0.0.1 开一个 UDP 端口（临时端口，不占特权端口），把答复里的 `X-DTLS-Port` 改成它，
  再交给 openconnect；openconnect 的 DTLS 目标是它连 CSTP 的地址（127.0.0.1，`--resolve`）加这个端口。
  转接把收到的数据报原样发往"网关 IP:原 DTLS 端口"，回来的原样还给 openconnect；只收 127.0.0.1 来的数据报。
  这条 UDP 与 TLS 那条一样禁止走任何隧道（`prohibitedInterfaceTypes = [.other]`）；pf 的网关放行不分协议、不带状态。
- CONNECT 请求里 `X-DTLS-CipherSuite` 去掉 `PSK-NEGOTIATE`：它从 TLS 会话导出密钥，而 openconnect 的 TLS 会话是和转接的，
  不是网关的，选中就必然失败；其余套件、`X-DTLS12-CipherSuite`、主密钥原样。请求头改为"整段收齐再转发"，
  请求体（含密码）仍即到即转、不留存；答复头按字节改单个值，其他字节（含非 UTF-8 的横幅）原样。
- openconnect 去掉 `--no-dtls`。DTLS 不通时 openconnect 自己退回 TLS 通道（行为与改动前相同）。
- 转接日志记"udp channel: local port -> gateway port"与关闭时的 UDP 包数/字节数，便于判断 DTLS 是否真的在用。
验证级别：脚本级与 harness——RelayHarness 单元检查（请求改写、答复按字节改值）；relay-test 端到端：经真实转接，
网关收到的 CONNECT 无 PSK-NEGOTIATE 而其他套件与主密钥完好、答复端口被改成转接本地端口、小包与整包数据报双向原样到达。
真实网关是否接受经转接的 DTLS、公司网络是否放行这条 UDP：需实测。

### 26.11 自建连接连上后自检：30 秒不通就自动断开、恢复直连（2026-11-05，用户选定）
两次"面板写已连接、实际上不了网、要用户手动救网"（§26.8、§26.9）之后加的保险。自建连接每次连上后的头两分钟，
App 每轮同时向 4 个 HTTPS 地址发 HEAD（任何一个有 HTTP 答复即算通，含域名解析，走的是隧道/分流后的真实路径）；
连续至少 3 轮、且 30 秒内没有任何答复，就按"断开"处理（关 VPN、恢复直连），面板显示橙色说明、发一条通知，
建议改用"经 Cisco"。两分钟后不再检查，之后的掉线仍按断线保护处理。这是"只有用户手动断开才恢复直连"之外
唯一的例外：它只在会话刚建立、从未证明可用时生效，由用户明确要求（不再被困）。Cisco 方式不做此检查。
验证级别：规则为脚本级（scripts/connection-check-test.sh，含 §26.9 的真实时间线）；App 内的探测与自动断开需实测。

### 26.12 一个开关"按网站分流"；名单完全自定义；面板看得到分流在做什么（2026-11-05，用户反馈）
B5 第三次实测（§26.10 之后）用户反馈：用起来正常、没再断网（转接日志：44 秒 UDP 收发约 1.7 万包、10 MB，TLS 通道只 3 个控制包），
但①不知道分流有没有起作用；②"连接方式"应与分流绑定；③分流开关应在面板上；④不该固定预置的网站组，应让用户自定义。
- 开关与连接方式合一：存储仍是 `connectionMode`（own/cisco），界面只叫"按网站分流"。`HelperClient.setSplit(on:)`：未连接时直接切；
  连接中先断开，每 0.5 秒看一次，等状态回到"已断开"且网络不再暂停（最多 30 秒）再换方式并用已存凭据重新连接。本机没有 Cisco 时
  开关只决定名单是否生效（推给后台服务的名单为空）。
- 名单：新字段 `directSites`（名称 + 域名列表，按用户顺序）。第一次读取时把旧的 `directGroups`（开着的预置组）与 `directCustom`
  转成条目并清掉旧字段；预置组只用于迁移（"添加常用网站"菜单试了一版，用户认为没必要，已删）。合成 Codable 的可选字段缺失即 nil，旧设置可读。
- 分流可见：转发器的 onDirect 带上命中的名单条目；引擎记录本次会话命中的条目（最新在前、最多 20 个）与直连地址数，断开清零。
  新 XPC 方法 `getSplitActivity`（条目、地址数、是否有自建引擎），App 侧 3 秒超时回落（旧后台服务不答 = 不显示）。面板打开期间每 3 秒取一次。
- 通用页的"断线保护"在分流开启时写明"始终开启"而不是消失。
- 截图用离屏渲染时，渲染进程必须用独立的偏好域：一次渲染直接写进了用户真实的 App Group 偏好（`CFFIXED_USER_HOME` 对
  `UserDefaults(suiteName:)` 无效），当场已按用户截图时的状态还原（自建连接、旧预置组），之后改用改了 suite 名的副本编译渲染器。
验证级别：本机构建与全套检查（含转发器 harness 新签名）；离屏渲染截图核对布局；真实切换（连接中拨动开关自动重连）、面板实时命中显示需实测。

### 26.14 更新后台服务不用先断开（2026-11-05，用户反馈）
用户在连着时看到面板红黄闪烁：新 App 每 3 秒调用旧后台服务没有的 `getSplitActivity`，NSXPC 对未知方法会断掉整条连接，
App 立即重连，于是"后台服务未运行 / 有新版本"来回切换。修正一：只对与 App 包内同一份代码（CDHash 相同）的后台服务调用
该方法（§21.8 的比较）。我让用户"先断开再更新"，用户指出程序应能兼容各种状态。修正二：`HelperClient.installHelper`——
自建连接正在运行时（隧道在后台服务里，替换服务会把它粗暴带走），先断开、等收尾，再装，装完（成功或取消都）自动重连；
经 Cisco 时 Cisco 的隧道不受影响，装完只重发断线保护（`rearm`）。面板"更新"按钮走这条路，文案注明"更新时自动断开再重连"。
验证级别：本机构建；连着时点"更新"的真实效果需实测（重连时手机可能要再批准一次）。

### 26.13 名单支持 geosite / geoip / 网段；网络页并入分流页；本地局域网自动识别（2026-11-05，用户选定）
用户问"一个网站请求很多域名怎么管"、"能不能写「除了某地以外」这类规则"、"网络页跟分流很像"，选定做 geosite/geoip 写法与合并网络页
（不做"最近访问"），并补充"局域网直连默认开启、不要写死 192.168"。
- 名单每行一种写法：网址（含子域名）、`geosite:名字[@属性]`（v2fly domain-list-community）、`geoip:cn`、
  网段（单个地址记为 /32）。数据随 App 打包（Sources/App/GeoData，`scripts/make-geo-data.py` 生成：清单的 include/属性过滤/
  &归属全部展开成平面规则，共 1555 个清单、约 11.9 万条；geoip:cn 取 APNIC 公开分配数据合并成 5498 段）。
- App 侧（ListRules.swift）解析与展开：网址与清单变成后台服务的规则（`domain:`/`full:`/`keyword:`/`regexp:`），geoip:cn 变成
  `ipcidr:` 段；网段不交给 DNS 转发器，而是进断线保护放行名单（两种连接方式都生效），分流模式下另由后台服务经物理网关加路由
  （跳过 Mac 自己所在的网段，那段本来就直连，加网关路由反而会坏局域网），写进直连路由台账，恢复工具也能撤。
- 后台服务（SplitRules）：后缀按标签逐级查集合、精确名查集合、关键字与正则逐条；名字没命中时照常问隧道 DNS，若是 A 记录且答案
  落在 `ipcidr:` 段内（二分查找），先把这些地址加直连再回答——"解析到国内 IP 的网站直连"。旧 App 发来的纯域名名单照常工作。
  注意：公司放在国内公网 IP 上的服务也会被判直连；公司内网（10.x 等私网）不受影响。
- 本地局域网直连：默认开，自动取各个 en 网卡当前所在网段（最宽到 /16，跳过 169.254），不写死 192.168；网络切换时（NWPathMonitor）
  若正连着或断网暂停中，重新推送放行名单。网络页删除，Cisco 的"允许访问局域网"检查卡移到分流页（经 Cisco 时显示）。
  迁移：旧网络页的网段并入名单，当初默认的 192.168.0.0/16 去掉（由自动识别代替）。
验证级别：脚本级与 harness——list-rules（写法解析、清单展开与属性过滤、geoip 展开、本地网段）、dns-forwarder（各规则类型、
geoip 路径：答案落段即先直连再回答、段外留隧道）、session（台账含网段、移除）；本机构建与全套检查；离屏截图核对界面。
真实网关下 geoip:cn 的效果与网段直连路由需实测。

### 26.15 名单不再带预置网站组；写法示例与参考地址；泄漏自检的 DNS 项；不写死 192（2026-11-05，用户反馈）
- 旧版预置组不再迁移进名单；已迁移成条目的（名称与域名和预置组完全一致）启动时删除一次（`presetsDropped`）。
  输入框提示也不再举预置组的例子。
- 分流页加"写法示例"卡：github.com、geosite:google、geosite:cn、geosite:geolocation-!cn、geosite:apple@cn、
  geoip:cn、网段/单个地址，各配一句说明，点一下填进输入框；两条参考链接：domain-list-community 的 data 目录（全部清单名）与其
  README（属性与写法）。脚注注明清单是随 App 带的 2026-11-05 版本。
- 诊断"泄漏自检"的"隧道 DNS 已生效"一直红（"系统解析器：未读到"）：解析把 `nameserver[0] : x` 剩成了 `[0] : x`，永远对不上；
  输出里有非 UTF-8 字节时整段读成空。改为取冒号后的地址、按字节宽松解码、先读完管道再等进程；分流时系统先问 127.0.0.1 的
  转发器、隧道 DNS 排在后面，这算通过，并写明"名单外的域名交给隧道 DNS"。
- 补记（同日实测仍红）：真正的原因是自检调用 `/usr/bin/scutil`，而 scutil 在 `/usr/sbin`——进程根本没起来，输出为空，
  所以永远"未读到"。路径改正，并把源码里所有写死的工具路径逐个核对过存在（openconnect、pfctl 的多候选路径除外）。
- 诊断页"访问本地路由器"的脚注不再写"192.168 设备"。
验证级别：list-rules 覆盖示例全部可解析、@cn 有结果、预置条目识别与不迁移；本机构建与全套检查；自检项的真实结果需用户更新后台服务后再跑一次。

### 26.16 写法示例收进问号（2026-11-05，用户反馈）
用户觉得示例卡占地方，要折叠到问号里、悬停才出现、示例多一些或给官网。改为输入框旁一个问号：悬停是系统提示框，列 13 条写法与
说明；点击用浏览器打开 domain-list-community 的 data 目录。示例卡删除。验证级别：list-rules 覆盖全部示例可解析；本机构建。

### 26.17 更新后台服务不再多要一次手机批准（2026-11-05，用户反馈"弹了两次 手机审批"）
系统日志还原的时间线：用户点"连接"（转接 L1 启动，第一次批准推送），等批准时又点了"更新"；§26.14 的做法是先断开（openconnect 收到
SIGTERM 会向网关注销会话）、装、再自动重连，于是第一次批准作废、重连要第二次批准；服务重启后 App 原有的"后台服务重启后恢复"
（recoverAfterInterruption）又连了一次（用的是第二次批准得到的 Cookie，没再弹）。修正：
- 后台服务被停（更新、卸载）时用 SIGHUP 结束 openconnect：openconnect 断开但不注销会话，保存的 Cookie 仍有效；
- `installHelper` 不再自己断开、自己重连：直接替换服务，由既有的恢复逻辑用 Cookie 重连，不需要手机批准；
- 正在登录（连接中/认证中/等批准）时点"更新"，先等这次登录结束（最多 2 分钟）再更新，面板写"等这次登录完成后再更新…"；
- 经 Cisco 时不受影响，装完重发断线保护。
验证级别：本机构建与全套检查；openconnect 收到 SIGHUP 不注销、连着时更新无需批准，需实测（下次有后台服务更新时）。

### 26.18 问号提示悬停即显示（2026-11-05，用户反馈）
§26.16 的问号用的是系统提示框（`.help`），鼠标要停一秒左右才出来。用户要放上去就显示。改为通用的 `HoverHelp`：鼠标进入问号
立刻弹出小浮窗（popover，箭头指向问号、开在右侧，不压在鼠标下，不会因遮住鼠标而闪烁），移开即收起；点问号照旧在浏览器打开
清单名目录。浮窗内容排成两列（左边写法用等宽字、右边说明），底部一行说明 geosite 清单来源。分流页只有这一个问号，其余页面的
悬停说明是按钮的普通提示，不在此列。
验证级别：本机构建与全套检查；浮窗内容离屏渲染截图核对排版；鼠标悬停即弹、移开即收的实际手感需实测（装到"应用程序"后）。

### 26.19 断线保护两种连接方式都能关，默认开（2026-11-05，用户要求）
用户问"断线保护能加个开关吗？默认开"。查现状：经 Cisco 时开关一直在（面板与通用页，§21.6，关 = 不装 pf，掉线后 Cisco 自己重连、
流量走本地网络）；分流开启（自建连接）时通用页写死"始终开启"、面板不显示开关（§26.12），掉线时既有网络闸门的封网规则，
又有 vpnc-script 保留的路由（物理默认路由已被拿掉）把网卡住。补齐自建连接一侧，存储仍是同一个 `dropProtection`（缺省 = 开）：
- 新 XPC 方法 `setDropProtection(on)`：App 在每次自建连接前（与名单一起，XPC 保序）和每次拨开关时发；后台服务记住它，交给引擎，
  运行中的会话立即生效。只发给与 App 同一份代码的后台服务（§26.14，未知方法会断掉整条 XPC 连接）；不认或 3 秒不答的旧服务
  照旧始终保护，此时 App 照实显示"网络已拦截"，不谎称走本地网络。
- 引擎（只在调用侧加开关，NetworkGuard 接口不变）：关时 `loadPf` 只记下隧道与网关、不装任何规则集（连着与掉线都不装，与 Cisco
  一侧"关 = 不装 pf"一致）；掉线时不重装封网集，改为"交还本地网络"：按自己的 holder 释放闸门（没有就是空操作），route-state
  存在时跑一次脚本 `restore`（物理默认路由、去掉网关主机路由与隧道 DNS），然后照常重连；下次连上由 connect 脚本重新接管路由与 DNS。
  重连途中某次尝试没连上就结束时（`handlePostAuthFailure`）也再交还一次，覆盖"重试进行中才关开关"的情况。
- 连接中拨开关：关 → 立刻释放本引擎的规则集；若正处在两次重试之间（无子进程）同时交还路由。有子进程在跑时不动路由：它的 connect
  脚本可能正在改路由，此时恢复可能让连上的隧道没有默认路由；等它连上（关着就不装规则）或结束（上一条交还）。开 → 按当时形状装回：
  连着装原来的集，掉线中装封网集（路由已交还，由 pf 兜住）。释放会清空闸门的直连表，所以装回时先把本次会话转发器放行过的地址
  （splitAddresses）补回直连表，程序缓存的解析结果仍可直连。
- openconnect 在同一隧道内的短暂自重连（attempt-reconnect，隧道接口不消失）不算掉线，期间仍走隧道，开关不影响。
- 界面：面板与通用页的"断线保护"开关两种方式都显示；脚注按开/关与连接方式写后果；重连中的状态行、"网络已暂停"提醒与
  通知按开关走（`protectsDrops`）。
验证级别：本机构建与全套检查；会话 harness 新增两个场景（假 openconnect、记日志的 pfctl 桩）：关着连接—掉线—重连全程不装 pf、
不留"已拦截"状态；连着时关 → 释放、再开 → 重新装上，断开后全部归还。真实 Mac 上关着掉线后网络是否立即恢复、重连后路由/DNS
是否正确接管，需实测（下次掉线或用 drop-test 时）。

## 二十七、通用化：自包含、不绑公司、与其他 VPN 共存（2026-11-05，用户要求）
用户希望 App 在别人的 Mac 上也能跑、尽量自包含、极少依赖用户设备上的软件包，且不和公司特有的东西绑死；担心与 Clash、sing-box 冲突。

### 27.1 去掉写死的公司内容
- `Profile` 默认服务器、用户组改为空（原为公司的 Cisco 条目名与组名）；服务器列表照旧从本机 Cisco 配置读取，未选时取第一条；
  用户组为空即用网关默认组（openconnect 不带 `--authgroup`）。已保存的设置不受影响。
- 界面与通知里的"在手机聊天 App 上点批准"统一为"在手机上确认登录"；后台服务的状态文字同理。
- 后台服务与 Profile 里写死的 192.168.0.0/16 默认放行网段去掉：放行名单一律由 App 推送（名单网段 + 自动识别的本地网段，§26.13），
  连接前就推。开发用命令行 `run-once` 的 `--allow` 也不再有默认值。
验证级别：本机构建与全套检查（测试夹具里的网段与组名仍作示例值使用）。

### 27.2 识别其他 VPN 与代理（Clash、sing-box 等），只提示不干预
两个都要接管全部流量的 VPN（Clash/sing-box 的 TUN、增强模式，Surge 增强模式，WireGuard 等）会抢默认路由与系统 DNS，Cisco 与它们同开
也一样；只开系统代理时可以共存。App 不去改别人的设置，只把看到的情况说清楚（NetworkNeighbors）：
- 默认路由在 utun 上、却不是我们的会话也不是 Cisco 的 → 警告"××（或另一个 VPN）正在接管全部流量（utunN）……请先关掉它的 TUN/增强模式"；
- 认得的客户端在运行（按 bundle id：ClashX、Clash Verge、Mihomo Party、FlClash、sing-box、Surge、Stash、V2rayU、Quantumult X、
  Shadowrocket、Tunnelblick、WireGuard；按进程名：clash、mihomo、sing-box、xray、v2ray、hysteria、tun2socks）但没接管 → 提示可共存的条件；
- 分流开着、我们没连时 127.0.0.1:53 已有人答 DNS（常见于 Clash 的 DNS）→ 警告"连上后按网站分流会暂停"（§26.5 的退化）；
  检测用一次 DNS 查询而不是试绑端口（普通用户绑 53 一律 EACCES，试绑看不出来，本机实测）；
- 只有系统代理 → 提示一般可共存。
面板打开时检查一次（警告常显，提示只在未连接时显示），诊断页有"其他 VPN 与代理"一栏。
验证级别：分类规则为脚本级（neighbors-test）；本机探测实测（我们的转发器在 53 端口时被识别为"有人答"）；真实 Clash/sing-box 共存需实测。

### 27.3 openconnect 随 App 打包，用户机器不需要 Homebrew
- `scripts/bundle-openconnect.sh`：从构建机的 Homebrew openconnect 出发，按 `otool -L` 广度遍历收集全部非系统库（本机 13 个：
  libopenconnect、GnuTLS、Nettle/Hogweed、GMP、p11-kit、libtasn1、libidn2、libunistring、libintl、stoken、libtomcrypt、libtommath），
  用 `install_name_tool` 改成彼此就近加载（@loader_path），残留任何 /opt/homebrew、/usr/local、@rpath 即失败；逐个签名；附 VERSIONS
  与各组件许可证原文。build-local 把它放进 `Contents/Resources/openconnect`（App 约 17 MB）。
- 安全：后台服务以 root 运行 openconnect，而 App 包归用户、可写，所以 root 绝不从 App 包里执行。安装后台服务时（dev-helper install）
  把这份拷到 `/Library/PrivilegedHelperTools/AlwaysConnect-openconnect`（root:wheel、去掉组与其他人的写权限）；后台服务只在该路径
  逐级为 root 所有且他人不可写时才用它，否则退回 Homebrew 的（开发机）。卸载时一并删除。注意：后台服务"有新版本"的判断只比后台服务
  本体，单换 openconnect 时需手动"更新"一次。
- 运行时差异：打包的 GnuTLS 在别的 Mac 上没有自带的信任库（编译时指向 Homebrew 的 cert.pem），p11-kit 也找不到 Homebrew 的模块
  （无害）。经证书转接时 openconnect 用 `--servercert` 钉住转接的公钥，不依赖信任库；直连网关（不用证书）时，后台服务把 macOS 的
  根证书（系统钥匙串 SystemRootCertificates）导出成 PEM、每天刷新一次，以 `--cafile` 交给 openconnect。
- 顺带：安装脚本结束旧 openconnect 改用 SIGHUP（与 §26.17 一致，不注销会话）。
验证级别：本机——打包产物不再引用构建机路径（DYLD_PRINT_LIBRARIES 核对只从包内加载，p11-kit 的可选模块除外），
用打包的 openconnect 跑证书转接 harness 的引擎场景（经转接登录、取 Cookie、Cookie 重连）通过；CI 新增同样一步。
真实网关下用打包版连接：已实测（2026-11-05，经证书转接，见 mac-proof）；直连网关时的 --cafile、在没有 Homebrew 的 Mac 上安装：需实测。

### 27.4 打包与开销：不和本机已装的冲突，不变慢
用户追问打包后会不会和本机已装的冲突、会不会增加 CPU/内存。
- 不冲突：打包的 openconnect 只从自己的 lib 目录按精确路径加载（@loader_path），不进 PATH、不装系统级库、不碰 Homebrew 的那份；
  macOS 的两级命名空间也让同名库各用各的。唯一的交集是 p11-kit 若在本机找到 Homebrew 的 PKCS#11 模块配置会加载它（只读，不影响连接）。
- 开销：连接时仍是同一个 openconnect 进程（本机实测常驻约 10 MB，空闲几乎不占 CPU），和用 Homebrew 版时一样；App 包多 9 MB 磁盘。
- 名单数据：原先把 2.1 MB 的 geosite 文件整份解析成内存表并常驻，测得 App 多占约 20 MB。改为内存映射文件 + 只建"清单名 → 位置"的索引，
  用到哪个清单才临时展开、用完即释放：geosite:cn + geoip:cn 展开一次测得 +4 MB、12 ms（原 42 ms）。
验证级别：本机测量（mach task_info 的常驻内存、ps 的 RSS/CPU）；list-rules harness 覆盖新的读取方式。

### 27.5 后台服务重启被记成"断了 2 秒，停止重试，没恢复"（用户反馈）
重连策略本身没变：自建连接掉线后无限重试，间隔 1、2、5、10 秒，之后每 30 秒，带抖动，从不放弃（core/src/backoff.rs）。
用户看到的那条记录发生在他点"更新"后台服务的那一刻：旧服务退出时连接随之结束，App 随后的"服务重启后恢复"把服务报告的"已断开"
直接套用，掉线记录当场以"停止重试"收尾，而 App 紧接着就重新连上了（那次会话又跑了约 30 分钟）。修正：服务重启时若之前在连接，
按"重连中"处理并发起重连，记录等重连结果再定（恢复 / 失败）。另：证书转接 harness 的日志改写到临时目录，不再混进用户的 relay.log。
验证级别：本机构建与全套检查；真实更新时的记录需实测。

## 二十八、日常稳定性（方案二 C 批：换网络、睡眠唤醒、IPv6、长跑）

### 28.1 换网络：网关的路、直连路由、本地 DNS 跟着走；内部重连如实显示（2026-11-05，用户实测出问题）
现象：用户在公司连着自建连接合盖下班，到家连上 Wi-Fi 后断网约 3 分钟，面板一直显示"已连接"，最后一次全新的连接才恢复。
转接日志还原：离开公司时转接到网关的连接"另一条路更好 / 不可用"，但转接没有关它，openconnect 到转接的本机连接一直健康，
于是 openconnect 没察觉（睡眠期间计时器也停了）；醒来后 openconnect 的内部重连每次都卡在"连不上网关"——去网关的主机路由还指向
公司路由器；内部重连期间引擎不向 App 报状态，面板仍是"已连接"。修正：
- vpnc-script 的 `attempt-reconnect`（openconnect 每次内部重连前调用）：用"按网卡限定的默认路由"找当前物理网络（先看原网卡，
  再看其他 en* 网卡，覆盖 Wi-Fi 换有线、手机热点），变了就先记台账、再把网关主机路由改过去，并通过钩子报给引擎；`reconnect` 也报。
- 引擎：收到 `attempt-reconnect` 即视为"重连中"（面板变红、掉线记录开始），网络变了时把名单直连路由改到新网关（DirectRoutes.repoint）、
  重取本地 DNS、更新转发器、重新计算名单网段路由（避开新所在网段）、按新本地 DNS 重载防火墙；收到 `reconnect` 回到"已连接"。
- 证书转接：网关连接不可用持续 8 秒、或系统报告另一条网络接管 3 秒后，主动结束这对连接，让 openconnect 立刻重连（而不是等 DPD）。

补充（同日，用户要求"回家路上和到家后不漏网、名单里的照样直连"）：上面的跟随只在 openconnect 内部重连时发生；若它已放弃、
后台服务在反复新起连接而隧道迟迟连不上，名单直连会一直指向旧路由器。现在分流开着时后台服务自己每 5 秒从 configd 读一次
物理网络（有线/Wi-Fi 服务的 Router，隧道占着默认路由时也读得到），一变就执行同样的跟随（直连路由、本地 DNS、名单网段、防火墙），
不等隧道；新起的连接在 connect 钩子里发现网络变了也会把本会话的直连路由改过去。期间名单外的流量仍被拦（不漏），名单里的网站与
本地局域网照常可用。验证级别：本机构建与全套检查；configd 读取在本机试过；真实回家路上的表现需实测（mac-proof I13）。
另：用户到家后打不开 192.168.100.1（光猫管理页，在家用路由器外一层）——它不在自动识别的本地网段里，按规则进了隧道；
需要时在名单里加 `192.168.100.0/24`（或整段 `192.168.0.0/16`），立即生效。这是"不写死 192"的取舍，界面不默认放行整段。

### 28.2 睡眠唤醒
合盖时网关连接随之失效；醒来后系统把这条连接标为不可用或换了网络，按 §28.1 由转接在几秒内结束它，openconnect 立即走内部重连，
attempt-reconnect 先把路改对。没有另加"唤醒通知"的通道：触发点在网络本身，同一条路径覆盖睡眠与换网络。

### 28.3 IPv6：分流时所有域名只给 IPv4 答案
隧道只配 IPv4，分流模式下 pf 也拦掉从 Mac 出去的 IPv6；若照常把隧道 DNS 的 AAAA 答案交出去，双栈网络（家里常见）上的程序会先试
IPv6、卡到超时才退回 IPv4。转发器对名单外的域名也直接回空的 AAAA（名单内本就如此，§26.4）。
验证级别：dns-forwarder harness（名单外 AAAA 为空且不问隧道 DNS）；双栈网络下的体感需实测。

§28.1–28.2 验证级别：脚本级（vpnc-route-plan：换网络改网关路由并更新台账、同网络不动、换到另一块网卡、暂无网络时不动、
reconnect 上报）；引擎整环（假 openconnect 模拟一次内部重连：状态先"重连中"再"已连接"，local-checks 与 CI）；本机构建与全套检查。
真实换网络、合盖再打开需实测（mac-proof I13）。

### 28.4 长时间运行的记录脚本
`scripts/soak-check.sh`：只读、无需管理员，每分钟一行——经隧道打开一个网页的结果与耗时、默认路由、App/后台服务/openconnect 的
常驻内存与 CPU，写到 /tmp/ac-soak.log。用于连续几小时观察是否有泄漏、变慢或悄悄断掉。验证级别：脚本可运行（本机试跑）；长跑结果需实测。

### 28.5 局域网默认放行：公司网关自己声明不走 VPN 的私网段
用户问能否默认放行局域网网段（到家后打不开光猫管理页 192.168.100.1）。一刀切放行全部私网段不行：公司内网本身就在 10.x 等私网段
（隧道地址与隧道 DNS 都在里面），放行会把公司流量送去本地网络。折中：网关下发的分流排除名单（CISCO_SPLIT_EXC_*）里属于私网段的
（10/8、172.16/12、192.168/16、169.254/16 之内）——也就是公司自己声明不走 VPN 的那些——自动当作直连网段：断线保护放行，分流模式下
经物理网关加路由（跳过 Mac 所在网段）。这台网关的排除名单里有 192.168.0.0/16，所以家里所有 192.168 开头的设备（含光猫）默认直连，
与经 Cisco 时一致；公司没排除的私网段不受影响。vpnc-script 的 connect 钩子带 `lanex=`，引擎与用户名单里的网段合并使用。
验证级别：vpnc-route-plan（公网段被滤掉、私网段上报）；本机构建与全套检查；真实效果需实测（装新版后打开 192.168.100.1）。
实测后修正（2026-11-06）：装上后 192.168.100.1 仍进隧道。原因是"跳过 Mac 所在网段"写成了"跳过任何与之重叠的网段"，
192.168.0.0/16 包含家里的 192.168.50.0/24 就被整段跳过。改为只跳过落在所在网段之内的（它本身及其子网），包含它的大网段照常
经物理网关加路由（直连的 /24 更具体，局域网不受影响）。session harness 固定了这条规则。

### 28.6 App 内存（用户要求优化）
本机测量（连着自建连接、开过设置窗口）：App 实际内存占用（footprint，活动监视器显示的那个数）约 74 MB，RSS 约 130 MB（含与系统共享的部分）；
其中堆约 44 MB，大头是 SwiftUI 的视图树。两处改动：
- 设置窗口关闭后连同四个页面一起释放（原先第一次打开后常驻到退出），下次打开再建；
- 证书转接的 UDP 转发每收一个数据报都新分配 64 KB 缓冲，改为每对连接一块复用（有流量时每秒上千次分配，也省 CPU）。
此前已改：网站清单数据按需读取（§27.4，省约 16 MB）。后台服务约 15 MB、openconnect 约 10 MB，不在此列。
验证级别：本机构建与全套检查；改后的实际占用需装上新版后复测（`footprint <pid>` 或 soak-check）。

### 28.7 设置里的"连接"页：哪些走 VPN、哪些直连，哪个程序、访问什么
用户想在设置里看到本机所有网络情况。新增"连接"页（通用 / 账号 / 分流 / 连接 / 诊断）：
- 后台服务（root，看得到所有程序）用 `lsof -nP -iTCP -sTCP:ESTABLISHED -iUDP +c 0 -F pcPn` 列出已建立的连接（只取 IPv4，§28.3），
  每个远端地址问内核走哪块网卡——经路由套接字（RTM_GET + RTA_IFP），不起进程，500 次约 4 ms（`route -n get` 每次起进程，
  一页 40 多个地址要 1–2 秒）。原因按本会话的设置判断：隧道口 = VPN；网关 = VPN 隧道本身；直连表里的地址 = 名单直连；
  名单网段与网关声明的私网段（§28.5）= 局域网；其余本地网卡 = 直连；lo0 = 本机。
- 地址名：分流开着时转发器记下最近答复过的"地址 → 域名"（上限 4096，满了清空），连接页显示域名；否则显示 IP。
- 新 XPC 方法 `getConnections`（JSON），App 侧 3 秒超时；旧后台服务不调用（§26.14 的教训）。整页一次约 0.15 秒（本机实测）。
- 界面：全部 / 走 VPN / 直连 筛选、搜索、汇总（走 VPN N 条 · 直连 N 条 · 本机内部 N 条），同一程序 + 地址 + 走向合并成一行带 ×次数，
  直连的排在前面；打开时每 5 秒刷新，关掉设置窗口即停（§28.6 释放窗口）。
验证级别：connections-test（分类、内核路由查询与耗时）；本机以普通用户身份列出连接并离屏截图核对；root 下全量列表需装新版后实测。
补充（同日，用户问能否看到协议）：连接页加"协议"列，由传输层（TCP/UDP）与远端端口推断常见应用协议（HTTPS、QUIC、DNS、SSH、
邮件、Apple 推送、NTP、STUN、远程桌面等，网关的 TLS/DTLS 端口标为 VPN），并照写"TCP/UDP 端口"；只按端口判断，不看包内容。

## 二十九、等手机批准时的提醒

### 29.1 菜单栏图标下的提醒气泡（2026-11-06，用户要求）
原先等批准只有一条系统通知（不带声音、几秒就收起的横幅）加菜单栏变黄，用户在电脑前也常错过手机上的批准。
用户定的方向：不要声音；人一般就在电脑前；要的是"提醒"，不是挡住操作的强弹窗；从菜单栏图标处弹出。
现在：
- 进入等批准时，从菜单栏 AlwaysConnect 图标下方弹出一个小气泡（箭头指着图标，像面板那样），写"请在手机上批准 VPN 登录"、
  "登录请求已发到手机 · 已等 0:23"（批准超时后重新发起时写"第 N 次请求"）；手机图标外有一圈慢慢扩散的波纹。
  批准后变"已批准，正在连接…"，连上变绿色"已连接"，停 1.6 秒自己收回。被拒、断开、批准超时（等下次重新发起）时直接收起。
- 不抢键盘焦点（不激活 App 的面板窗口），所有桌面与全屏 App 上都在；图标不在屏幕上（全屏时菜单栏藏起、刘海挤掉图标）时改在屏幕顶部正中、不带箭头。
- 点气泡打开菜单栏面板；× 只隐藏这一次等待，下一次请求再出现；从图标打开面板时气泡让开。
- 计时只显示"已等多久"，不做倒计时：网关批准过期的时长没有实测（§21.19 只测了过期后的文案），不猜。
- 自建连接：§30.9 起引擎按"密码发出 3 秒仍无答复"识别等批准（掉线后的重新登录也算），气泡与 Cisco 一样显示"请在手机上批准 VPN 登录"；
  在那之前的"登录中"持续 3 秒以上时先显示"正在登录 VPN / 手机收到批准请求时请点批准"，随后转成等批准仍算第 1 次请求，
  登录中被隐藏的，这次登录的等批准也不再弹出（tracker 断言覆盖）。
- 气泡开着时，等批准的系统通知不再重复发；屏幕锁定时（看不到气泡）照发。设置 → 通用"等手机批准时在菜单栏下提醒"（默认开）可关掉，关掉即回到只发通知。
- 外观：装机后用户实看（深色菜单栏）反馈毛玻璃底与背景混在一起、不醒目；试过实心色块、彩色边缘光，用户都否定（花哨）。
  定为黑白、不画边框：系统毛玻璃底，从边缘向外的一圈柔和光晕（模糊的同形状挖掉气泡本身，只在外面；深色模式白色、浅色模式淡淡的暗色；
  窗口向上多留 10 pt，箭头周围的光晕不被截平），等批准时缓慢呼吸
  （"减少动态效果"打开时不动）；只有左侧图标带颜色（用户要求）：等批准橙色手机、连接中蓝色省略号、已连接绿色对勾。（中途试过黑白描边，用户认为边框颜色不自然，去掉。）
- 弹出逻辑（什么状态弹、更新、收起、第几次请求、隐藏只管一次）单独成 ApprovalPromptTracker（只依赖 Foundation）。
验证级别：脚本级断言 `scripts/approval-prompt-test.sh`（已进 local-checks 与 CI）；外观为离屏渲染核对；
真实菜单栏下的位置、不抢焦点、全屏上的显示、真实等批准时弹出与收起：**需实测**（mac-proof D7）。
本机实测（2026-11-06，用户截图）：自建连接登录 → 批准后气泡在菜单栏图标下显示"已连接"并收回，位置正确；醒目程度不够，已按上条改为毛玻璃 + 边缘光晕，改后待用户再看。
同日装上最终版后实测：开着"按网站分流"连接，转接日志记下密码提交后 15.6 秒网关才答复（等手机批准），App 状态 awaitingApproval → 已连接；
用户反馈光晕连气泡内侧也亮、看着怪，改为只向外。

## 三十、核心流程边界场景梳理（2026-11-06，用户："点了后台更新后卡住断网……把核心流程梳理一下边界场景都整一整"）

### 30.0 起因：更新后台服务后卡在"正在连接"，整机断网
用户连着自建连接点"更新"后台服务：面板停在"正在连接…（spawning openconnect, attempt 1）"，电脑断网，点"恢复网络"才好。
转接日志：更新后约 80 秒里每次转接连网关都是 20 秒握手超时，网关一侧始终没有回应（openconnect 一侧是好的）。
原因：网关的域名背后有两个地址，DNS 轮流给（本机连查 6 次，两个地址各 3 次）。后台服务重启时网络闸门接管旧的封网（§25.2，正确：
更新那一刻不漏），但那套规则只放行旧会话用的那一个网关地址；App 随后重连、重新解析网关，一半概率拿到另一个地址——被自己的封网挡住，
登录永远进不去，封网又一直有效。上一次更新没出事是碰巧拿到了同一个地址。
同时发现"断了 2 秒，没恢复"那条掉线记录又出现：新服务在 App 接上时先推送"已断开"，比 §27.5 的恢复逻辑早到，记录当场收尾。
之后用两路独立走查（生命周期、网络状态）把核心流程逐个状态过了一遍，下面按主题记录改动；30.7 是总表。
验证级别：根因来自转接日志 + 本机 DNS 实查 + 代码路径；修复由 session harness 复现（修前失败、修后通过）；真实更新需实测（mac-proof I15）。

### 30.1 断线保护交接：新引擎启动时接管已在封网的规则
任何时候自建连接的新引擎启动，若闸门里已经有一套封网（来源三种：后台服务重启后接管的、被替换的旧引擎留下的、登录被拒后留下的），
新引擎立即以自己的名义接管：仍是封网规则，但放行的网关地址换成这次转接用的地址，局域网用 App 刚推送的列表；面板按"掉线恢复中"显示
（红色"重连中"，不是黄色"正在连接"——那时整机确实是封着的）。断线保护关着时，新引擎启动即放开这套规则。
替换引擎（App 重开、换网关地址、"保存并连接"）以前是"旧的先完全停下、放开封网、恢复路由，新的再登录"——新登录期间整机走本地网络，
若要手机批准就一直漏着（F12 说过"期间不漏"）。现在：替换开始时先让旧引擎的名义失效（它下线时的放开被忽略），新引擎启动即接管；
同一服务器 + 账号的替换用 SIGHUP 让旧 openconnect 不注销会话离开，新引擎沿用 Cookie，不再要手机批准。
另外：没有引擎时关掉断线保护，会放开留下的封网；没有引擎时 App 推送的新局域网列表也写进留下的封网（以前被丢掉，换了网络局域网仍被封）；
没有引擎时的放开会一并撤掉分流的直连路由。后台服务记住 App 最后推送的局域网列表，新引擎从第一秒就放行局域网。
验证级别：session harness `takeover-adopted`、`takeover-replace`、`protection-off-adopted`、`held-allow-update`（假 openconnect + 记录 pf 规则文本的 pfctl 桩）。

### 30.2 换网络：去网关的路由、直连网段、局域网路由
- 去网关的主机路由以前只在 openconnect 自己内部重连（attempt-reconnect）时跟着走。openconnect 进程退出、引擎在两次尝试之间时换了网络，
  每次新尝试都经旧路由器去网关，永远连不上；新尝试的 connect 脚本又只看默认路由（掉线后已没有），回落到台账里的旧路由器。
  现在：每 5 秒的网络检查不再只在分流时运行，发现变化就让脚本 `follow-network` 把网关主机路由与台账一起挪到新路由器；
  connect 在没有物理默认路由时先查各 en* 接口的作用域默认路由（`physical_now`），最后才用台账。
- 直连网段路由：以前 `route add` 失败就 `route change`，并照样记进台账——会把别的接口的子网路由（Wi-Fi 与有线同时在用）
  或系统自己的局域网路由改走另一个路由器，断开时又按目的地删掉，局域网直到接口重连前都不通。现在网段只 add、加不上就不记；
  所有在用的 en* 子网都不加路由；换网络后已变成本机所在网段的那条由我们删掉，并补回该网段的接口路由（我们的路由先占了位置，系统没能加上）。
  紧急恢复脚本删直连网段后同样补回各 en* 的接口路由。
- 名单答复里若有 VPN 网关自己的地址或本机局域网里的主机，不再给它们加直连路由（网关的主机路由属于会话，删直连路由时会把它一起删掉）。
验证级别：路由计划桩测试 3 个新步骤；session harness 的网段筛选；真实换网络需实测（mac-proof I13）。

### 30.3 停止、清扫与紧急恢复
- 用户断开后、openconnect 注销的几秒里，迟到的连上通知 / 网络跟随 / 名单更新不再重新加载封网；在途的名单 DNS 答复不再在清理之后补加直连路由。
- 后台服务启动时清扫上一次崩溃留下的 openconnect 改用 SIGHUP（SIGTERM 会注销会话，App 恢复时要重新手机批准）。
- 引擎替换的兜底等待由 10 秒改为 20 秒：旧引擎的路由恢复不应落在新会话的路由上。
- 紧急恢复脚本（桌面双击版）先卸下后台服务再结束 App：以前先杀 App，后台服务看到 App 没了而自己还在封网，会立刻把 App 拉起来，
  拉起的 App 又自动连接，恢复等于白做。结束时把后台服务重新加载（空闲，随用随起）。默认路由修复改为遍历所有 en* 接口。
验证级别：脚本 `--dry-run` 与语法检查；session harness 全套。

### 30.4 App 侧的状态
- 后台服务重启：App 记下"正在等服务恢复"，期间服务推送的"已断开"不作数；恢复失败（服务 2 秒后还没起来）每 7 秒重试一次，最多半分钟；
  "更新"完成时若 App 没收到中断，由安装完成本身启动恢复。掉线记录按一次掉线收尾为"已恢复"。
- "强制恢复网络"（后台服务不响应时）：期间同样不触发"服务重启后自动重连"，用户刚要回网络，VPN 不再自己连回去。
- 自建连接的 30 秒自检（§26.11，唯一的故障开放例外）只用于一次会话的第一次连上；掉线后重连、唤醒、服务重启后的恢复不再触发
  （以前每次回到"已连接"都重新开始两分钟窗口，用了几小时的会话也可能因为一次慢恢复被关掉、走本地网络）。
- "更新"等登录完成最多 2 分钟，只等一次（以前等完会重新开始等）。
验证级别：本机构建与全套检查；真实更新与重启需实测（mac-proof I15）。

### 30.5 App 与后台服务一起更新
后台服务以 root 运行、装在系统目录，替换它必须管理员授权，这是 macOS 的规则；让后台服务自己从 App 包里拷新版本可以免密码，
但 App 包普通程序就能写，等于给任何程序一条拿 root 的路，不做。能做到的是合成一步：App 启动时发现后台服务比自己旧、且没有会话在跑，
先弹管理员密码框更新，再自动连接；取消则照旧连接，面板仍提供"更新"。这样也避开了"连着的时候换后台服务"。
完全免密码需要苹果开发者账号签名（SMAppService 随 App 一起更新），属于另一个决定。
验证级别：本机构建；真实安装后的首次启动需实测（mac-proof I15）。

### 30.6 网关地址：沿用与换址
App 记住每个网关名解析到的全部地址和上次用的那个（本机 UserDefaults，不进仓库）：重连时上次的地址只要还在解析结果里就沿用；
DNS 暂时解析不了（掉线时系统 DNS 指向已断的隧道）就用记住的地址。转接连续 3 次（约 1 分钟）openconnect 在、网关不回应，
就换同一网关的另一个地址重连（经 30.1 的交接，封网不断、会话不注销）；只有一个地址时不换。
验证级别：relay harness 的地址选择断言；真实换址需实测。

### 30.7 边界场景总表（自建连接，分流开）
| 场景 | 期望 | 机制 | 验证 |
|---|---|---|---|
| 连接中/已连接时更新或后台服务崩溃重启 | 封网不断，新服务接管后放行新网关地址，面板"重连中"，恢复后记"已恢复"，不重新批准 | 30.1 接管 + 30.4 恢复 + SIGHUP | harness；I15 |
| App 崩溃后被拉起 / 用户重开 | 同上（不漏、不重新批准） | 30.1 替换交接 | harness；需实测 |
| openconnect 内部重连时换网络 | 网关路由、直连路由、本地 DNS、封网跟着走 | §28.1 | 桩测试；I13 |
| openconnect 退出后、两次尝试之间换网络 | 同上 | 30.2 follow-network + physical_now | 桩测试；需实测 |
| Wi-Fi 与有线同时在用 | 两个局域网都直连可达，断开后系统路由完好 | 30.2 网段筛选与只 add | harness；需实测 |
| 换到名单里某网段所在的网络 | 局域网可达；断开后接口路由仍在 | 30.2 删除后补接口路由 | 需实测 |
| 网关某个地址不通 | 约 1 分钟后换另一个地址 | 30.6 | harness；需实测 |
| 登录被拒后留下封网，再换网络 | 新局域网放行；关断线保护可放开 | 30.1 | harness |
| 断开过程中的迟到事件 | 不重新封网、不补路由 | 30.3 | 代码路径 |
| 强制恢复 / 桌面恢复脚本 | 恢复后不自动连回去 | 30.3、30.4 | dry-run；需实测 |
| 已连几小时后一次慢恢复 | 不被自检关掉 | 30.4 | 需实测 |
| 新版 App 首次启动 | 一次密码更新后台服务，然后连接 | 30.5 | I15 |

### 30.8 已知未做
- 名单里删掉一个网站后，本次会话已为它加的直连路由与直连表条目要到断开才撤（新的查询已不再直连）。
- 掉线期间先放开再重新打开断线保护：系统 DNS 已恢复为本地 DNS，名单网站在下次连上前不会直连。
- 交接期间（新引擎登录前）系统 DNS 是本地 DNS，查询的域名对本地网络可见（流量仍被封）；与后台服务重启时相同。
- 只有 IPv6（NAT64）的网络上自建连接无法重连（封网只按 IPv4 放行网关）。
- （已补，见 30.9）自建连接重新登录时的等批准识别。

### 30.9 自建连接的等手机批准：按"密码提交后网关不回"识别（2026-11-06，用户："把缺口补上，你自己去验证"）
网关等手机批准时什么也不输出（§16.5、§23.4 的"没有可识别的文字"），但有固定的形状：openconnect 把带 `<password>` 的认证回复发出去后，
网关一直不回，直到手机点了批准（或请求过期）才回。证据：
- openconnect 9.21（App 打包的同一版）对本地模拟网关的真实输出：密码请求体是一行 `> <config-auth …><password>…`，
  回复以 `Got HTTP response: HTTP/1.1 200 OK` 开头；
- 真实网关的转接日志：每次需要批准的登录里，同一对连接从打开到隧道建立隔 12–17 秒（就是用户点批准的时间），不用批准的 Cookie 重连约 1 秒。
做法（后台服务）：看到密码请求后 3 秒内网关没回 → 状态切到"等手机批准"（掉线重连时也如此，所以 §29.1 的提醒气泡会弹）；网关一回就退出等待，
后面照常判（连上 / 被拒 / 退出）。密码提交到"Login failed"超过 20 秒 → 是批准过期（没人点），不是密码错：按 30/60/120/300 秒（±20%）
重新发起，没人理满 1 小时后每 15 分钟一次（与 Cisco 引擎 §21.19 同一规则）；瞬间的"Login failed"仍按密码错立即停下（防锁号）。
引擎自带的 120 秒批准超时在 openconnect 还在等网关时不再另起第二个登录（以前会两份并行）。
自证手段（不需要管理员权限）：转接把登录过程的"形状"写进 ~/Library/Logs/AlwaysConnect/relay.log——哪种请求、是否带密码、网关多久回、
状态码、表单的 auth id 与提示文字；不记请求头、路径、Cookie 或任何输入的值。App 的状态变化也写进同一个日志（"app state: A -> B"）。
验证级别：`scripts/approval-wait-test.sh`（真 openconnect + 模拟网关挂起/过期/拒绝四种情况，旧引擎下 6 项失败、现在全过；已进 local-checks 与 CI）；
转接日志的登录记录与不泄密由 relay harness 断言。
真实网关实测（2026-11-06 14:16，用户按要求隔十几秒才点批准）：转接日志依次为 06:16:23 "POST with the password sent"、
06:16:26 "app state: authenticating -> awaitingApproval"（3 秒后识别为等批准）、06:16:39 "POST (password) answered after 16.4s: 200 auth=success"
与 "awaitingApproval -> authenticating"、06:16:41 "-> connected"；前两次请求（账号表单）都在 0.1 秒内回。即：网关确实扣住密码的回复直到批准，识别与退出都对。
批准过期也已实测（同日 14:21，用户故意不点）：06:21:41 密码发出，3 秒后等批准；**100.6 秒**后网关回 200，内容是重新给出账号密码表单
（auth=main，"Please enter your username and password."），没有单独的"过期"字样；引擎按"提交 20 秒后才失败 = 批准过期"处理，
29 秒后（30 秒 ±20%）重新发起，手机收到第二次请求，用户点了，6.4 秒后网关回 auth=success，06:24:00 连上。即：网关的批准有效期约 100 秒，
过期不会被当成密码错而停下。

### 30.10 切换 Wi-Fi：换了出口地址要重新批准；切回时白等 20 秒（2026-11-06 实测）
用户连着自建连接，先切到手机热点，再切回公司 Wi-Fi（转接日志与每 5 秒的网络探测，含从 en0 强制直连的漏网探针）：
- 两次切换后都自动重新连上，去网关的路由跟到新路由器，漏网探针全程被挡（000）。
- 两次都要手机重新批准：openconnect 先用原会话重连，网关立刻断开连接（两次，各约 1 秒），引擎随后用密码登录。
  对照第一轮"关 Wi-Fi 再开"（回到同一网络、出口地址不变）原会话直接续上、无需批准，判断为网关按出口地址认会话——网关的规则，客户端改不了。
- 切到热点 3 秒内就发出了批准请求；切回 Wi-Fi 却用了 27 秒：切换那一刻转接新开的网关连接绑在热点的地址上，换网后这个地址已失效，
  握手永远等不到回应，白等满 20 秒超时，之后两次原会话重连被拒，才走密码登录。
修正（App 的证书转接）：监视物理网络（不含自己的隧道），一有变化就放弃所有还在握手的网关连接，openconnect 立即在新网络上重来；
另外 openconnect 已连上而网关 10 秒仍未应答就放弃（原来 20 秒，真实网关正常 1–2 秒内应答）。预计切回时也是几秒内发出批准请求。
验证级别：本机构建与全套检查；切网效果用户说小改动不必再测（需实测时看转接日志"network changed during the handshake"）。

## 三十一、干净卸载（2026-11-06，用户："程序里提供一个干净卸载能力，无残留"）

### 31.1 入口与选项
设置 → 通用最下面一张"卸载"卡片：[卸载…] 展开行内确认，说明会断开 VPN、恢复直连、删掉什么、要一次开机密码、不动 Cisco；
两个开关"保留账号密码（钥匙串里）""保留设置（服务器、分流名单等）"，**默认都关 = 什么都不留**（用户要求无残留；保留是给"卸了再装"的人）。
App 打不开时同样的事在终端做：`sudo bash /Applications/AlwaysConnect.app/Contents/Resources/uninstall.sh [--keep-settings] [--keep-password]`；
`--dry-run` 只列出会删什么（不需要管理员权限）。

### 31.2 留在系统里的东西（盘点）与谁来删
| 东西 | 位置 | 删法 |
|---|---|---|
| 封网、路由、DNS、直连路由、pf 锚点与我们的 pf 开启引用 | 内核 / scutil State: | reset-network.sh（与"恢复网络"同一份，§24.6），加 `--keep-unloaded` 不再把后台服务装回 |
| 后台服务 | /Library/LaunchDaemons/com.alwaysconnect.app.helper.plist、/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper | launchctl bootout 后删除 |
| 随附 openconnect（root 份） | /Library/PrivilegedHelperTools/AlwaysConnect-openconnect | 删除 |
| 台账与会话：guard.json、pf-state、route-state、direct-routes、manual-disconnect、session.json（Cookie）、relay/（转接客户端私钥）、system-roots.pem、vpnc 脚本 | /Library/Application Support/AlwaysConnect | 整个目录删除（台账先由 reset 撤销） |
| 后台服务日志 | /Library/Logs/AlwaysConnect | 删除 |
| 转接日志、用户域 vpnc 脚本（测试时的回落位置） | ~/Library/Logs/AlwaysConnect、~/Library/Application Support/AlwaysConnect | 删除 |
| 缓存、HTTP 存储、窗口恢复状态 | ~/Library/Caches、HTTPStorages、WebKit、Saved Application State 下的 com.alwaysconnect.app | 有则删除 |
| 设置：服务器、分流名单、用户名（App Group 域）；窗口位置、网关地址缓存、掉线记录等（App 域） | ~/Library/Preferences/group.com.alwaysconnect.app.plist、com.alwaysconnect.app.plist | 未选保留时先 `defaults delete`（经 cfprefsd，不会被缓存写回）再删文件 |
| 离屏渲染留下的偏好（开发构建） | ~/Library/Preferences/group.com.alwaysconnect.render.plist | 删除 |
| 钥匙串密码 | 登录钥匙串，服务名 com.alwaysconnect.app（所有账号） | 未选保留时：App 里由 App 自己删（KeychainStore.deleteAll，不弹授权）；终端里用 `security delete-generic-password` |
| 开机自动打开 | SMAppService 登录项 | App 里 unregister；终端卸载做不到，App 删掉后系统登录项失效 |
| 隐私授权（快捷键用的辅助功能） | TCC | `tccutil reset All com.alwaysconnect.app` |
| 桌面"AlwaysConnect 恢复网络.command" | ~/Desktop | 内容带我们的标记行时删除，同名的别人文件不动 |
| App 本身 | 正在运行的那份 + /Applications/AlwaysConnect.app | 只删 CFBundleIdentifier 为 com.alwaysconnect.app 的包 |

不碰：Cisco Secure Client 的一切（程序、后台服务、配置、它自己的 VPN 会话）、钥匙串里公司发的证书、构建机上的开发签名身份
"AlwaysConnect Local Dev"（scripts/dev-signing-identity.sh 造的，属于构建工具不属于 App；要删在钥匙串访问里删）。
删除函数只删名字里带 AlwaysConnect 的路径，防止参数出错误删。

### 31.3 顺序（取消密码框什么都不变）
1. App 以管理员身份运行包里的 uninstall.sh `--from-app`：它只把自己和 reset-network.sh 复制到 root 专用的 /private/tmp 临时目录，
   后台起一个脱离的收尾进程就返回（App 包随后会被删，脚本不能从包里跑）。
2. 密码框通过后 App 才删钥匙串（未选保留）和登录项，然后**正常退出**：退出照常断开 VPN、放开网络、结束子进程（§21.5、§23.11）。
3. 收尾进程等 App 进程消失（最多 60 秒，超时强制结束），然后 reset-network.sh：先卸下后台服务（防它看到 App 消失又把 App 拉起来，§30.3），
   结束残留进程，撤销路由台账与直连路由、清 DNS 残留、清 pf 锚点、释放 pf 引用，验证网页能开；后台服务保持卸下。
4. 删系统文件、用户文件、设置（未选保留），最后删 App 包，发一条系统通知"AlwaysConnect 已卸载，网络已恢复直连"（网页仍打不开时换成检查 Wi-Fi 的提示），
   临时目录自删。
reset-network.sh 同批改动：默认路由走着一条**仍然活着的** utun 时不再改（我们的 openconnect 此时已结束，活着的隧道是别的 VPN，
比如用户自己开的 Cisco），只在默认路由缺失或指向已死的隧道时改回物理网卡。"恢复网络"按钮同样受益。

### 31.4 验证级别
- 脚本级断言：`scripts/uninstall-test.sh`（假文件系统，改动 Mac 的命令只记录不执行）5 个场景 80 项：终端全删、两项保留、
  从 App 启动时立即返回且等 App 退出后才动手、别人的同名 App 包与桌面文件不动、dry-run 不改任何东西；Cisco 的文件每个场景都在。
  已进 local-checks 与 CI。
- 本机只读：`uninstall.sh --dry-run` 在真实 Mac 上列出的清单与 31.2 一致。
- **需实测**（mac-proof I17）：真实卸载后上述位置全部不存在、网页直连、钥匙串无 com.alwaysconnect.app 条目、pf 锚点为空、
  `launchctl print system/com.alwaysconnect.app.helper` 不存在；收尾进程在 `do shell script` 返回后存活；通知送达；重新安装后从向导开始。
  系统设置"通知"列表里的 AlwaysConnect 条目与登录项后台记录（BTM）是否随 App 删除消失：需实测，不能用脚本删。

### 31.5 本机实测（2026-11-06 14:32）与随之修的进程匹配
用户在 App 里点卸载（选了"保留设置"）：App 退出约 1 分钟后收尾进程跑完，检查结果：App、LaunchDaemon、后台服务、随附 openconnect、
/Library/Application Support 与 /Library/Logs 下的目录、用户日志与用户域目录、渲染偏好、桌面恢复脚本全部不存在；后台服务未加载；
临时副本已自删；默认路由走 en0，网页 200。保留设置时两份偏好照留（符合选择）。钥匙串条目仍在：用户确认当时也开了"保留账号密码"，符合选择（不保留时 App 删钥匙串的效果仍**需实测**）。完成通知用户记不清是否看到：**需实测**。
实测中发现：reset-network.sh 按 `pgrep -f "<后台服务标签>"` 找进程，命令行里只要**提到**这个名字的进程（如终端里的
`launchctl print system/<标签>`）都会被 kill -9（实测把检查用的终端命令杀了）。改为只匹配真正的程序：App 按可执行文件名
`pgrep -x AlwaysConnect`，后台服务、openconnect、旧分流核心按"命令行以该程序路径开头"（`^/Library/PrivilegedHelperTools/<标签>( |$)`、
`^[^ ]*/openconnect .*alwaysconnect-vpnc\.sh`）；dev-helper.sh 的 pkill 同改。验证：用同名的真实二进制与"只提到名字"的命令行分别试，
前者命中、后者不中（脚本级）。

## 三十二、开销审查：用完即还（2026-11-06，用户："开销尽量低，不要占用太多内存；用某个功能时可以有开销，用完要自动回收"）

本机测量（装在"应用程序"的版本，连着自建连接、运行约 2 小时、正有约 350 KB/s 的隧道流量；只读，`footprint`、`heap`、`top`、`sample`、`nettop`）：

| 进程 | 内存实际占用 | CPU | 每秒唤醒 |
|---|---|---|---|
| App | 44 MB（峰值 153 MB；其中在用的堆只有 16 MB，其余是释放后留下的碎片页） | 12–20 % | 约 4000 |
| 后台服务 | 约 10 MB | ≈0 | 约 18 |
| openconnect | 约 5 MB | 2–4 % | ≈0 |

App 的 CPU 来自两处（`sample` 5 秒）：
- **看不见的界面在一直重画**（主线程约 7 %）：等批准提醒气泡收起时只是把窗口移出屏幕，卡片还在，波纹与呼吸光晕是无限循环动画，
  于是整天在后台重画（窗口列表里它与面板都还在，只是不在屏幕上）。菜单栏面板同理：关上后视图仍活着，每 3 秒问一次后台服务
  "分流做了什么"，状态一变就重画一次没人看的面板。
- **证书转接逐包转发**（约 10 %，随流量增减）：UDP（DTLS）每个数据报经 Network.framework 回调、再转线程、再 `sendto` 回环；
  采样里 `sendto` 系统调用本身占了大半。这是"App 内转接"这一结构的固有成本，见 32.5。

### 32.1 界面：关上即释放
- 提醒气泡：收起（自己收、点 ×、点开面板、设置里关掉）时窗口连同 SwiftUI 视图一起释放、卡片清空；下次请求重新建。
- 菜单栏面板：关闭后释放（NSPopoverDelegate.popoverDidClose），3 秒轮询随之停止；每次打开本来就新建一份。
- 首次向导：关闭后释放（原先保留到退出，连同它每 2 秒的检查）。
- 设置窗口关闭即释放已在 §28.6 完成。

### 32.2 转接的 CSTP 分包改为线性
每读到一块（最多 64 KB）后按包切分，原先每切一包就把剩余字节整体前移一次（`removeFirst`），一块里几十个包就是几十次大拷贝；
改为用偏移量走完、最后丢一次。行为不变，relay harness 的分包用例覆盖。

### 32.3 后台服务的日志有上限
helper.log 原先只增不减（本机安装会记下每次登录的 openconnect 输出，已脱敏）。后台服务启动与每次连接时检查：超过 4 MB 只留最后
1 MB（从整行开始）。launchd 以只写追加方式打开这个文件，所以经文件路径另开只读句柄取尾部，再截断原文件写回。转接日志 relay.log
已有 1 MB 上限。卸载时整个日志目录照旧删除。

### 32.4 其他
- `geoip:cn` 不再常驻内存（约 5500 条），与网站清单一样用时读、用完丢（§27.4）。
- 后台服务的空闲检查计时器给了 3 秒容差，让系统可以合并唤醒。
- 试过但不采用：关窗后调用 `malloc_zone_pressure_relief` 归还空闲页。本机测试（分配 75 MB 小对象、留 2 % 不放）它一页也还不回来，
  系统分配器本来就会归还整页空闲的内存；剩下的是被零星存活对象钉住的碎片，只能靠"不在常驻进程里建大对象"避免——即 32.1 的做法。

### 32.5 常驻的转发逻辑迁到 Rust（用户 2026-11-06 决定：能迁的都迁）
用户补充（2026-11-06）：之前的约定是常驻逻辑用 Rust、界面用 Swift（本文开头"核心用 Rust，Swift 只做壳"）。现状不符：
证书转接（App 内，含 UDP 数据报转发）、DNS 转发器、openconnect 编排、网络闸门都是 Swift。开销最大的正是转接的逐包转发。
建议分批：① UDP（DTLS）数据报转发移进 Rust（纯字节转发，不涉证书，一个线程用 kqueue 批量收发，预期唤醒与 CPU 明显下降），
App 首次链接 Rust 静态库；② DNS 转发器移进 Rust（后台服务已链接 Rust 核）；③ TLS 一侧因要用钥匙串里不可导出的私钥签名，
仍需 Swift/Security.framework 完成握手，评估后再定。每批都要真实网关实测（需用户在场），改动涉及其他 Thread 负责的模块时先协调。

验证级别：32.1–32.4 本机构建与全套检查（local-checks 全部 PASS）；日志截断用临时程序在追加方式打开的文件上验证（超限后只留尾部、
后续写入接在其后）。改后的实际占用与 CPU 需装上新版后复测（`footprint <pid>`、`top -stats cpu,idlew`）：需实测。

### 32.6 迁移：DNS 转发器改用 Rust（2026-11-06，用户："把能迁移的都迁移到 rust……后续不要再犯，不要劣化"）
原 Sources/Helper/DNSForwarder.swift 的全部逻辑（监听 127.0.0.1:53 的 UDP/TCP、名单匹配含 domain/full/keyword/regexp/ipcidr、
本地 DNS 经物理网卡绑定发问、隧道 DNS 逐个 UDP 后 TCP、截断改 TCP、AAAA/HTTPS 置空、"地址 → 域名"记忆上限 4096）移到
`core/src/dns_forwarder.rs`，经 C ABI（`ac_dns_*`）由后台服务调用；Swift 只剩同名的薄壳，接口不变，编排（CLIOrchestrator）不用改。
行为保持：直连名单的地址先交给 onDirect（加主机路由、写网络闸门的直连表，同步返回）再把答复交给系统——harness 用事件顺序断言。
Swift 侧的 onDirect 闭包交给 Rust 时被保留，直到最后一个在途查询结束才释放（壳先走也不会悬空）。
线程：一个线程用 poll 同时等 UDP、TCP 与停止管道，醒来一次处理完所有就绪的查询；查询交给常驻 30 秒的小栈工作线程，同时最多 64 个
（原来 GCD 并发队列不设上限）。依赖：socket2（绑网卡、连接超时、SO_NOSIGPIPE）、libc、regex-lite（无 Unicode 表的小正则）。
对比（同一台 Mac，回环假上游，3000 次查询含名单内外各半、3000 条名单）：每次查询整进程 CPU 97 → 96 µs、耗时 157 → 156 µs；
压测后多占内存 1.6 → 1.5 MB；空闲时 1 个等待线程、无定时唤醒。
验证级别：Rust 单测（名单规则、报文、整环：先路由后答复、AAAA/HTTPS 置空、换上游、截断转 TCP、TCP 客户端、geoip、停止即释放端口）；
dns-forwarder harness 经 Swift 壳全过；session harness 与 local-checks 全过。真实网关下的分流需装新版后实测。

### 32.7 迁移：证书转接的明文处理与 DTLS 通道改用 Rust
App 里的证书转接只留下必须用苹果框架的部分：钥匙串身份、两段 TLS（Network.framework）、本机监听与换网络监视、20 秒握手超时与
"网关不应答换地址"（onGatewayUnreachable，按连接结果计数）。每对连接的明文处理交给 `core/src/relay.rs` 的 Stream（`ac_relay_*`）：
请求透传与 CONNECT 识别（去掉 PSK-NEGOTIATE）、CONNECT 应答 200 后改写 X-DTLS-Port 并开 UDP 通道、之后两个方向按整包切分
（App 仍是一包一次 TLS 写入）、登录形状记录（§30.9 的 relay.log 行原样保留）、关闭时的计数；网关地址选择（§30.6 pick）也在 Rust。
DTLS 数据报转发（原 Network.framework 的 NWConnection 每包一次回调 + 线程切换）改为 Rust 一个线程 poll 本机口、网关口与停止管道，
醒来一次收发完所有就绪的数据报。网关口绑定到 TLS 那条连接所用的网卡（由它的本机地址查出，查不到就用它报告的网卡名；都没有则
不开 UDP 通道、openconnect 留在 TLS 上，并在 relay.log 写明），所以与原来一样绝不经隧道（§23.6）。relay.log 的
"udp channel to gateway ready" 行保留（accept-check 依赖），现在附带网卡名。App 首次链接 Rust 静态库（project.yml、build-local.sh）。
对比（回环，10 万个 1200 字节数据报经转接往返，窗口 32，整进程 CPU 含收发两端）：每个往返 88–93 → 69–70 µs，转接自身的内存
增量 1.6 MB → 0.16 MB，吞吐持平（约 32 MB/s 每向）。
验证级别：Rust 单测（CSTP 分包、请求透传与 CONNECT、头部逐字节改写、登录记录、地址选择、CONNECT→UDP 通道整环收发）；
relay harness 全过（逐包 TLS 记录、DTLS 端口改写与两向数据报、本机双向认证、引擎经转接登录与 Cookie 复用、登录记录不泄密）；
local-checks 全过。真实网关下的 DTLS、换网络与实际 CPU 需装新版后实测（mac-proof I18）。

### 32.8 迁移清单（还在 Swift 的常驻逻辑，按批迁）
已迁：DNS 转发器（32.6）、转接明文与 DTLS（32.7）、连接页与转接日志（32.9）、路由台账（32.10）、Cisco 引擎（32.11）、网络闸门与 Cisco 断线保护（32.12）、openconnect 编排（32.13）。
第二轮（32.15）：设置窗口独立进程、轮询改事件。仍在 Swift、可再评估的：后台服务的会话管理（HelperSession：XPC 接口背后的引擎替换与整体释放决策）、App 的 HelperClient
（状态映射、掉线记录、网络变化推送），它们与 XPC/界面交织，迁移前先拆出纯逻辑。界面、XPC、钥匙串、Security/Network.framework 外壳按 AGENTS.md 留在 Swift。

### 32.9 迁移：连接页的列举与分类、转接日志的写入改用 Rust
- 连接页（§28.7）：lsof 输出解析、每个远端地址的内核路由查询（路由套接字 RTM_GET，原样移植）、走向与原因分类、所在网段判断、
  输出 App 读的 ConnectionRow JSON，都在 `core/src/connections.rs`（`ac_connections_json`）；域名直接读 Rust 转发器的记忆。
  Swift 的 Connections 只剩调用壳。只在连接页打开时运行，调用之间不留任何东西。
- 转接日志（relay.log）：写文件、1 MB 上限、时间戳、harness 改写路径（ALWAYSCONNECT_RELAY_LOG）在 `core/src/relay_log.rs`；
  转接的 Rust 部分直接写，App 其余地方经 `ac_relay_log`。
验证级别：Rust 单测（分类七种情形、lsof 字段解析含 IPv6 跳过、JSON 转义、内核路由查询 lo0 与 500 次耗时、时间戳）；
connections harness（本机真实列举能按 ConnectionRow 解码、全部有走向、500 次路由查询 6 ms）；relay harness 的登录记录检查经新写入器通过；
local-checks 全过。root 下的全量列举需装新版后实测。

### 32.10 迁移：路由台账改用 Rust
直连路由的台账与操作（先记账再加路由、主机路由已存在则 change、已存在的网段路由不是我们的就不碰也不记、换网络时全部改指新网关、
中途删除、断开时全部撤销、后台服务启动时只撤销本次开机的台账、删网段路由后若 Mac 已在该网段则把系统的网卡路由补回）、
哪些网段需要经物理网关（§28.5、§30.2）、Mac 所在的 en* 网段，都在 `core/src/direct_routes.rs`（`ac_routes_*`），
仍经 /sbin/route 执行，命令与原来逐条一致。Swift 的 DirectRoutes 只剩同名薄壳；读 configd 的物理网关与本地 DNS
（SystemConfiguration）留在 Swift。
验证级别：Rust 单测（台账先写、去重、无效网关不加、删除与全部撤销、本次开机才撤销与未知开机作废、网段选择两组用例）；
session harness（台账撤销与网段选择，经 Swift 壳）与 local-checks 全过。真实路由的增删需装新版后实测（mac-proof I18 的分流部分）。

### 32.11 迁移：Cisco 引擎改用 Rust
Cisco 引擎（§二十一）的全部逻辑移到 `core/src/cisco.rs`：执行 Cisco 命令行（stdout/stderr 合流、逐行回调含不带换行的提示、
超时 SIGTERM、命令行退出即结束而不等它留下的子进程）、解析 state/stats/error、登录、两套退避（1/2/5/10/30 秒；推送过手机后
30 秒/1/2/5 分钟，一小时无人批准后每 15 分钟）、"Login failed" 且距密码提交足够久 = 批准过期并重新发起，否则与 "Login error"
一样按被拒处理、不自动重试（防锁号）、每 4 秒看 Cisco 状态（掉线拦截再重登，Cisco 自己重连时只拦截）、拦截指令与网关地址集合、
只管理 App 自己发起的会话。一个引擎线程按"下一次检查或重试"的时刻等通道，空闲不唤醒。
Swift 的 CiscoEngine 只剩外壳：钥匙串取密码、读 Cisco 配置文件里的网关、让 Cisco 窗口程序退出（AppKit）、"由 App 管理"标记写入
UserDefaults、回调转到主线程。顺带省开销：查默认路由所在网卡改为路由套接字精确查询默认路由（与 `route -n get default` 同答案，
单测对照），经 Cisco 连着时每 4 秒少起一个进程。
验证级别：Rust 单测（解析、逐行与提示、超时）；Cisco 引擎 harness 9 个场景经 Swift 外壳全过（连接、掉线重登、手动断开、被拒不重试、
暂时失败重试、批准过期重发、接管已连接会话与不接管别人的会话）；local-checks 全过。真实 Cisco 会话需实测（mac-proof H 节复测）。

### 32.12 迁移：网络闸门与断线保护（Cisco 用）改用 Rust
网络闸门（§25.2、§25.8、§30.1）整体移到 `core/src/network_guard.rs`：持有者与"被替换的引擎失效"、guard.json（字段与 Swift 版逐字相同，
新旧版本在同一次开机里互相接得上，旧记录缺字段照样能读）、pf 开启引用（`pfctl -E` 的 token，`-X` 归还）、同一次开机重启后接管
（一律先换成封网集）、别的开机留下的记录作废且绝不封网、没有 App 时最多保持宽限期（默认 120 秒）后整体释放并记下原因、
直连地址表 `<ac_direct>`（加入后才返回，重载规则后补回），以及全部 pfctl 调用（命令行与原来逐字一致）。pf 仍只有这一个写入点。
Cisco 的断线保护（KillSwitch）移到 `core/src/kill_switch.rs`：连上 = 放行物理出口，断线 = 封网加放行 DNS，连上期间每 2 秒看隧道网卡
还在不在、不在就自己封网；查往网关的物理网卡改用路由套接字（原来每次起一个 route 进程）。Swift 侧只剩同名外壳，
KillSwitch 的请求仍按到达顺序串行执行（断开前排队的设置不会落在断开之后）。依赖增加 serde/serde_json（读写 guard.json）。
验证级别：Rust 单测（Swift 写的旧记录可读、序列化字段名、token 解析）；session harness 24 个场景全过（用记录 pfctl 调用的替身：
封网/放行顺序、引用归还、宽限到期与取消、同次开机接管、别次开机作废、旧版 pf-state、直连表、被替换引擎失效、断线保护开关等）；
local-checks 全过。真实 pf 需装新版后实测。

### 32.13 迁移：openconnect 编排改用 Rust
自建连接的引擎（原 CLIOrchestrator 的全部逻辑）移到 `core/src/oc_engine.rs`，会话驱动（core/src/session.rs）在引擎里直接调用，
不再经 C ABI 绕一圈：启动 openconnect（参数、环境变量、手动断开标记文件、先 Cookie 后密码、Cookie 被拒只回落密码一次）、
读两路输出（逐行、脱敏后进 40 行尾巴、调试时写 stderr）、取 Cookie（只认 CSTP CONNECT 请求头）、vpnc-script 钩子
（connect / attempt-reconnect / reconnect）、等批准（密码发出后 3 秒没回音 = 等手机；"Login failed" 在 20 秒以上 = 批准过期，
30 秒/1/2/5 分钟后重新发起，一小时后每 15 分钟；否则 = 被拒，停、不重试）、子进程退出分类、掉线后先重载封网集再重连、
断线保护关时把本地网络还回去、接管已持有的封网集并放行自己的网关、手动停止（SIGTERM 注销会话，替换引擎用 SIGHUP 不注销，
8 秒不退就 SIGKILL）、分流的转发器与直连路由（直接用 Rust 的转发器、路由台账与网络闸门）、每 5 秒跟随物理网络。
Swift 的 CLIOrchestrator 只剩同名外壳：把配置交给 Rust，提供要用苹果框架的三样（configd 读物理网关与本地 DNS、系统根证书），
把状态、终止与"停止完成"回调转给后台服务。回调期间服务读引擎状态读的是事先发布的快照，不等引擎的锁（第一次接线时这里死锁过，
session harness 抓到）。子进程一律以默认信号处置、不屏蔽任何信号启动（Foundation 的 Process 原本如此；后台服务自己忽略 SIGTERM，
不重置的话 openconnect 会无视用户的断开，脚本也无法捕获 SIGHUP——session harness 的"换中继不注销"场景抓到）。
对比（run-once 驱动假 openconnect 保持隧道，10 秒）：后台服务内存占用 2400 → 2432 KB，CPU 0.0 → 0.0，每秒唤醒 0 → 0；
线程 4 → 7（多出的是引擎线程与两条输出读取线程、一个等待退出的线程，都在阻塞等待，不唤醒）。
验证级别：Rust 单测（脱敏与取 Cookie）；session harness 24 个场景、local-checks 25 项（含 mock 网关真 openconnect 登录、掉线重连、
隧道内重连、等批准与批准过期、密码不进输出）、证书转接 harness（真 openconnect 经转接登录与 Cookie 复用）、Cisco 引擎 9 个场景全过。
真实网关、真实 pf 与路由需装新版后实测（mac-proof I18）。

### 32.14 装机实测（2026-11-06 19:37–19:45，公司 Wi-Fi，自建连接 + 分流）
新版装到"应用程序"，启动时一次管理员密码更新后台服务；第一次登录即识别"等手机批准"（批准用了 32 秒），DTLS 通道由 Rust 转发、
绑在 en0；分流按名单生效（名单里的网站经 en0 直连，其余进隧道），系统首选 DNS 是 Rust 转发器。
开销（同一台 Mac，旧版为当天早上与装机前测得）：

| | 旧版 | 新版 |
|---|---|---|
| App 内存占用 | 44 MB / 72 MB | 25 MB（几轮操作后 40 MB） |
| App 空闲每秒唤醒 | 约 4000–5000 | 约 27 |
| App 转发 1 MB 的 CPU | 约 150–230 ms | 约 38 ms |
| 带流量时 App CPU | 12–20%（约 0.7 MB/s） | 4.6%（约 1.3 MB/s） |
| 后台服务 | 约 10 MB | 15 MB，CPU 0，每 5 秒唤醒 1 次 |

行为：手动断开即直连，再连需要手机批准（断开以 SIGTERM 注销会话，§26.17 设计如此）。关开 Wi-Fi 两次，每次约 15 秒自动恢复，
但都走了全新登录、需要批准：openconnect 的原地重连被网关在 TLS 之后直接断开（relay.log "end of stream from gateway"），
随后 Cookie 也不再有效。旧版当天 16:42 在同一网络留下的日志与此逐行同形，所以这不是迁移引起的；同一测试里另一次网络切换在
4 秒内原地恢复、无需批准。网关为何拒绝原地重连（换了源地址？会话随 TCP 关闭失效？）待查，记为后续。
验证级别：本机实测（真实网关、真实 pf 与路由）。未测：Cisco 模式（用户跳过）、断线期间零泄漏（需 root 看 pf）。

### 32.15 第二轮：用完即还、少唤醒（2026-11-06，用户："尽量降低，尤其是用完后不再用的，及时回收；cpu 也优化掉；通通优化"）
实测出发点（§32.14 之后）：App 刚启动 25 MB，开过面板与设置后 40 MB，其中在用的堆只有约 14 MB——其余是界面用完留下、系统收不回的碎片；
后台服务每秒约 4 次唤醒；Cisco 模式每 4 秒起一个 `vpn` 进程。
- **设置窗口独立进程**：设置窗口改由同一程序以 `--settings` 启动的子进程显示（`SettingsProcess.swift`），关窗即 `exit`，所用内存全部归还。
  只有菜单栏 App 执行动作：设置进程把用户的操作（连接、按网站分流、断线保护、名单与网段、快捷键、提醒气泡、掉线记录、卸载后退出）
  经分布式通知交给 App（带 App 启动它时给的一次性口令，别的进程发的不认），App 把状态推回来（只在设置进程开着时推，150 ms 合并）。
  只读查询（连接页、诊断、流量）设置进程直接问后台服务，答完立即断开——否则 App 崩溃后，后台服务会因为"还有客户端"而不开始
  2 分钟宽限，违反"崩溃最多封网 2 分钟"。设置进程监视父进程，App 一退出（含崩溃）它即退出；它的 ⌘Q 只退出自己，绝不走"退出即断开"；
  在设置里录快捷键时，App 的全局快捷键不响应（设置进程在前台时），免得录到当前组合时把 VPN 断开或连上。
- **Cisco 引擎按需创建**：自建连接模式下不再有空等的 Cisco 线程（只在连接、刷新、断开时创建）。
- **轮询改为等内核通知**：后台服务跟随物理网络（原每 5 秒）、Cisco 断线保护的隧道网卡看门狗（原每 2 秒）都改为阻塞在路由套接字上，
  路由/地址/网卡一变就醒（`core/src/route_watch.rs`），兜底各 60 秒、30 秒；Cisco 状态检查在路由变化时立即做，否则每 15 秒（原 4 秒，
  每次一个 `vpn` 进程）。断线时隧道网卡消失必有路由消息，所以封网不比原来慢。
- **DTLS 转发只读就绪的套接字**：保留，但实测几乎无收益——拆分测量后每个数据报约 15 µs，几乎全在内核的回环 UDP 上，现有结构下已到底；
  再降只能让 openconnect 的 UDP 绕过转接直达网关（需要 pf 改写回环流量），风险大，不做。
验证级别：Rust 单测、Cisco 引擎 harness（9 个场景；harness 把兜底间隔设为 4 秒，假 CLI 不改路由）、session harness 24 个场景、
证书转接 harness、local-checks 25 项全过。设置进程的实际内存回收、动作转交、路由事件触发需装新版后实测。

### 32.16 装机实测第二轮与两处新发现（2026-11-06 20:25–20:33）
装上 §32.15 的版本后：设置窗口独立进程按预期工作（开着时该进程约 34 MB，关窗即连同内存一起消失）；App 空闲每秒唤醒从约 63 次降到约 1 次
（VPN 连着、流量很少时）；但主 App 仍从约 25 MB 涨到 46–55 MB。连续采样找到两个来源：
- **菜单栏面板（NSPopover）**：每次打开主 App 冲到约 160–172 MB，其中约 107 MB 是"图形"类（显存），关掉回落，每次多留几 MB 碎片。
  单独做的对照（同一份 SwiftUI 内容）：NSPopover 打开期间约 +130 MB，关掉动画也一样；无边框面板加同样的毛玻璃背景 +7 MB。
  所以面板改为自绘的无边框面板（MenuPanel：毛玻璃、圆角，图标正下方，点外面/Esc 关闭，成为关键窗口，内容变化时顶边不动），关上即释放。
  早上看到的"峰值 153 MB"即来自此处。
- **管理员 AppleScript**：更新后台服务、强制恢复、恢复网络时在 App 里执行 `NSAppleScript`，AppleScript 运行时一经载入就常驻约 15 MB（实测）。
  改为在一次性的子进程里执行（同一个 App 程序加 `--admin-script`，密码框仍显示 AlwaysConnect；脚本从标准输入读、结果一行 JSON 写回、随即退出）。
  卸载本就在设置进程里执行，随它退出。
验证级别：对照实验为本机测量；子进程模式本机试跑（成功与报错两种返回）；local-checks 全过。面板换窗后的实际内存与交互需装新版后实测。
修正（同日，用户截图）：设置进程打开"诊断"页时偶尔把我们自己的隧道（utun6）和 DNS 转发器（53 端口）报成"另一个 VPN / Clash"。原因是设置进程
刚启动时状态还是默认的"未连接"，页面在 App 推来状态之前就做了检查。现在设置窗口等 App 的状态到了再打开（最多等 1.5 秒），诊断页在状态变化时
重新检查。验证级别：本机构建与 local-checks；真实表现需装新版后看。

### 32.17 修正：从 Cisco 切回自建连接时的竞态（2026-11-06，用户报告"开关分流后有一次没连上"，面板留红字"pf 兜底未生效"）
日志还原：Cisco 已连上；用户打开"按网站分流"→ App 要求 Cisco 断开，随即起自建连接，自建连接先把 Cisco 断掉（路由变化）。
Cisco 引擎此刻正在做状态检查（§32.15 起路由一变就立即查），排在它后面的"断开"还没处理，于是把"Cisco 已断开"当成掉线：
请求封网（Cisco 已断，没有隧道网卡，后台服务拒绝并回"pf 兜底未生效：缺少隧道接口或网关 IP"），几秒后处理到"断开"，
其收尾又让后台服务整体断开——把刚起来、正等手机批准的自建连接一并结束。这个竞态原来就有（4 秒一查也会撞上，概率小），路由事件让它必现。
修正：Cisco 引擎在用户已要求断开后不再把"断开"当掉线（检查前后都看断开标记）；切到自建连接后，Cisco 引擎迟到的状态、终止、封网请求一律不理，
封网请求迟到的回复不再留下红字；Cisco 断开收尾若发现已切到自建连接，只撤 Cisco 自己的封网，不再整体断开。
验证级别：Cisco 引擎 harness 9 个场景、local-checks 25 项；真实切换需装新版后复测（关、开"按网站分流"各一次）。
实测（同日 21:47–21:50，装上修正版后）：用户先关分流（经 Cisco 连上），再开分流两次；两次都是 Cisco 正常断开（没有当成掉线、没有封网请求、没有红字），
自建连接几秒内连上。此时 App 30 MB、峰值 31 MB。另：连接页在经 Cisco 时只显示 IP 是设计如此（域名来自自建连接的 DNS 转发器；经 Cisco 时
DNS 归 Cisco，我们不插手，§二十二）。


## 三十三、检查更新（2026-11-06，用户："检测更新能力，联动到 github 的 release 版本上，如果有新版就提示用户更新，手动即可"）

### 33.1 用户选定
- 预发布版本也提示（GitHub 上标成 Pre-release 的照样算；草稿永远不算）。
- 自动检查一直开着，不给开关。
- 有新版只在菜单栏面板里提示，不发系统通知。
- 只提示，不下载、不安装：点"查看"用浏览器打开那个版本的 Release 页面，下载与替换由用户手动完成。
  （2026-11-06 改：用户要求"尽量方便安装与使用"后，提示里加了需要用户点击并确认的 [更新]，见 §35.4；自动检查本身仍然不下载任何东西。）

### 33.2 何时检查、开销
- 没有计时器。App 启动 30 秒后、每次打开菜单栏面板时问一次"到时间了吗"：上次成功后满 24 小时、上次失败（网络不通、
  拿到的不是发布列表）后满 1 小时才真的发请求。所以一天最多一次请求，App 常驻期间不唤醒、不轮询。
- 设置 → 通用 → 版本 里的"检查更新"立即查一次（这一次在设置进程里执行，§32.15）。结果写进 App 自己的偏好
  （updateLastAttempt / updateLastSuccess / updateLastFailed / updateFound / updateSkippedVersion），菜单栏 App 下次开面板时读到，
  两个进程之间不需要新的消息。
- 请求：`GET https://api.github.com/repos/weiazm/always-connect/releases?per_page=20`（地址在 Info.plist 的 `AlwaysConnectReleasesAPI`，
  fork 改这一处即可；`ALWAYSCONNECT_UPDATE_URL` 环境变量只给 harness 用）。临时会话（ephemeral，无缓存、无 cookie），
  一次回答后即作废，不留连接池；只保存找到的那一个版本的标签、页面地址、是否预发布三项，不缓存发布列表与说明。
- 未登录访问 GitHub API 每个 IP 每小时 60 次，远够用。断线保护封网期间请求失败，按失败处理，一小时后再试。
- 仓库为私有时 API 回 404（JSON 对象而不是列表），按"拿到的不是发布列表"处理：自动检查静默，手动检查显示"暂时无法检查"。
  所以本功能在仓库公开之后才真正起作用。

### 33.3 判断逻辑在 Rust（core/src/update_check.rs，`ac_update_decide`）
- 输入：本 App 版本（CFBundleShortVersionString）、发布列表原文、用户跳过的版本。输出 JSON：
  `newer`（版本、标签、页面、是否预发布）/ `skipped` / `current` / `unreadable`。
- 版本：去掉开头的 v/V，`+` 之后的构建信息不参与比较；主体按点分数字逐段比较（`1.2` 等于 `1.2.0`，`0.10.0` 大于 `0.9.0`）；
  带 `-` 后缀的预发布低于同号正式版，后缀按 SemVer §11 比较（数字段按数值，数字段低于字母段，段少的低）。解析不了的标签忽略。
- 从未标为草稿的发布里取版本最高的一个；不高于本 App 即 `current`；正是用户跳过的那个即 `skipped`（更高的新版出来照常提示）。
- 页面地址必须以 `https://github.com/` 开头，否则当作没有这个发布（App 只往浏览器里开 GitHub 的页面）。
- 面板每次显示前，把保存的那个版本连同当前版本、跳过记录再交给核心判断一次：装上新版后或在另一个进程里点了"跳过"，提示自然消失。
- Swift 侧（Sources/App/UpdateChecker.swift）只发请求、调核心、存结果、开浏览器；界面在 Sources/App/UpdateViews.swift。

### 33.4 提示与更新步骤（UI-DESIGN §四、§五；更新方式已由 §35.4 取代，下面是最初的手动步骤）
- 面板底部工具行上方：一行"有新版本 x.y.z（预发布）[跳过] [查看]"，下面一行灰字简述步骤 + "复制命令"。
- 设置 → 通用 → 版本：当前版本 + [检查更新] 与结果；有新版时显示"跳过这个版本 / 打开发布页"、完整步骤与可复制的命令。
- 步骤：下载 zip 解压 → 面板里"退出" → 把新 App 拖进"应用程序"替换 → 第一次打开前执行
  `xattr -dr com.apple.quarantine /Applications/AlwaysConnect.app`（没有开发者签名与公证，不执行会被 Gatekeeper 拦下；
  也可以被拦后到"系统设置 → 隐私与安全性"点"仍要打开"，新版 macOS 已不能用右键打开绕过）。
  新版第一次打开若后台服务也旧了，照常弹一次管理员密码框一起更新（§30.5）。

### 33.5 发布约定
- Release 的标签必须是 `v` + Info.plist 的 CFBundleShortVersionString，否则新版装上后仍会提示"有新版"。
  `scripts/package-release.sh v<版本>` 先核对两者，再以固定的自签名身份（§35.5，原为 ad-hoc）构建并打出 `AlwaysConnect-<版本>-macos-<arch>.zip` 与 `.sha256`；
  创建 Release 仍是手动一步（用户规则：只有大版本才发 Release）。

### 33.6 卸载
- 新增的只是 App 自己偏好域里的几个键，`uninstall.sh` 删除该偏好域时一并清掉（勾"保留设置"时随设置保留）；
  临时会话不在磁盘上留下 HTTPStorages。无需改 uninstall.sh。

### 33.7 验证级别
- Rust 单测（版本解析与排序、预发布、草稿、跳过、私有仓库的 404 对象、非 GitHub 页面）。
- CI harness `scripts/update-check-test.sh`（已加入 local-checks 与 CI macOS）：App 的 UpdateChecker 对本机假服务器，
  覆盖新预发布、一天内不重复请求、404 与连不上时保留上次结果、失败一小时后重试、跳过、更高版本重新提示、装上新版后提示消失。
- 需实测：仓库公开后真实 GitHub 的回答、面板提示条与设置页的实际外观、点"查看"打开浏览器。
## 三十四、许可证、商标与使用定位（2026-11-06，用户："风险我们解决下，尽量规避"）

背景：用户问开源有没有法规风险，随后决定暂不开源，并要求把能用代码和文档规避的风险都处理掉。
本节只管代码与文档能解决的部分；单位政策是否允许、代码归属（职务作品）由用户自己向单位确认，不在仓库里下结论。

### 34.1 随包第三方组件（验证级别：脚本级断言 + 本机构建产物检查）

- 清单：`THIRD_PARTY_NOTICES.md`。随 App 分发的有三类：OpenConnect 与它加载的 12 个库（LGPL-2.1 / LGPL-3.0 或 GPL-2.0
  双许可 / BSD-3 / 公有领域）、静态链接进 `libalwaysconnect_core.a` 的 9 个 Rust crate（均取 MIT 选项）、分流数据
  （v2fly/domain-list-community，MIT；APNIC 公开分配统计）。没有第三方 Swift 包；系统库与 Cisco 不随包分发。
- App 的 Resources 里放 `THIRD_PARTY_NOTICES.md`、`RESPONSIBLE-USE.md`、`LICENSE.txt`、`third_party/`（Rust crate 声明、
  Apache-2.0 / LGPL / GPL 全文、v2fly 的 MIT 声明），由 build-local.sh 复制；local-checks 的 `app-notices` 检查它们在产物里。
- `third_party/rust-crates.txt` 由 `scripts/make-rust-notices.sh` 从 Cargo.lock 的运行时依赖生成（过程宏及其依赖只在编译期运行，
  不进产物，不列）；`--check` 进了 local-checks 与 CI，改依赖忘了重新生成会失败。
  为此 `core/Cargo.lock` 改为进仓库（原先被 .gitignore 忽略，CI 每次重新解析版本，随包 crate 的版本与声明就对不上）。
- 修正：`core/Cargo.toml` 的 license 原写 GPL-3.0-or-later，与仓库 LICENSE（MIT）矛盾，改为 MIT。

### 34.2 LGPL：对应源码与可替换（脚本级；下载与校验本机实跑过 openconnect、libunistring 两个包）

- `bundle-openconnect.sh` 额外写出 `openconnect/SOURCES`：每个库的上游源码包地址、SHA-256，以及 Homebrew 打的补丁地址。
  地址取自 `brew info --json=v2`；若构建机装的版本落后于当前 formula（实际遇到 libunistring 1.4.2 vs 1.5），地址换成已装版本、
  校验值记 `-` 并在构建日志里警告，提示构建机 `brew upgrade`。
- `scripts/fetch-third-party-sources.sh <目录>` 按 SOURCES 下载并校验；GNU 的镜像跳转偶尔给出不通的镜像（实测卡住），
  失败时回落到 ftp.gnu.org，单个下载有超时。把 App 交给别人的人附上这些源码包或在同一位置提供下载。
- 补齐许可证正文：Homebrew 对 gnutls、nettle、gettext、libtasn1 只装了 GPL 正文或缺 LGPL 正文，现在 `openconnect/licenses/`
  另放 LGPL-2.1、LGPL-3.0、GPL-2.0、GPL-3.0 全文（仓库 `third_party/licenses/`）。
- 可替换：App 不链接这些库，只把 `bin/openconnect` 当独立程序运行，它经 `@loader_path` 加载 `lib/`。替换同名兼容组件并在组件目录执行
  `codesign --force --sign - lib/*.dylib bin/openconnect` 后，先退出 App（VPN 断开），再由用户主动在终端安装：
  `APP=/Applications/AlwaysConnect.app`，然后执行 `sudo /bin/bash "$APP/Contents/Resources/dev-helper.sh" install "$APP/Contents/Library/LaunchDaemons/AlwaysConnectHelper"`。
  脚本从所给 Helper 同一 App 的 Resources/openconnect 复制组件到 root 专属位置。App 内管理按钮只接受原证书签名且完整未改动的 App；组件替换破坏整包封印，ad-hoc 签名不能恢复原证书，自动提权必须拒绝（§39.4）。
  `openconnect/README-LGPL.txt` 随包给出该手动流程；用户明确执行的终端路径不放宽自动验签。替换后实际能否运行需实测。
- 更正 README 旧说法："OpenConnect CLI 是 GPL"不对，openconnect 整个项目是 LGPL-2.1。

### 34.3 定位与示例（界面改动，见 UI-DESIGN；验证级别：编译 + ListRulesTest）

- README 开头加"定位"：只是客户端，连接所在单位授权的企业 VPN；不运营、不提供、不内置任何服务器、代理或线路，不提供跨境访问。
- 分流示例改为中性、与工作相关的写法（example.com、geosite:apple/microsoft/github、apple@cn、网段）；不再举地区、视频站、流媒体
  的例子，不再拿其他代理工具作比较。`geoip:cn` 功能不变（用户已有的名单照常生效），只是不作示例、不进输入框提示。
- README 对比表的表头不再写"用 Cisco 客户端时"，避免像在贬低或冒充某个产品。

### 34.4 商标与使用责任

- `RESPONSIBLE-USE.md`：它做什么、不做什么；用户须确认单位允许、遵守单位 IT 规定与所在地法律；免责；商标声明。
- 商标声明进 README、THIRD_PARTY_NOTICES、RESPONSIBLE-USE 与设置 → 通用 → 关于 的脚注；向导欢迎页加一行"请只连接你所在单位
  授权你使用的 VPN……与 Cisco 没有关联"，副标题不再写"替代 Cisco 客户端"。
- 设置 → 通用 新增"关于"（版本号在 §33 的"版本"卡里）：[使用须知]、[许可证与第三方声明]（用默认程序打开 Resources 里的文件，App 不常驻任何内容）。
- 图标（验证级别：离屏渲染核对）：菜单栏与 App 图标的地球改为原创造型。给用户看了四版全新设计后，用户要求保持整体风格：
  外圈、配色、玻璃底、锁与状态角标不变，圈里是普通地球仪的倾斜经纬线（赤道 + 经线两个椭圆，斜 24°，已连接时经线变绿）。用户指出第一版绿线在外圈处被硬切、
  边缘不自然，改为先画经纬线再画外圈，两端收进外圈底下。AppIcon.icns 用 make-app-icon 重新生成；README 截图用示例数据离屏重渲。
  装到本机需等用户说"装"并先问 Coordinator（共享 Mac）。

## 三十五、没有开发者账号时的安装与更新（2026-11-06，用户："不买开发者账号，你尽量优化下方便安装与使用"）

### 35.1 问题
- 发布包没有苹果开发者签名、没有公证。浏览器、聊天工具下载的文件带隔离标记（com.apple.quarantine），
  Gatekeeper 对带标记且未公证的 App 一律拦下（"无法验证开发者" / "Apple 无法检查其是否包含恶意软件"）。
- macOS 15 起"右键 → 打开"不再能绕过，只能被拦一次后到"系统设置 → 隐私与安全性"点"仍要打开"，或在终端去掉标记。
- 没有隔离标记的 App 不经 Gatekeeper 评估，只要签名完整（ad-hoc 或自签都可以）就能运行。curl 下载不加隔离标记。

### 35.2 一行命令安装（install.sh，仓库根目录）
- `curl -fsSL https://raw.githubusercontent.com/weiazm/always-connect/main/install.sh | bash`；首次安装与更新是同一条命令。
  地址按仓库公开后设计，私有期间 raw 与 API 都回 404，脚本报"没有返回发布列表"后停止，不动已装的 App。
- 选版本：GitHub 发布列表（新的在前）里第一个不是草稿、且带本机架构 zip 与其 .sha256 的发布；预发布也算，与检查更新一致。
  `--version v<版本>` 指定。架构按硬件判断（Rosetta 下的 shell 也装 arm64）。只用每台 Mac 都有的工具：
  发布列表用 JavaScript for Automation（osascript）解析，不依赖 python3 / jq。
- 校验：下载地址必须以 `https://github.com/` 开头；sha256 与 .sha256 文件一致；解出的包必须是 com.alwaysconnect.app、
  `codesign --verify --strict` 通过、LSMinimumSystemVersion 不高于本机。任一不符即停止，已装的 App 不动。
- 已在运行的那份：先告诉用户"会断开 VPN，新版打开后自动重连"，从终端（/dev/tty）问一次（`--yes` 跳过；没有终端且没给 `--yes` 时拒绝）；
  再用正常退出（`tell application id … to quit`，等同面板里点"退出"：断开 VPN、恢复直连，§21.5）。设置窗口是同一 App 的第二个进程，
  可能先接到退出请求，所以每 2 秒再请求一次，最多一分钟。绝不强杀：被杀的 App 会让网络闸门按崩溃处理、封网最多两分钟（§25.2）。
  一分钟内没退出就停下，请用户在面板里点"退出"后重跑。
- 替换：旧版先移到临时目录，新版用 ditto 放进去，去掉隔离标记，再验一次签名，通过后才删旧版；中途任何失败（含 Ctrl-C）
  都把旧版放回，并在它原本在运行时重新打开它。"应用程序"不可写（非管理员）时说明原因后用 sudo。最后打开 App。
- 整个脚本包在一个 `{ … }` 里：`curl | bash` 时脚本从标准输入来，bash 必须先读完全部再执行，免得某条命令吃掉后面的脚本。
  bash 3.2 在"变量未定义"中止时 EXIT 陷阱里的 `$?` 是 0，所以只有走到末尾才算成功。
- 不写系统里的任何其他东西（临时目录用完即删），uninstall.sh 不需改。

### 35.3 验证级别
- CI harness `scripts/install-test.sh`（已加入 local-checks 与 CI macOS）：本机假发布服务器 + 自签的最小 App 包，
  覆盖最新版选择（跳过草稿、含预发布）、指定版本、覆盖旧版且不留残余、坏校验值、系统版本过低、不是本 App、
  下载地址不在 GitHub、版本不存在、私有仓库 404、没有发布、没有本机架构的包、列表下载失败、分两步的暂存与安装（等进程退出、
  去隔离标记、清暂存目录）、坏包、从管道读脚本、目标位置有正在运行的副本而无终端时拒绝、临时目录不残留。
- 需实测：仓库公开后真实 GitHub 下载；正在运行的 App 被正常退出（含设置窗口开着时）、替换后自动打开与重连；非管理员账户走 sudo。

### 35.4 App 里一键更新（面板 [更新]、设置 → 通用 → 版本 [立即更新]）
- 用同一个 install.sh（打进 App 的 Resources），分两半：
  ① App 照常运行，后台跑 `install.sh --version <标签> --app <本 App 路径> --stage <暂存目录>`：下载、校验（同 §35.2）并解到
  `~/Library/Caches/com.alwaysconnect.app/update-<随机>`，输出 `STAGED <路径>`。失败时什么都没动，面板橙字显示脚本的"错误："那一行，删掉暂存目录。
  ② 成功后启动 `install.sh --from <暂存的 App> --app <本 App 路径> --wait-pid <本进程> --yes`，经一层立即退出的 shell 放到后台
  （`nohup … &`），使它的父进程变成 launchd：App 退出时会结束自己的全部子进程（§23.11），更新脚本不能是其中之一。
  然后 App 正常退出（等同点"退出"：断开 VPN、恢复直连）。脚本等本进程结束（最多一分钟）、替换、去隔离标记、删暂存目录、打开新版；
  任何一步失败都放回旧版并重新打开它。输出写 `~/Library/Logs/AlwaysConnect/update.log`（每次覆盖，大小有限；卸载时随目录删除）。
- 要更新的位置：本 App 所在路径；若 App 是从"下载"文件夹直接打开、被系统挪到只读的 AppTranslocation 路径运行，则装到 /Applications。
- 版本由 Rust 的判断（§33.3）选定后以 `--version` 传给脚本；脚本用 App 的发布列表地址（Info.plist，fork 自然更新自己的）。
- 设置窗口是另一个进程（§32.15）：[立即更新] 经 SettingsLink 把 `installUpdate` 交给菜单栏 App 去做，失败显示在面板上。
- 确认一次再开始：更新必然断开 VPN（退出即断开），新版打开后自动连接；openconnect 的退出会注销会话，所以可能需要再在手机上确认一次。
  新版若带新的后台服务，启动时照常弹一次管理员密码框（§30.5）。
- 不是常驻逻辑：只在用户点击后运行一次，结束即退出；不增加计时器与常驻内存（§32）。
- 验证级别：CI harness（`scripts/install-test.sh` 第 8 项）：编译 App 的 UpdateChecker 与 Rust 核心，对本机假服务器找到新版并点更新——
  坏校验值时显示原因、不退出、旧版不动、暂存目录已删；正常时调用退出，测试进程结束后脱离的另一半把版本换成新版、写日志、清暂存目录。
  需实测：真实菜单栏 App 点 [更新] 后正常退出、换版、自动打开与重连，及设置窗口里的 [立即更新]（mac-proof I20 ⑤）。

### 35.5 发布包用固定的自签名身份（不再 ad-hoc）
- ad-hoc 签名的指定要求是二进制的 cdhash，每个版本都不同：钥匙串把每个新版本当作新程序，用户每次更新后第一次连接都要再点
  "始终允许"（VPN 密码与证书私钥各一次，§21.15 是同一问题在本机重编时的表现）。
- `scripts/package-release.sh` 改用 §21.15 的自签名身份"AlwaysConnect Local Dev"签名（`RELEASE_SIGN_IDENTITY` 可换，`-` 即 ad-hoc）；
  钥匙串里没有该身份时停下并说明，打包后核对指定要求为 identifier + certificate leaf。不需要开发者账号，证书也不需要被信任：
  没有隔离标记的 App 不经 Gatekeeper，系统只校验签名完整（§35.1）。证书只有 CN，不含个人信息。
- 效果：各版本的指定要求相同，"始终允许"跨版本有效；本机自编版本与发布版本也是同一身份，来回切换不再询问。
  所有发布必须一直用这一个身份：换身份（例如换了打包的电脑而没带走证书）会让每个用户再被问一次。
- 没有团队标识，后台服务的同团队校验与安装路径（§21.8）与 ad-hoc 时完全相同；浏览器下载 + "仍要打开"的路径也不受影响。
- 验证级别：本机打包 0.1.0，指定要求为 `identifier "com.alwaysconnect.app" and certificate leaf = H"…"`；该 zip 经本机假服务器用 install.sh
  装到临时目录，校验全部通过。钥匙串条目在两个不同版本之间不再询问，§21.15 已用探针程序实测同一机制；跨发布版本的真机确认需实测（mac-proof I20 ⑥）。

## 三十六、公开前的安全与隐私审查（2026-11-07，用户："继续推进开源事项……注意信息安全、合规、隐私、安全"；"都做吧""做干净，该删的就删"）

完整报告只留本地（含用于扫描的关键词与真实配置，不进仓库）；这里只记行为结论与仓库内的改动。

### 36.1 历史与文件（验证级别：脚本扫描 + 逐张目视）
- 按本地关键词清单（单位名与域名、网关主机与地址、内部 CA、Cisco 配置条目名、用户名、本机名）扫全部提交的补丁与提交信息：
  只有 `geosite.txt`（v2fly 公开清单）里有公开域名，其余为零；邮箱、私钥与常见令牌格式为零。历史上的全部截图与图标版本逐张看过，
  只有示例数据，PNG 元数据只有尺寸与分辨率。
- 删掉：连接页把某个具体网关端口标成"VPN"的协议标签；DESIGN 末尾残留的合并冲突标记。
- 删掉或改写（不是泄露，但不该公开）：对 Cisco 闭源安装包的研究记录（docs/research-report.md）；无开发者签名分流的一次性 PoC
  脚本、报告与交接材料（结论摘要留在 §22.3–22.14）；文档里旧图标沿革的说法（§34.4 只写现在的造型）；
  视频站、流媒体的示例与实测记录（换成示例网站）；规则测试与界面草图里的具体 AI 应用示例（换成 com.example.workapp / "工作应用"）；
  早期预置网站组的迁移代码（只用户本机用过，已迁移完）。测试夹具一律用 example 域名。

### 36.2 仓库与历史（2026-11-07，用户选定"新建干净仓库"）
- GitHub 会长期保留改写前的提交（按提交号仍能打开，短提交号也能试出来），PR 引用也会留住旧对象；只有删库或换库才彻底清掉。
  做法：新建仓库，只放一个干净的初始提交；旧仓库（含全部历史）随后删除（用户 2026-11-07："之前的都删掉"）。
  仓库名改为小写中划线 `weiazm/always-connect`（用户同日要求），安装、更新、发布列表地址随之改为新名字；
  GitHub 会把旧名字 weiazm/AlwaysConnect 重定向到新仓库（已装的旧版 App 查更新仍能找到），但新版只写新名字。
- 2026-11-07 用户要求公开并发布：仓库改为公开，首个公开版本 v0.2.0（预发布：多项本机实测仍待做，见 mac-proof）。
- 换库后其他分支迁移：`git rebase --onto <新根提交> <旧 main 尖端> <分支>`；旧历史的任何引用都不能推到新仓库。
- CI 显式 `permissions: contents: read`，同分支旧运行自动取消；只用 push 与 pull_request 触发（不用 pull_request_target），fork 的 PR
  拿不到写权限与 secrets。新增 `SECURITY.md`（私下报告）、Issue 模板（先脱敏）、`.github/dependabot.yml`（cargo 与 Actions，每月，最多 3 个）。
- 仓库设置（2026-11-07 公开后已开）：私下漏洞报告、Secret scanning 与 push protection、Dependabot alerts 与安全更新、
  main 规则集（禁止强推与删除）、外部贡献者的 fork PR 工作流需批准、Actions 只允许 GitHub 官方与已验证作者的 action、令牌默认只读。

### 36.3 加固（代码改动）
- **后台服务只认同一证书签名的 App**：原来比较双方团队标识，自签名与 ad-hoc 构建都没有团队标识，两边都空就放行，本机任何进程都能
  驱动 root 后台服务（改连别的网关、封网解封、列出全部连接）。现在 `ClientRequirement` 从后台服务自己的签名推出要求：
  有团队 = 同团队且 Apple 签发；只有证书 = `identifier "com.alwaysconnect.app" and certificate leaf = H"<自己证书的 SHA-1>"`；
  没有证书（ad-hoc）= 谁都不接受（build-local.sh 会警告，先跑 dev-signing-identity.sh）。监听时按 pid 先拒一次，
  再用 `NSXPCConnection.setCodeSigningRequirement` 让系统按审计令牌校验每条消息。
  验证级别：harness `scripts/helper-client-test.sh`（真证书签的小程序：同证书 App 通过，别的证书、别的标识、ad-hoc 都拒；
  CI 用临时钥匙串里的一次性身份）；真实 XPC 拒绝路径需实测（mac-proof I21，等用户说"装"）。
- **更新包固定签名者**：install.sh 除了签名完整，还要求 `certificate leaf` 等于已装那份的证书（更新；fork 的用户留在 fork），
  没装过时等于内置的发布证书 `RELEASE_SIGNER`。curl 限定 https（含跳转）。`package-release.sh` 核对发布证书与 RELEASE_SIGNER 一致。
  验证级别：install-test 新增 ad-hoc 发布被拒、首次安装证书不符被拒、更新以已装证书为准、http 列表被拒（CI harness）。
- **诊断包可公开**：服务器、Group、Cisco 条目名与地址在全文（含后台服务的说明与掉线原因）替换为 `<已隐去>`，名单只写种类不写内容。
  验证级别：`scripts/diagnostics-redaction-test.sh`。
- **后台服务日志默认不记 openconnect 输出**：原来所有安装都写（已遮密码，但有服务器名与用户名）；现在只有
  `sudo ALWAYSCONNECT_DEBUG_CHILD_OUTPUT=1 scripts/dev-helper.sh install` 时才写。

### 36.4 许可证
- 每次发布由 `package-release.sh` 一并生成 `AlwaysConnect-<版本>-third-party-sources.tar.gz`（按 SOURCES 下载并校验），
  与安装包放在同一个 Release 里，满足 LGPL"在同一位置提供对应源码"。
- 复核：THIRD_PARTY_NOTICES 与实际打包的 13 个库一一对应；自带的 vpnc-script 是独立实现（与 GPL 版只有两行普通判断相同）。
- 组件替换按 §34.2 的主动终端安装流程；§39.4 的 App 内管理按钮不接受修改后或 ad-hoc 重签的 App，防止用户可写包变成 root 执行入口。

### 36.5 发布包里不能有构建机的路径（2026-11-07，发布前扫描发现）
- Rust 的 panic 位置字符串带源码路径，crate 缓存在构建者家目录下（`~/.cargo/registry`），于是二进制里出现了构建机的用户名。
  build-local.sh 给 cargo 加 `--remap-path-prefix`（家目录 → `/build`，crate 缓存 → `/cargo/registry/src`）；
  package-release.sh 打包前扫描 App 里所有文件的字符串，出现家目录或 `/Users/<当前用户>` 就拒绝打包。
- 验证级别：本机打包 v0.2.0 后解包扫描：关键词清单与用户路径零命中。

## 三十七、修正：从设置里卸载时 App 退不掉（2026-11-07，用户："我在程序里点了卸载了，为什么还会在 apps 里面出现，没有删干净吗？"）

### 37.1 现象与证据
- 用户在设置 → 通用 → 卸载… 输完密码后，"应用程序"里仍有 AlwaysConnect。卸载脚本（§31）先等 App 正常退出再删文件，
  App 一直没退，脚本等满 60 秒后强制结束它，随后照常删完（事后核对：App、后台服务、随附 openconnect、日志、设置、钥匙串密码都已删除，网络直连）。
  用户看的时候正好在这 60 秒里。
- 系统日志：设置进程把"退出"转给菜单栏 App 的同一秒，App 隐藏了菜单栏图标、停掉了证书转接（退出流程已开始），之后再无任何输出；
  设置进程（App 的子进程，退出收尾会结束它）一直活着，说明 App 停在退出中途，收尾从未执行。

### 37.2 原因
- App 对退出答 `.terminateLater`，断开 VPN 的各步回调和 15 秒兜底都是主队列上的块；AppKit 在 `terminate` 里开一个嵌套 run loop 等答复。
  嵌套 run loop 在"正在执行的主队列块"里不会再执行别的主队列块。设置进程发来的"退出"由 DistributedNotificationCenter 的
  `.main` 观察者处理（OperationQueue.main，也走主队列），于是回调、兜底都排不上，退出永远等下去。
- 一键更新（§35.4）在 `DispatchQueue.main.async` 里调用退出，App 内卸载在 `asyncAfter` 里调用，同样会卡住。面板"退出"按钮从事件处理里调用，不受影响，
  所以平时退出正常。
- 最小 App 实测：在 `DispatchQueue.main.async` 或 `OperationQueue.main` 里调用 `terminate` → 卡住；在计时器或 run loop 块里调用 → 正常退出。

### 37.3 修正
- 新增 `AppQuit`（Sources/App/AppQuit.swift）：退出一律经 `CFRunLoopPerformBlock`（全部模式）从 run loop 本身发起，不在任何主队列块里。
  设置转来的退出、App 内卸载、一键更新、面板两个退出按钮都改用它。
- 双保险：退出收尾的最终答复同样经 run loop 送达；15 秒兜底改成加在全部模式上的 run loop 计时器，即使以后又有人在主队列块里调用退出，
  最多 15 秒也会退出（不再等卸载脚本的 60 秒强杀，也不跳过正常退出的断开 VPN 步骤）。
- 顺带：两个 harness（update-check-test、install-test）用的临时偏好域，结束时连同空的 plist 文件一起删除（之前会在 ~/Library/Preferences 留下空文件）。

### 37.4 验证级别
- CI harness `scripts/quit-test.sh`（已进 local-checks 与 CI macOS）：最小 App 按 `.terminateLater` + 主队列收尾，从主队列块、OperationQueue.main、
  后台线程、直接调用四种来源经 AppQuit 退出都在 5 秒内结束；旧写法（主队列块里直接 `terminate`）仍然卡住，证明 harness 测得出这个问题。
- 需实测：真机上从设置卸载时 App 几秒内退出、通知送达（mac-proof I17）；一键更新时 App 正常退出并换版（I20）。

## 三十八、从本机 Cisco 自动导入服务器（2026-11-07，用户："希望 app 在安装时能够自动读出来 anyconnect 上已经保存的 vpn 链接地址与描述信息，然后使用时走钥匙串保存的密码或者提示用户输入"）

### 38.1 现状与缺口
- §21.13 起服务器列表在"列表为空"时从 Cisco 配置导入一次（Swift XMLParser，只取 HostName → HostAddress），之后再不看 Cisco：
  Cisco 里新增、改地址、删掉的条目都不跟；默认选按名称排第一的，而不是 Cisco 上次连的那台；Cisco 记的用户名、组不预填；
  同一条目出现在两个 profile 文件里时靠"按名称去重"碰巧没重复，手加过同一地址的服务器会和导入的并列两条。
- 本机实测（只读，结论只写形状）：Secure Client 5 的 profile 目录有 4 个 XML，HostEntry 共 5 条、去重后 4 台（一条在两个文件里重复）；
  HostAddress 都是"主机:端口"，没有 UserGroup；另有 `mgmttun/` 子目录（管理隧道，不是用户可选的服务器）。
  偏好文件 `/opt/cisco/secureclient/vpn/.anyconnect_global` 的 `DefaultHostName` 是其中一条的主机名（不带端口、不是条目名），
  `DefaultHostAddress` 是另一个主机（与任何条目都对不上），`DefaultUser`、`DefaultGroup` 为空；没有 `~/.anyconnect`。

### 38.2 做法
- 解析与合并移到 Rust（core/src/cisco_import.rs，经 `ac_cisco_sync` / `ac_cisco_snapshot` 交换 JSON）；Swift 的 CiscoProfiles 只剩路径与薄壳，
  原 XMLParser 删除，连接时的条目名 → 地址（§20.6）、Cisco 引擎的网关放行表也改用同一份解析。Cisco 的文件只读不写。
- 来源：profile 目录（`/opt/cisco/secureclient/vpn/profile`、旧版 `/opt/cisco/anyconnect/profile`）顶层的 `*.xml`，文件按名排序，同名条目先到先得；
  子目录不读。只取 HostEntry 自己的 HostName / HostAddress / UserGroup（备用服务器、负载均衡列表里的 HostAddress 是别的网关，不取）；
  没有 HostAddress 时 HostName 本身就是地址（Cisco 的 schema 如此）；有 UserGroup 且地址没有路径时拼成"地址/组"（Cisco 的组 URL，§23 的地址解析认这种写法）。
  偏好文件：Secure Client 5 的全机文件、旧 AnyConnect 的 `~/.anyconnect` 与全机文件；记着服务器的、最新写入的优先，其余字段从别的文件补。
- 合并规则（每条都有 cargo test）：
  1. 新条目加到列表末尾，带"Cisco"小标、按条目名连接（§21.13 不变）。
  2. 已导入的条目 Cisco 里改了地址就跟着改；用户改过的显示名保留。
  3. Cisco 里没了的条目不删：转成普通条目、保留最后的地址；正选着它时，选择跟着变成这个地址。Cisco 读不到或一条都没有时（没装、权限、文件损坏）一律不动。
  4. Cisco 改名（地址不变）：原条目换成新名字，位置、选择都保留，不出现一新一旧两条。
  5. 手加过同一地址的服务器（主机名大小写、`https://`、默认端口 443、末尾斜杠都视为相同）直接挂到 Cisco 条目上，不重复列出。
  6. 用户删掉的条目（或手改地址、从 Cisco 条目变成普通条目的）记进 Profile.dismissedCisco，自动同步不再加回；账号页"从 Cisco 重新导入"清掉这份记录、全部重新取。
  7. 还没选服务器（首次运行）或选的那台没了：选 Cisco 上次连的那台——按条目名、显示名或主机（偏好里带端口时连端口）匹配 `DefaultHostName`，
     它为空时用 `DefaultHostAddress`；上次连的是直接敲进 Cisco 的地址（不是任何条目）时，把它作为普通条目加进来并选上；都没有就选第一台。
  8. 老版本只存了一个服务器的配置：那台照旧放在列表最前（§21.13 不变）。
- 什么时候同步（无计时器、不监视文件，开销不变）：App 每次启动时一次（在自动连接之前）；账号页（含首次向导的账号一步）每次显示时一次，
  有变化就在列表下面一行灰字说明"已从 Cisco 同步：新增…；更新…；…已不在 Cisco 里，保留为普通服务器"；点"从 Cisco 重新导入"总会给一句结果
  （含"已和 Cisco 一致（N 台）""本机 Cisco 里没有找到保存的服务器"）。Cisco 在连接时会从网关下载更新的 profile，所以下次启动就能跟上。
- 读不到时的回退：没装 Cisco 或没有条目时列表为空，脚注提示"点「添加服务器」填网关地址"，与以前手填一致；不显示"重新导入"按钮（没有 Cisco 目录时）。
- 账号与密码：用户名、Group 在第一次保存前用 Cisco 记的 `DefaultUser`、`DefaultGroup` 预填（只填表单，不自动保存，所以首次向导照常出现）。
  密码照旧：有钥匙串密码就用（§21.12，每次运行最多读一次），没有时面板按钮写"填写账号与密码"（列表还空时仍是"填写服务器与账号"），直达账号页。

### 38.3 验证级别
- Rust 单元测试（cargo test，CI 两路）：profile 与偏好的解析（备用服务器不混入、命名空间前缀、CDATA、实体、残缺 XML）、读目录（子目录与非 XML 跳过、
  重复去重、偏好文件取舍）与上面 8 条合并规则、再同步一次无变化。夹具只用 VPN-A… 与 example.com。
- 脚本级：scripts/list-rules-test.sh 现在连同 Rust 库一起编 CiscoProfiles.swift。
- 本机只读实测：用 App 的 CiscoProfiles 与 Rust 库读本机真实 Cisco 文件：得到 4 台（5 条去重），默认选中的正是偏好里上次连接的那台，局域网偏好照常读出。
- 需实测：账号页与首次向导的实际外观（"从 Cisco 重新导入"按钮、同步说明行）、删条目后重启不回来、重新导入后回来；Cisco 下发新 profile 后重启 App 跟上（mac-proof I22）。

### 38.4 本机实测（2026-11-07，用户在场）
- 装了一份标成 0.1.99 的 main 构建（只在本机改版本号、不提交），以便测"有新版本 → 一键更新"。首次启动即从 Cisco 导入 4 台、全带 Cisco 小标，
  选中的是 Cisco 上次连的那台（读 App 自己存的设置核对，只看形状）；用户走完向导、填用户名密码后连上（自建连接 + 分流）。
- 检查更新：面板出现"有新版本 0.2.0（预发布）"；点更新后成功换成 v0.2.0。时间线（系统日志）：12:05:27 开始下载，
  8.7 MB 安装包下到 12:07:40（约 2 分 13 秒），12:07:42 校验完、App 退出，12:07:43 新版打开——退出与换版只用了 1 秒（§37 的修正在真机上生效）。
  事后在同一网络上重跑同一下载只用了 6 秒，所以慢的是那一次的下载链路，不是脚本。
- 用户反馈两点：更新时"看不到进展、等了好久"（→ §38.5）；Group 没填也能连上，不知道干嘛的（→ §38.6）。
- 发布 v0.2.1 后用户在 v0.2.0 的设置页点"立即更新"：App 开始退出（菜单栏图标消失）后卡住，更新脚本等满一分钟放弃
  （update.log："AlwaysConnect 一分钟内没有退出，未更新"），旧版未被替换、新版未打开。这正是 §37 修掉的退出卡死，v0.2.0 里还没有那个修正；
  从 0.2.1 起的版本自带修正。处理：结束卡住的进程，用 install.sh 装上 0.2.1。结论：从 v0.2.0 升级不能用一键更新，要先退出再用终端一行命令。

### 38.5 一键更新显示进度
- install.sh 在 App 的暂存模式下先报一行 `DOWNLOAD <文件> <字节数>`（字节数取 GitHub 发布列表里安装包的 size），下载完报"正在校验…"；
  App 边读脚本输出边更新状态：查找安装包 → 下载（进度条 + "3.1 / 8.7 MB（VPN 照常可用）"）→ 校验 → "校验通过，正在退出并换上新版，几秒后自动打开…"。
  下载进度每 0.5 秒看一次文件大小，只在下载进行时运行，下完即停（开销规则）。
- 终端里的一行命令安装：下载安装包时显示 curl 的进度条（只在有终端时；App 调用与管道输出不变）。
- 验证级别：CI harness——scripts/install-test.sh 断言暂存输出带正确的大小与"正在校验"，UpdateInstallTest 断言 App 依次经过
  查找 → 下载（大小已知）→ 校验 → 退出换版。真机上的进度条外观需实测（mac-proof I20 ⑤）。

### 38.6 Group 说明
- Group 是网关上的登录组（Cisco 窗口里的 "Group" 下拉）。留空 = 网关默认的组，自建连接时不带 `--authgroup`；经 Cisco 连接时 AlwaysConnect 不传组，用 Cisco 自己的设置。
  只有单位让你选非默认的组时才需要填。账号页的 Group 框加了"一般留空"提示，脚注一句话说明。验证级别：本机编译；用户实测留空可以连上。

## 三十九、公开后安全加固（2026-11-07）

### 39.1 F2：pf 规则不再落临时文件
旧实现用可预测文件名写入 root 的规则，可能跟随其他用户预先创建的链接。现在 NetworkGuard 通过匿名管道把规则交给 `pfctl -a … -f -`；写入与输出读取并行，子进程退出后回收，不留下规则文件。session harness 的桩也只接受 stdin。检查其余 Rust 临时文件使用点：另外两处只在单元测试内；持久化状态仍在后台服务专属目录。
验证级别：Rust 单测、CI harness（session-test）；真实 pf 装载需实测（I23）。未运行 App，改前/改后 footprint、CPU、每秒唤醒均需实测；只增加装规则时短暂的管道写入线程，没有新增轮询。

### 39.2 F3：root 不回落到用户的 openconnect
后台服务默认只运行受信的内置组件，缺失时停止重试，返回「内置连接组件缺失或不可信，请重新安装后台服务」。校验包含文件和直到根目录的所有祖先：root 属主、没有组/他人写权限、没有符号链接。显式 openconnectPath 和测试 seam 保留；普通用户仍可用 Homebrew/PATH，run-once harness 不变。新增组件缺失终态（session reason 4）并显示面板红字，不把组件故障说成账号错误；封网仍需用户显式恢复。
验证级别：Rust 单测覆盖 root 默认路径不回落与非 root 默认选择；CI harness 覆盖现有显式路径。真实缺失组件的面板提示、断开出口需实测（I24）。

### 39.3 F5：管理员脚本子进程校验父进程
`--admin-script` 在读取 stdin 前通过 Security.framework 校验父进程的运行代码、同一叶子证书和可执行文件真实路径，校验前后确认 ppid 没变；动态代码校验和路径校验一起限制 PID 复用与替换路径。ad-hoc 开发构建要求相同 designated requirement（代码哈希）及相同路径。外部进程启动此入口会立即以 77 退出，不执行脚本。校验仍是系统 API 薄壳，没有新增常驻计时器。
验证级别：本机编译；`admin-parent-test.sh --adhoc-only` 验证同一父程序成功、外部父进程拒绝（仅执行返回字符串的 AppleScript，无提权）。完整证书 harness 已尝试，本机临时证书不受信任，codesign 报找不到身份，证书分支未验证；需 CI harness 和 I25 实测。

### 39.4 F1：提权后只执行验签的私有副本
安装/更新后台服务、强制恢复、恢复网络、卸载全部经 `PrivilegedBundle`：运行中的 App 取得自己的叶子证书哈希并核对运行代码；固定的 root shell 以 umask 077 创建 root 专用临时目录，复制整个 App，拒绝绝对或跨父目录的符号链接，改为 root 所有且不可由组/他人写，再以 `codesign --verify --strict --deep -R` 固定 App 标识和叶子证书校验副本。校验失败给中文错误并退出，成功才运行副本内脚本及后台服务；用完清理副本。卸载脚本的异步后半程仍使用其自己的 root 私有副本。shell 和 AppleScript 分别转义。
无证书的 ad-hoc 构建可以继续构建和测试，但管理按钮明确拒绝提权并说明使用已有开发证书；终端手动 `sudo …/dev-helper.sh install`、`sudo …/reset-network.sh` 保留，属于用户知情执行，后台服务原有拒绝 ad-hoc 客户端的规则不变。不自动建立长期身份。
LGPL 组件替换也使用 §34.2、§36.4 和随包 README-LGPL.txt 的主动终端流程，不能再通过 App 管理按钮安装修改后的包（R1 文档修正）。验证级别：说明生成和脚本级断言；实际替换安装需实测。
验证级别：本机编译；`privileged-bundle-test.sh` 为脚本级断言（执行顺序、两层转义、AppleScript 编译、bash 语法），并用真实 codesign 验证 ad-hoc 不满足证书 pin、改过的资源验签失败；未执行 root bootstrap。管理员安装/恢复/卸载及有效签名通过路径需实测（I26）。无新增常驻逻辑；改前/后 footprint、CPU、唤醒需实测。

### 39.5 F4：设置进程使用匿名私有通道
删除 DistributedNotificationCenter 的状态、动作、请求与回复广播和环境 token。父进程创建匿名 socketpair，只将子端继承为设置进程的 stdin/stdout；子进程先校验同签名、同路径的父 App。状态镜像、动作、回复和打开指定页均经过该通道，原动作及三秒超时不变。同会话的其他进程没有可监听或连接的名字，也不再能从广播取到权限凭据。
`SettingsTransport` 只做系统 IPC 薄壳：非阻塞描述符、DispatchSource 读写就绪、JSON 行的边界与一 MB 缓冲上限；不增加轮询，空闲不注册写就绪，错误/EOF 关闭并回收描述符。设置窗口退出释放通道；父进程退出触发 EOF，设置子进程随之退出。连接业务决策仍在原 Rust 核心与 App 外壳中。
验证级别：本机编译、CI harness（`settings-transport-test.sh`：双向请求/回复、换行转义、非法消息关闭、缓冲上限、EOF；检查无广播入口）。窗口交互与资源回收、改前/后 footprint/CPU/每秒唤醒需实测（I27）；未运行真实 App。

### 39.6 F6：安装包版本与发布绑定，默认拒绝降级
下载模式要求 CFBundleShortVersionString 与所选 tag 去掉 v 后完全一致；`--from` 必须传 `--expected-version`，App 的两阶段更新会传入所选版本。新包低于已安装版本时拒绝，只有终端显式 `--allow-downgrade` 可放行；即使放行降级，版本匹配和签名检查仍必须通过。版本比较分别处理数字段、预发布标识和构建元数据，稳定版高于相同核心版本的预发布版，数字比较不发生整数溢出；无效版本拒绝。App 沿用安装脚本的中文错误展示。
验证级别：`install-policy-test.sh` 脚本级断言（签名桩：拒绝降级、显式放行、版本不符、缺少期望版本、预发布数字排序、稳定版排序、无效版本）；`install-test.sh` 增加真实签名的降级、tag/包版本不符与放行用例，已尝试但本机测试证书不受信任，真实签名整环未验证，交后续 CI harness。真实更新及错误文案需实测（I28）。

### 39.7 F8：复制后仍固定同一签名者
`check_app` 首次确定的叶子证书 requirement 保留到整个安装结束。等待旧进程退出后再检查源包，复制到最终目标后使用同一 `-R` 复检，同时确认最终副本仍是期望版本，防止复制期间换入同证书旧包；不会因为旧 App 已移走而退回其他签名者。最终检查失败会删除新副本并由清理流程恢复旧版，ad-hoc 的完整签名不再能代替发布证书。
验证级别：`install-policy-test.sh` 脚本级断言模拟最终签名者不符，验证固定 requirement 和回滚；`install-test.sh` 增加 ditto 复制时替换为 ad-hoc 包的真实签名用例，但本机测试签名环境不可用，需 CI harness；真实换版/回滚需实测（I29）。

### 39.8 F10：后台服务限定一个 uid
采用首个通过签名校验的 XPC 客户端 uid 归属方案；uid 来自 NSXPCConnection 的系统凭据，不能由消息参数指定。NSLock 原子地登记归属，设置子进程、同用户重连与崩溃后的 App 可继续连接；其他 uid 在导出对象、订阅状态或读取全机连接列表前拒绝。归属保留到本次后台服务进程退出，包含两分钟崩溃宽限期，不会因临时 XPC 断开被其他用户抢走。
取舍：快速用户切换不会让新用户接管旧用户的 VPN，也不主动拆旧会话；新用户需等旧用户正常退出 App、后台服务按现有空闲机制退出后再连。已有 App 仍附着时不把“VPN 暂未连接”当作可以换主人的时机。此策略不引入控制台用户观察器或轮询，保留现有 App 拉起与宽限期生命周期；后台服务重启后由首个通过认证的 uid 重新建立归属。
验证级别：本机编译；`helper-uid-test.sh` 脚本级断言覆盖同 uid、不同 uid、并发竞争和新服务实例；session CI harness 覆盖退出、宽限期、恢复生命周期。真实多用户 XPC 与快速切换需实测（I30）；改前/后 footprint、CPU、唤醒需实测。

## 四十、局域网直连不依赖分流（2026-11-08）

### 40.1 直连网段的路由与分流 DNS 脱钩
本机只读排查（用户在场，未断开 VPN）：自建连接连着时打不开上一级路由器（光猫）的管理页 192.168.100.1。Mac 在 192.168.50.0/24，
光猫在第二跳（经 192.168.50.1），不在本机网段内；绑定物理网卡访问它返回 200，说明光猫与断线保护都没问题，但路由表把它交给隧道。
原因：这次会话的分流 DNS 没有启动（本机 53 端口无监听、系统 DNS 不含 127.0.0.1、名单网站也走隧道），而 `route_networks_direct`
在分流没在跑时直接跳过，于是网关声明的私网段（§28.5，含 192.168.0.0/16）、用户名单里的网段、自动识别的局域网都没有经物理路由器加路由；
pf 照常放行这些网段，只是没有路由。分流为什么没起来需要后台服务日志才能确定，另案处理。
改动（Rust 核心）：直连网段只要会话知道物理路由器就加路由，不再要求分流在跑；换网络时（`physgw` 变化、`follow_network`）不论分流在否，
本会话的直连路由都改指新路由器并重算网段。路由仍写同一份台账（`direct-routes`），断开、后台服务启动和恢复工具照旧撤销，清理路径不变。
分流在跑时行为与之前相同；没有分流时（含不经证书转接的 openconnect 连接）现在也会给这些网段加直连路由，与"局域网直连默认开"一致。
测试：fake-openconnect 支持 `FAKE_CONNECT_HOOK` 模拟真实网络才有的 `phys=/physgw=/lanex=`；session harness 新场景 `own-lan-direct`：
无分流的自建连接，网关声明的私网段写入台账并经 pf 放行，断开后台账清空。恢复旧判断时该场景失败，确认测试能抓到这个问题。
验证级别：CI harness（session-test）；真实效果需实测（I31）。常驻开销：只去掉一个判断，没有新增线程、计时器或轮询。

## 四十一、睡眠中的断线合成一条记录（2026-11-09，用户："睡眠这种断线场景是不是可以聚合一下啊，而不是每个都一条，也不要不记录"）

### 41.1 现象与原因（本机只读排查，未断开 VPN）
掉线记录里一晚上有 9 条"断了 1 秒，连接自己续上了"。电源日志（`pmset -g log`）显示当时合着盖子在睡（Clamshell Sleep），
系统每隔 15–18 分钟做一次暗唤醒（DarkWake，收邮件、同步等，屏幕不亮），每条掉线的开始时间与一次暗唤醒精确到秒地对上；
relay.log 里这些连接"开了 1000 秒左右、隧道计时只有 46 秒"，因为 Rust 的 `Instant` 在 macOS 上睡眠时不走。睡眠期间网关那头认定会话
断了，暗唤醒时 openconnect 发现连接已死，在同一个进程里用 Cookie 重连，1 秒内回来、不需要手机批准。开盖后整个白天一次没断。
这一秒里不漏网：openconnect 内部重连不退出、utun 与默认路由都在；分流在跑时 pf 只有一套（连着与断着相同），`attempt-reconnect`
不动 pf；断线保护开着。验证级别：代码 + 本机日志（relay.log、电源日志、路由与 DNS 现状）；pf 规则现状与 helper.log 需管理员密码，未看。

### 41.2 做法（`Sources/App/DropHistory.swift`，只依赖 Foundation）
- 睡眠窗口：App 收到 `NSWorkspace.willSleepNotification` 时打开，`screensDidWakeNotification`（屏幕亮起，即开盖或按键的完全唤醒）
  时关上；暗唤醒不点亮屏幕，所以一晚就是一个窗口。重复的"将要睡眠"不重置窗口起点。开盖后 60 秒内开始的掉线（开盖时才发现的断线）
  仍算这次睡眠的。
- 在窗口里开始的掉线照常走 `DropEpisodeTracker` 判定开始与结局，记录上带 `sleepSince`（窗口起点）；`DropRecord.appending` 遇到
  最新一条记录是同一窗口的就合进去：次数相加（`sleepDrops`）、实际断开时间相加（`downSeconds`，不是第一次断到最后一次恢复的跨度）、
  重新登录与手机批准次数相加、结局取最后一次、记下最后一次的开始时间（`lastDroppedAt`）。不在睡眠里的掉线照旧一条一条记。一条都不丢。
- 文案：诊断页这一行时间写"首次 – 最后一次"并标"睡眠中"，下面一句如"电脑睡眠时断了 9 次，合计 7 秒，每次都自己续上了（没有重新登录）"；
  面板"上次掉线"取最后一次的时间，如"睡眠中断了 9 次（合计 7 秒），都已恢复"。只合一次时写"电脑睡眠时断了 5 秒，……"。
- 合并后记录 id 不变，设置进程（§32.15）原来只比较条数与最新 id，看不到变化；快照里加了最新一条的签名（结束时间、合并次数、结局、
  重新登录次数），变了就重读。引擎在"已断开"之后报的终止原因照旧补到这一条上，自建连接补来的重新登录次数只加这次掉线新增的部分。
- 新字段都是可选，旧记录照常解码。逻辑仍在 Swift：属于 §32.8 已登记的"App 的 HelperClient（掉线记录）"，事件驱动、一晚几次，
  没有新增线程、计时器或轮询，只多两个系统通知的观察者。

### 41.3 验证级别
脚本级断言：`scripts/drop-history-test.sh`（CI 与 local-checks）新增睡眠窗口：醒着的掉线单独一条、三次睡眠掉线合成一条（次数、合计时间、
跨度）、重复的睡眠通知不重置、开盖 60 秒内的掉线合入（含重新登录与批准）、超过 60 秒单独一条、下一晚另起一条、最后一次没恢复的文案、
编解码往返。需实测：真实睡眠一晚后诊断页只出现一条合并记录，以及暗唤醒确实不发 `screensDidWakeNotification`（mac-proof D8）。

## 四十二、HTTPS 记录照转，只删地址提示（2026-11-09，用户："HTTPS记录那个问题，可以按你建议改"）

### 42.1 起因（本机只读排查，未断开 VPN）
用户发现名单里加了一个网站后，经 127.0.0.1 查这个网站的 HTTPS 记录（type 65）就拿不到了，名单外的网站照常有。原因是 §26.4 的规则：
名单内域名的 HTTPS(SVCB) 查询一律当场回空的 NOERROR，为的是不让记录里的 ipv4hint/ipv6hint（转发器没有先路由的地址）把连接带走。
代价是整条记录都没了：ALPN（HTTP/3）、ECH 密钥、端口等，浏览器只能退回普通 TCP。名单外则原样转发，记录里的 ipv6hint 在分流模式下
（pf 拦 IPv6）连不上。对照：名单外的公共站点经转发器与直接问隧道 DNS 结果一致；名单内域名拿到的是转发器自己生成的空答复（没有上游
答复里的 SOA）。转发器没有缓存，换上游、睡眠、重连都不影响这条规则，不是缓存或上游切换的问题。

### 42.2 做法（`core/src/dns_forwarder.rs` 的 `without_addresses`）
- HTTPS(65) 与 SVCB(64) 查询照常发问（名单内问本地 DNS、经物理网卡；名单外问隧道 DNS），答复交回前：每条 HTTPS/SVCB 记录删掉
  ipv4hint(4) 与 ipv6hint(6)（"mandatory" 里列了它们也一并删，删空就去掉 mandatory），A/AAAA 记录（常见于附加区）丢掉；其余原样
  （SvcPriority、TargetName、alpn、no-default-alpn、port、ech、OPT 等）。客户端只能连自己 A 查询拿到的地址：名单内的这些已先路由直连
  （§26.4），名单外的走隧道或按 geoip 判定（§26.13）。所以名单外也删两种提示，不只删 ipv6hint。
- 名单内保守处理：答复里有别的名字的 HTTPS/SVCB 记录（CNAME 指向别处）或 TargetName 不是 "."，客户端会接着去连一个名单未必覆盖的名字，
  这种照旧回空答复。名单外的这种记录照转（只删提示）。
- 只有确实要删东西时才重写报文，否则原字节交回。重写时问题区原样；名字展开后重写，只对与问题共享的后缀用压缩指针（问题区的偏移不变），
  SRV、DNAME、TargetName 不压缩。结果不会比原报文长（长了就不改：名单内回空、名单外原样），所以不会超出上游原答复的大小。
  报文读不懂（越界、指针环、长度不符）同样不改。
- AAAA 不变（§28.3），IPv6 仍不支持：隧道只配 IPv4（网关只分 IPv4，Cisco 客户端显示 IPv6 为 Drop All Traffic，§20.12），分流时 pf 拦 IPv6。
- 名单内的 HTTPS 查询现在会问一次本地 DNS（原先当场回空）。开销：重写一条带 ECH 的真实答复（195 → 147 字节）0.47 µs（release，
  同一台 Mac），每次查询整体约 96 µs（§32.6）；不加线程、计时器、缓存，空闲不变。

### 42.3 验证级别
Rust 单测（删提示而 alpn/ech/OPT 保留、丢附加区的 A、mandatory、无可删时原字节返回、名单内遇 CNAME 或别的 TargetName 回空而名单外照转、
坏报文不改；整环：名单内问本地 DNS 并删提示、名单外删提示）；dns-forwarder harness（经 Swift 壳）；local-checks 全过。
本机只读对照：真实隧道 DNS 的几条带提示与 ECH 的答复经临时端口上的转发器改写后，dig 经 UDP 与 TCP 解析正常，提示已删、ECH 与 alpn 在。
需实测：装新版后名单内网站的 HTTPS 记录可查到、浏览器能用 HTTP/3，连接页上这个网站仍经物理网卡（mac-proof I32）。

## 四十三、手机确认很快失败不再当成密码错（2026-11-09，用户重启路由器后 App 停在"账号或密码被拒绝"；用户："可以 修"）

### 43.1 现象与原因（本机 relay.log，未断开 VPN）
23:01 路由器重启，外网断了约 3 分半；期间引擎照常重试、换网关地址，断线保护一直封网。23:05:10 外网恢复，出口地址变了，网关不认旧会话，
要密码加手机确认。23:05:11 密码发出，网关扣住不回（3 秒后进入"等手机批准"，§30.9：只有密码对了网关才会去等手机）；14.5 秒后网关
退回账号密码表单（`Login failed`）。规则是"提交后 20 秒内失败 = 密码被拒，立即停下防锁号；超过 20 秒 = 批准过期，过会儿再发"
（§21.19、§30.9），14.5 秒落在前一类，于是停下、封网、写"账号或密码被拒绝"。90 秒后用户手动重连，5.5 秒批准、连上，密码并没有错。
手机确认这一步为什么失败日志分不出：手机同在刚重启的路由器上、确认没送到或回不来，或者被点了拒绝，两者网关的回答一样。

### 43.2 做法（Rust 引擎，`core/src/oc_engine.rs`）
- 这次密码请求若已进入"等手机批准"（网关扣住了回复，`approval_waited`），之后的 `Login failed` 不论多快都不是密码错。
  超过 20 秒的照旧按批准过期处理（30/60/120/300 秒重发）。
- 不到 20 秒就失败的：第一次按首个重发间隔（30 秒 ±20%）再发一次确认，状态写"手机上的登录确认没有通过，N 秒后重新发起"；
  连着第二次还这样，才停下，新的终止原因 `ApprovalDeclined`（引擎码 4，后台服务给 App 的码 5），红字与通知写
  "手机上的登录确认没有通过，已停止重连。确认手机能上网后点「重新连接」"，掉线记录原因写"手机上的登录确认没有通过"。
  只再发一次是为了真点了"拒绝"时不连续往手机推。连上即清零。
- 网关当场回绝（没进入等批准）仍按密码错立即停下，防锁号不变。停下后封网与恢复出口不变（故障关闭，面板一直有"断开 VPN，恢复直连网络"）。
- 经 Cisco 的引擎没改：Cisco 命令行对错密码打印 `Login error`，与 `Login failed` 可区分（§21.19）。

### 43.3 验证级别
CI harness：`scripts/approval-wait-test.sh` 新增 declined 场景（真 openconnect + 模拟网关：扣住密码 4 秒后 `Login failed`，过期门槛设 60 秒）：
先进入等批准、写"没有通过，N 秒后重新发起"、第二次登录、第二次失败后 `TERMINAL approval-declined`、从不出现 auth-failure、没有第三次；
原有的批准、瞬回、过期、错密码四个场景照旧通过。掉线记录对码 5 的原因由 drop-history-test 断言。真实网关上点拒绝的表现需实测（mac-proof D9）。
常驻开销：只多两个字段与一个分支，没有新线程、计时器或轮询。
