# AGENTS.md

给在这个仓库里干活的人和 AI 助手。先读 HANDOVER.md（当前状态与后续方向），
再读 DESIGN.md（契约与每条实测结论，§二十 起是真实 Mac 上的实测与 Cisco 引擎），
UI-DESIGN.md 只管界面。不要凭记忆复述设计，设计变了以 DESIGN.md 为准。

## 项目一句话

macOS 菜单栏 App：借本机 Cisco Secure Client 连公司 VPN（证书由 Cisco 出示），
自己负责自动登录、掉线无限重连、断线期间 pf 封网不漏、家里局域网可达。
另有一套 OpenConnect 自有引擎（"自建连接"）：经 App 内证书转接出示钥匙串证书，是分流的基础（DESIGN §二十三）。

## 构建与验证

```bash
scripts/build-local.sh --tests      # 只需 Command Line Tools：编 Rust + App 与后台服务两个 Swift 目标，
                                    # 组装 .local-build/AlwaysConnect.app，跑本机断言（local-checks）
scripts/cisco-engine-test.sh        # Cisco 引擎逻辑（假 Cisco CLI，9 个场景）
scripts/relay-test.sh               # 自建连接的证书转接（测试证书 + 要求客户端证书的模拟网关）
cd core && cargo test               # Rust 核心
scripts/drop-test.sh                # 真实断线测：需已连 VPN、App 在跑、用户手机批准一次
```

- CI 两路（.github/workflows/ci.yml）：Linux（Rust + 本地 ocserv 认证）与 macOS
  （XcodeGen 工程编译、引擎整环含掉线重连、vpnc-script 分支与路由计划、pfctl 规则解析、
  Cisco 引擎 harness、证书转接 harness、会话与进程清扫 harness）。推送后 CI 全绿再汇报。
- 后台服务（Helper）的本机安装：App 里点"安装/更新后台服务"（管理员密码框，内部即
  `scripts/dev-helper.sh install`）；救急恢复本地网络 `sudo scripts/reset-network.sh`（不依赖 App 与网络，
  结束本项目进程、清路由/DNS 残留/pf；用户桌面有双击版"AlwaysConnect 恢复网络.command"），
  只清 pf 与路由状态用 `sudo scripts/dev-helper.sh recover`；面板也有"恢复网络"按钮。
- 给用户装到"应用程序"：`scripts/install-app.sh`（先正常退出正在运行的那份，替换前要告诉用户）。
- 干净卸载：设置 → 通用 → 卸载…，或 `sudo bash <App>/Contents/Resources/uninstall.sh`（`--dry-run` 只列清单；DESIGN §三十一）。
  App 新写到系统里的任何文件、偏好或钥匙串条目，都要同批加进 uninstall.sh 与 scripts/uninstall-test.sh。
- 自包含（DESIGN §二十七）：用户机器只需 macOS（经 Cisco 时另需 Cisco）；openconnect 由 `scripts/bundle-openconnect.sh` 打进 App，
  构建机才需要 Homebrew 的 openconnect。root 只运行安装到 `/Library/PrivilegedHelperTools/AlwaysConnect-openconnect` 的那份。
  不要再引入依赖用户安装的软件包；界面与默认值里不写任何公司特有的名字。
- 签名：build-local.sh 有本地自签身份"AlwaysConnect Local Dev"（scripts/dev-signing-identity.sh）
  时用它签，钥匙串"始终允许"才不会因重编失效；发布包（scripts/package-release.sh）也用这同一个身份，
  "始终允许"才能跨版本有效（DESIGN §35.5）。所有发布只用这一个身份，不要换。
  后台服务只接受与它同一张证书签名的 App（DESIGN §36.3），ad-hoc 构建连不上后台服务；install.sh 的 RELEASE_SIGNER 就是这张证书。
- 安装与更新：没有开发者签名与公证，README 的主路径是一行命令 `install.sh`（curl 下载不带隔离标记）；
  App 的 [更新] 用同一个脚本（DESIGN §三十五）。改 install.sh 必须跑 `scripts/install-test.sh`。
- 界面截图：离屏渲染（NSHostingView + CALayer），无需屏幕录制权限；强调色按钮在离屏下显示为灰。

## 验证级别（汇报时必须分清，不许混着说）

- CI 编译：只证明能编、能链接。
- 脚本级断言：伪造 env / 桩命令跑脚本分支，证明逻辑，不证明 Mac 上的实际效果。
- CI harness：mock 网关、假 openconnect、假 Cisco CLI，证明引擎逻辑整环。
- 本机实测：真实 Mac + 真实网关（需用户在场：密码、手机批准、管理员密码）。
  已测项与待测项见 docs/mac-proof-checklist.md；没跑过的写"需实测"，不写"已验证"。

## 工作方式

- 按批改、按批提交：一个提交只做一件事，提交信息写清改了什么与为什么。
- 代码与文档同批改：改行为必改 DESIGN.md（新问题开新小节，写明验证级别），
  改界面必改 UI-DESIGN.md，状态变化同步 README / HANDOVER。
- 结论以 git HEAD 为准，不以工作树为准；读到"已经修好"先查 `git status`。
- 用户纠正时：先承认、再改代码与文档，跟进所有受影响处，不辩解旧版本。
- 对用户说话用大白话：说"后台服务"不说"Helper"，说"断线保护"不说"kill switch"。
- 会动到用户本机网络的测试（封网、断线）先说明影响和恢复办法，需要用户配合的给出一步步指令。
- 动网络之前先留退路（用户两次被断网后的硬要求，DESIGN §24.6）：恢复工具就位且用户知道怎么用；
  测试本身要有自动回退（连通性探测失败即撤销改动），不许让用户在没有退路的情况下测。

## 硬规则（违反即返工）

- **常驻逻辑用 Rust，Swift 只做界面与系统外壳**（用户约定，2026-11-06 重申："后续不要再犯，不要劣化"）：长时间运行、
  逐包/逐请求执行的逻辑（转发、分包、解析、规则匹配、DNS、编排决策，包括暂停/恢复、代次、重试、收尾核验这类状态机）写在 `core/`（Rust，经 C ABI 调用），由 cargo test 覆盖；
  Swift 只放 SwiftUI/AppKit 界面、XPC、钥匙串与 Security.framework（证书私钥签名、TLS 握手）、Network.framework/系统 API 的薄壳。
  新功能不许把常驻逻辑写进 Swift；改到现有的 Swift 常驻逻辑时顺手迁移或先在 DESIGN §32.5 的迁移清单里登记。
- **开销不劣化**：用功能时可以占内存，用完必须归还——窗口、面板、气泡关上即释放（不是只 orderOut），循环动画、`Timer.publish`、
  轮询只在看得见时运行；常驻进程不缓存大数据（按需读、用完丢）；日志必须有上限；重复计时器给容差。改动涉及常驻路径时，
  汇报里写出改前改后的 `footprint` / CPU / 每秒唤醒（`top -stats cpu,idlew`），基线见 DESIGN §三十二；变差即返工。
- **故障关闭优先**：掉线时封网，只有用户手动断开、退出 App 或关掉"断线保护"才恢复直连（唯一例外：自建连接刚连上两分钟内 30 秒不通的自检自动断开，用户选定，DESIGN §26.11）；
  任何时候面板都要有一键恢复直连的出口，不能把用户困住。
  新增任何会自动断开 VPN 或撤掉断线保护的功能：必须默认关闭、由用户主动开启，界面写明影响；
  触发条件能被伪造的（Wi-Fi 名称、DNS 搜索域/服务器与应答、明文 http）必须在界面上提示，并提供经 TLS 证书校验的条件可选（PR #4 审查）。
- **退出 = 不开 VPN**：退出 App 断开 VPN、恢复直连，后台服务空闲自退；只有崩溃才保持封网，且最多 2 分钟
  （网络闸门的宽限期，期间尝试把 App 拉起来；DESIGN §25.2）。关机/重启等同退出：别的开机留下的封网记录一律作废，
  开机时绝不封网（DESIGN §23.12，用户曾因此整机断网）。pf 只能经 NetworkGuard 写，不许另开写入点。
- **不绕过公司管控**：Cisco 连接期间由 Cisco 执行公司的分流名单，不做任何绕过 Cisco 过滤器、
  篡改其路由的功能（自定义域名直连的合规路线见 DESIGN §二十二）。
- **公开仓库零敏感信息**（仓库是公开的；2026-11-06 曾为此改写全部历史、删掉发布包和旧 CI 记录，不许再犯）。
  进仓库的任何东西都不能让人看出用户在哪家公司、公司内网怎么配置、用户是谁，具体如下：
  - 不写：公司名，公司网关域名/IP，公司内部 CA 或证书名，公司内部系统和工具名（包括登录审批用的聊天/认证 App，
    统一写"手机上确认登录"），本机 Cisco 配置里的服务器条目名和 Group 名（示例一律用 VPN-A、VPN-B… 和 Staff），
    公司内网网段，用户名、工号、密码、公司邮箱，本机用户路径（`/Users/<真名>`），用户的个人动机或私人账号情况。
  - 实测结论照样写进 DESIGN / 实测清单，但只写行为和数字，把上面这些替换成示例值。
  - 范围不只是代码：文档、代码注释、脚本默认值、测试桩和夹具、UI 草图、截图、日志样本、提交信息，
    以及 CI 日志（测试输出公开可见）和 Release 包（二进制里的字符串也算）。
  - 截图只用离屏渲染加示例数据，不读真实钥匙串、Cisco 配置和连接状态；真机截图和诊断包只留在本地，不提交。
  - 提交身份用仓库本地配置的个人身份，`git log` 不得出现公司邮箱。
  - 推送前对 `git log -p origin/main..HEAD`（含提交信息）和新增的图片、二进制做一次关键词审查；
    关键词清单只放在本地，不写进仓库。发现已经推上去了，先停下来告诉用户，不要自己改写历史。
- **提权与进程边界**（DESIGN §36.3、§三十九；违反即提权漏洞）：
  - root 只执行 root 私有、验过签名的东西：不从用户可写位置（App 包、`/opt/homebrew`、`/usr/local`、`/tmp`、用户目录）
    执行脚本或程序；需要管理员密码的操作先把 App 复制到 root 私有目录、用 App 自己的证书 `codesign --verify --strict --deep -R` 验签，
    只执行副本（PrivilegedBundle）。root 不写可预测路径的临时文件，数据走 stdin 或 root 私有目录。
  - 后台服务只接受与它同一张证书签名的 App（按审计令牌逐条消息校验），一次生命周期只服务一个登录用户；新增 XPC 方法同样受此约束。
  - 进程之间不用广播（DistributedNotification 之类）或环境变量传状态和令牌，用父子继承的私有通道；
    管理员脚本子进程先校验父进程是本 App。
  - 安装与更新：签名者固定（已装那份的证书，首装为 RELEASE_SIGNER）、包内版本必须等于发布标签、默认拒绝降级、复制后复检；
    install.sh 不得新增下载源，curl 只走 https。发布包不得含构建机的路径或用户名（package-release.sh 会拒绝）。
- Phase 1 三个 XPC 方法（connect/disconnect/getStatus）签名不动；新增 XPC 方法一律 App 侧
  3 秒超时回落。XPC 客户端必须导出 AlwaysConnectHelperClientProtocol，否则 Helper 的状态推送会让连接失效。
- 钥匙串：判断"有没有存密码"只用 KeychainStore.exists（不取数据、不弹授权）；真正读密码只在连接时，
  每次运行每个账号最多一次。
- openconnect 路线：Cookie 只从 `--dump-http-traffic` 的 CSTP CONNECT 请求头取；掩码必须盖住
  webvpn=、webvpncontext=、`<password>`，且掩码后搜索起点移到掩码值之后。
- 不猜真实网关行为：批准超时表现、退出码文案等一律等实测，不编造默认值。
- 二手资料说的 API 与开关，以编译器、头文件与实测为准。

## 外部贡献与 PR（贡献者和审 PR 的人都要看）

- 开工前和提 PR 前都 rebase 到最新 main。DESIGN 新小节号、mac-proof 实测清单编号取当时最大值加一，提交前 `grep` 确认没被占用。
- 本仓库文档里的"用户"专指维护者本人，引号里的话必须是维护者原话。贡献者自己提出的需求写"外部贡献（PR #N）"，
  维护者同意后补上同意的日期与范围；不得替维护者编写引述。
- PR 描述按上面的验证级别写清楚哪些是 CI/脚本级、哪些需实测；未实测项列进 docs/mac-proof-checklist.md；
  涉及常驻路径的附改前改后开销数据；同样遵守"公开仓库零敏感信息"，推送前做关键词审查。
- 审外部 PR：先看 CI 配置、install.sh、依赖与下载源、签名与发布脚本、后台服务 / XPC / pf 的改动，确认没有供应链风险，
  再批准 fork 的 CI 运行；本机测试只在 `git archive` 解出的临时目录里跑，不在共享 checkout 里执行未审过的代码。
  合并必须由维护者确认。Dependabot 升级 Rust crate 后要重跑 `scripts/make-rust-notices.sh`。

## 已知的坑

- `grep -c` 计数为 0 时退出码为 1，`bash -e` 下会杀掉 CI 步骤，调试打印加 `|| true`。
- 被 cancel 的 DispatchSource 若仍 suspended 就释放，会静默 SIGTRAP；close 里 cancel 后按标志位 resume。
- 写 socket / 管道必须防 SIGPIPE（SO_NOSIGPIPE / 忽略信号），否则一条被重置的连接带崩整个进程。
- pf 锚点必须挂在 `com.apple/` 下才会被系统规则集求值，且要用 `pfctl -E` 引用计数开启 pf。
- 菜单栏程序的窗口与弹出面板要先 `NSApp.activate`，否则窗口在后面、原生控件画成灰色。
- Swift 合成的 Codable 对缺失键会抛错（不会回落默认值），给持久化模型加字段要写 decodeIfPresent。
- zsh 不做分词、`=` 开头会被展开；脚本里用 bash。Python 原地改文件别写 `open(p,'w').write(open(p).read())`。
- `pfctl` / `route` / `scutil` 的实装命令 CI 跑不到：脚本保证测试模式（ALWAYSCONNECT_NO_ROUTES=1）
  能跳过，路由计划用桩命令断言。

## 目录

- `Sources/App/` 菜单栏 App：面板、设置五页（通用/账号/分流/连接/诊断）、分流名单规则与数据（ListRules、GeoData）、向导、Cisco 引擎（CiscoEngine）、证书转接（CertificateRelay）、钥匙串、图标
- `Sources/Helper/` 后台服务（root LaunchDaemon）：openconnect 引擎、vpnc-script、pf（PfController、
  KillSwitch）、诊断
- `Sources/Shared/` App 与后台服务共用的模型与 XPC 协议
- `core/` Rust 核心：规则引擎、pf 文本生成、会话驱动、FFI；`core/scripts/` 测试用的假网关与桩
- `scripts/` 本机构建、检查、安装、实测脚本；`docs/` 研究输入、实测清单、README 截图与架构图（`scripts/make-overview-diagram.py` 生成）
- `project.yml` 是 Xcode 工程定义的唯一来源（生成物不进仓库）
