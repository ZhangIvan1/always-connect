# 第三方组件声明（Third-Party Notices）

AlwaysConnect 本身按 [LICENSE](LICENSE)（MIT）发布。App 安装包里还带有下列第三方组件，
它们各自按自己的许可证提供，**不因随 AlwaysConnect 分发而改变**。本文件与全部许可证正文随每一份 App 一起分发
（`AlwaysConnect.app/Contents/Resources/` 下的 `THIRD_PARTY_NOTICES.md`、`LICENSE.txt`、`third_party/`、
`openconnect/licenses/`）。清单的维护方式见 DESIGN.md §三十四。

## 1. OpenConnect 及其加载的库（LGPL 等）

位置：`AlwaysConnect.app/Contents/Resources/openconnect/`（安装后台服务时复制到
`/Library/PrivilegedHelperTools/AlwaysConnect-openconnect/`）。由 `scripts/bundle-openconnect.sh`
从构建机的 Homebrew 复制，未作修改。

| 组件 | 文件 | 许可证 |
|---|---|---|
| OpenConnect | `bin/openconnect`、`lib/libopenconnect.5.dylib` | LGPL-2.1 |
| GnuTLS | `libgnutls.30.dylib` | LGPL-2.1-or-later |
| Nettle（含 hogweed） | `libnettle.9.dylib`、`libhogweed.7.dylib` | LGPL-3.0-or-later 或 GPL-2.0-or-later（双许可） |
| GMP | `libgmp.10.dylib` | LGPL-3.0-or-later 或 GPL-2.0-or-later（双许可） |
| p11-kit | `libp11-kit.0.dylib` | BSD-3-Clause |
| libtasn1 | `libtasn1.6.dylib` | LGPL-2.1-or-later |
| libidn2 | `libidn2.0.dylib` | LGPL-3.0-or-later 或 GPL-2.0-or-later（双许可） |
| libunistring | `libunistring.5.dylib` | LGPL-3.0-or-later 或 GPL-2.0-or-later（双许可） |
| gettext（libintl） | `libintl.8.dylib` | LGPL-2.1-or-later |
| stoken | `libstoken.1.dylib` | LGPL-2.1-or-later |
| LibTomCrypt | `libtomcrypt.1.dylib` | 公有领域（或 WTFPL，双许可） |
| LibTomMath | `libtommath.1.dylib` | 公有领域（The LibTom license，Unlicense 式） |

- **许可证正文**：`openconnect/licenses/<组件>/`（各项目自带的文件）与 `openconnect/licenses/*.txt`
  （LGPL-2.1、LGPL-3.0、GPL-2.0、GPL-3.0 全文，仓库里在 `third_party/licenses/`）。
- **确切版本与对应源码**：`openconnect/VERSIONS` 写明版本，`openconnect/SOURCES` 列出每个版本的上游源码包地址、
  SHA-256 以及 Homebrew 打在其上的补丁。`scripts/fetch-third-party-sources.sh <目录>` 按这份清单下载全部源码并校验。
  **把 App 交给别人的人**，应同时附上这些源码包，或在同一位置提供下载；对方索取时须提供。
- **可替换**：AlwaysConnect 不链接这些库，只把 `bin/openconnect` 当作独立程序运行；`bin/openconnect` 经
  `@loader_path` 加载旁边 `lib/` 里的库。用户可以用自己编译的同名文件替换其中任意一个，做法见同目录的
  `README-LGPL.txt`（替换后 `codesign --force --sign -` 重签，再在 App 里点"安装/更新后台服务"）。
  App 不校验这些文件的哈希，不阻止替换。

## 2. 链接进 App 与后台服务的 Rust 库

`libalwaysconnect_core.a`（`core/`）静态链接了下列 crate，均按其 MIT 选项使用：
itoa、libc、memchr、regex-lite、serde、serde_core、serde_json、socket2、zmij。
每个 crate 的版本、仓库与版权声明全文见 [`third_party/rust-crates.txt`](third_party/rust-crates.txt)
（`scripts/make-rust-notices.sh` 从 `core/Cargo.lock` 生成，local-checks 检查它与锁文件一致）；
Apache-2.0 正文在 `third_party/licenses/Apache-2.0.txt`。只在编译期运行的 crate（serde_derive、syn、quote、
proc-macro2、unicode-ident）不进入产物，不在此列。

## 3. 分流名单数据

- `geosite.txt`：由 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 生成，
  MIT License，Copyright (c) 2018-2019 V2Ray；全文见 `third_party/licenses/v2fly-domain-list-community.txt`。
  它只是公开的"域名 → 类别"清单，用于用户自己选择哪些网站走本地网络。
- `geoip-cn.txt`：由 APNIC 公开的地址分配统计（`https://ftp.apnic.net/stats/apnic/delegated-apnic-latest`）
  合并生成的网段列表，属公开事实数据。

生成方式与日期见 `Sources/App/GeoData/README.md`。

## 4. 系统组件（不随 App 分发）

App 只调用 macOS 自带的框架（AppKit、SwiftUI、Security、Network 等）和系统库（libxml2、zlib 等），
不带任何第三方 Swift 包。经 Cisco 连接时调用用户机器上**已经安装**的 Cisco Secure Client 命令行，
App 不包含、不分发、不修改 Cisco 的任何文件。

## 5. 商标

Cisco、Cisco Secure Client、AnyConnect 是 Cisco Systems, Inc. 及/或其关联公司的商标或注册商标。
OpenConnect 是其各自作者的项目名称。AlwaysConnect 是独立的个人项目，与 Cisco 没有任何关联，
未获其认可、赞助或授权；文中出现这些名称只为说明兼容的软件。
