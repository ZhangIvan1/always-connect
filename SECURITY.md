# 安全问题报告（Security Policy）

AlwaysConnect 带一个以 root 运行的后台服务，并会改动本机的路由、DNS 和防火墙（pf）。
如果你发现可能被利用的安全问题（例如本机其他程序能操纵后台服务、更新包可被替换、凭据泄露），
**请不要开公开 Issue**，改用 GitHub 的私下报告：

- 仓库页面 → **Security** → **Report a vulnerability**
  （<https://github.com/weiazm/always-connect/security/advisories/new>）

请写明：macOS 版本、AlwaysConnect 版本（设置 → 通用 → 版本）、复现步骤和你看到的影响。
**不要附上**真实的 VPN 服务器地址、账号、密码、证书或未脱敏的诊断包。

这是个人维护的项目，没有固定的响应时限；收到后会尽快确认，修复后在发布说明里致谢（你不希望署名的除外）。

只处理最新发布版本。不在范围内的：需要先拿到本机管理员权限才能做到的事，单位 VPN 网关或 Cisco Secure Client 本身的问题
（请报告给相应厂商或你的单位 IT）。

---

Please report security issues privately via GitHub's **Report a vulnerability** (Security tab), not in public issues.
Do not include real VPN server names, accounts, passwords or certificates.
