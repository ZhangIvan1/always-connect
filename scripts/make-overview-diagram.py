#!/usr/bin/env python3
"""Draws docs/images/overview.svg, the README's "它是怎么工作的" diagram.

Usage: python3 scripts/make-overview-diagram.py   (writes the SVG in place)

The picture the user chose (2026-11-09): two boxes saying what the menu-bar
App and the background service each do, then one row per way to connect.
Box colours match their owner: blue = App, orange = background service,
green = goes straight out, grey = not part of AlwaysConnect. Keep it this
simple; the details live in DESIGN.md. Sample names only (AGENTS.md).
"""
import os
from html import escape

FONT = ("-apple-system, BlinkMacSystemFont, 'PingFang SC', 'Hiragino Sans GB', "
        "'Microsoft YaHei', 'Noto Sans CJK SC', sans-serif")
COLOR = {  # fill, stroke
    "app": ("#e0ecff", "#3b82f6"),
    "service": ("#ffeedd", "#f97316"),
    "direct": ("#e3f8ea", "#22c55e"),
    "other": ("#f1f5f9", "#94a3b8"),
}
W, H = 980, 660
out = []


def text(x, y, s, size, color="#0f172a", bold=False, anchor="start"):
    weight = ' font-weight="700"' if bold else ""
    out.append(f'<text x="{x}" y="{y}" font-size="{size}"{weight} fill="{color}" '
               f'text-anchor="{anchor}">{escape(s)}</text>')


def program(x, y, kind, title, sub, bullets):
    fill, stroke = COLOR[kind]
    out.append(f'<rect x="{x}" y="{y}" width="410" height="200" rx="12" fill="{fill}" '
               f'stroke="{stroke}" stroke-width="2"/>')
    text(x + 22, y + 34, title, 18, bold=True)
    text(x + 22, y + 56, sub, 12.5, "#475569")
    for i, b in enumerate(bullets):
        yy = y + 90 + i * 27
        out.append(f'<circle cx="{x + 28}" cy="{yy - 5}" r="3" fill="{stroke}"/>')
        text(x + 40, yy, b, 13.5, "#1e293b")


def box(x, y, w, h, kind, title, sub=None, size=14):
    fill, stroke = COLOR[kind]
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" '
               f'stroke="{stroke}" stroke-width="1.5"/>')
    cx = x + w // 2
    if sub:
        text(cx, y + h / 2 - 3, title, size, bold=True, anchor="middle")
        text(cx, y + h / 2 + 16, sub, 12, "#334155", anchor="middle")
    else:
        text(cx, y + h / 2 + 5, title, size, bold=True, anchor="middle")


def arrow(points, kind):
    color, width = {"command": ("#475569", 1.6), "vpn": ("#1d4ed8", 3.2),
                    "direct": ("#16a34a", 3.2)}[kind]
    d = "M" + " L".join(f"{x},{y}" for x, y in points)
    out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}" '
               f'marker-end="url(#head-{kind})"/>')


def marker(kind, color, size):
    return (f'<marker id="head-{kind}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="{size}" markerHeight="{size}" markerUnits="userSpaceOnUse" '
            f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>')


# The two programs.
program(20, 20, "app", "菜单栏 App", "用你的账号运行，平时待在菜单栏", [
    "面板、设置、登录提醒、检查更新",
    "方式一：替你登录 Cisco，掉线重新登录",
    "方式二：证书转接，出示钥匙串里的单位证书",
    "密码和证书的私钥都留在钥匙串里",
])
program(550, 20, "service", "后台服务", "管理员权限，用的时候才启动", [
    "方式二：运行 openconnect，掉线自动重连",
    "按网站分流：本机查域名时分开，加直连路由",
    "断线保护：用防火墙关上本地出口（两种方式都用）",
    "断开时把改过的网络设置全部还原",
])
arrow([(430, 120), (550, 120)], "command")
text(490, 108, "发指令", 12, "#334155", anchor="middle")
text(490, 142, "连接、断开", 11, "#475569", anchor="middle")
text(490, 157, "分流名单", 11, "#475569", anchor="middle")

# The two ways to connect.
out.append('<line x1="20" y1="250" x2="960" y2="250" stroke="#e2e8f0" stroke-width="1.5"/>')
text(20, 280, "两种连法（面板上的「按网站分流」开关二选一）", 15, bold=True)

text(20, 312, "方式一 · 经 Cisco（开关关）", 13.5, "#1d4ed8", bold=True)
box(20, 324, 130, 54, "other", "你的软件")
box(200, 324, 490, 54, "other", "Cisco 建的 VPN 通道",
    "用你电脑上已装的 Cisco Secure Client，App 替它登录")
box(740, 324, 220, 54, "other", "单位 VPN 服务器", "vpn.example.com")
arrow([(150, 351), (200, 351)], "vpn")
arrow([(690, 351), (740, 351)], "vpn")

text(20, 420, "方式二 · 按网站分流（开关开）", 13.5, "#1d4ed8", bold=True)
box(20, 432, 130, 54, "other", "你的软件")
box(200, 432, 240, 54, "service", "openconnect 建的 VPN 通道", "后台服务运行它", size=13.5)
box(490, 432, 200, 54, "app", "证书转接", "在 App 里，出示单位证书")
box(740, 432, 220, 54, "other", "单位 VPN 服务器", "vpn.example.com")
arrow([(150, 459), (200, 459)], "vpn")
arrow([(440, 459), (490, 459)], "vpn")
arrow([(690, 459), (740, 459)], "vpn")
arrow([(85, 486), (85, 530), (200, 530)], "direct")
box(200, 506, 490, 48, "direct", "名单里的网站、家里局域网：不进通道，直接上网", size=13.5)

# Drop protection and the colour key.
out.append('<rect x="20" y="582" width="940" height="40" rx="8" fill="#fde8e8" '
           'stroke="#ef4444" stroke-width="1.2"/>')
text(490, 607, "两种方式下 VPN 断了：后台服务用防火墙先拦住该进 VPN 的流量，"
     "等连回来再放行，不会偷偷改走本地网络", 13.5, "#7f1d1d", anchor="middle")
text(20, 648, "颜色：蓝 = 菜单栏 App 负责　橙 = 后台服务负责　绿 = 直接上网　"
     "灰 = 不属于 AlwaysConnect", 12, "#64748b")

markers = (marker("command", "#475569", 9) + marker("vpn", "#1d4ed8", 7)
           + marker("direct", "#16a34a", 7))
svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
       f'viewBox="0 0 {W} {H}" font-family="{FONT}">\n'
       f'<!-- Generated by scripts/make-overview-diagram.py; edit that, not this file. -->\n'
       f'<defs>{markers}</defs>\n<rect width="{W}" height="{H}" fill="#ffffff"/>\n'
       + "\n".join(out) + "\n</svg>\n")

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "images", "overview.svg")
with open(path, "w") as f:
    f.write(svg)
print("wrote docs/images/overview.svg")
