# Claude 审查修正实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 修正 f52961d 独立审查发现的 DNS 可用性、状态与恢复缺口，保留故障关闭。
**Architecture:** Rust 决定策略与同步结果；Swift 只接系统事实、XPC 与证书操作。DNS 观察确认与全量直连收敛分开，不用未完成的可选新增拖住无关查询。
**Tech Stack:** Rust、Swift 系统外壳、现有回环/命令替身测试。
**Spec:** DESIGN.md §48–51；本轮独立审查按问题逐项验证，用户已要求直接修复。

## Global Constraints
- 保留单隧道与直连名单；VPN DNS 不退回本地解析。
- NetworkGuard 是唯一 PF 写入口；关闭保护及手动退出的现有语义不变。
- 本轮不安装、不动当前网络、不发布；所有系统命令使用替身。
- 不移除已观察 VPN 归属以腾出新的直连容量；所有常驻状态有界。
- 系统 API 的事实采集保留在 Swift，编排/授权/回落决策在 Rust。

## Review Focus
- 一条新增路由冲突时，无关 VPN 答复仍可确认；同 IP 的必要撤销未完成则不确认。
- 纯 VPN 新名字不触发完整直连核对；饱和安全退化必须可见。
- 首次网关、旧后台服务、慢物理 DNS 与 IPv6-only 本地 DNS的引导结果明确；保护中禁止系统回落。
- 网关引导不能改坏活动引擎的物理接口/DNS许可；清理待办不冒充封网。
- PF 重载保留或清空表的两种替身行为都收敛；表操作失败仍保留基础保护。

## Task 1: DNS 失败隔离与策略增量
**Files:** core/src/oc_engine.rs、core/src/split_policy.rs。
- [x] 先运行失败回归：单条直连新增冲突后五条无关 VPN 答复均被接受。
- [x] 先运行失败回归：纯 VPN 新观察返回未改变动态直连集合；共享 IP 观察确实改变集合。
- [x] 缓存当前有效地址集合和关联数，仅在动态集合变更/本答案依赖待办时同步。
- [x] 可选新增逐条处理；只启用已收敛地址，保留重试和错误；必要撤销失败仅拒绝受影响答案。
- [x] 容量到达时给出现有面板错误提示；保留有界归属记录，不丢弃已观察的 VPN 所有权。

## Task 2: 网关与活动物理上下文
**Files:** core/src/dns_forwarder.rs、core/src/ffi.rs、Sources/Helper/HelperDaemon.swift、Sources/App/HelperClient.swift、网关接线测试。
- [x] 先加并运行旧版本/慢DNS/多物理接口负例。
- [x] 使用完整网络总预算；首次连接不能把旧服务能力缺失误当空DNS。
- [x] 未受保护引导与保护中的解析按可验证状态区分；未知状态保持保守。
- [x] 活动引擎存在时优先其接口，并防止引导刷新覆盖活动DNS许可。

## Task 3: 清理状态与 PF 表
**Files:** core/src/direct_routes.rs、core/src/oc_engine.rs、core/src/network_guard.rs、相关 harness。
- [x] 先加并运行“只有中断意图不算封网”的状态回归，保留清理诊断与文件。
- [x] 先加并运行“规则重载清空表”的 PF 替身回归，再统一整表替换与失败回落。
- [x] 不通过盲删同签名路由消除诊断待办。

## Task 4: 收口
- [x] 运行完整 Rust 与适用 Swift/脚本 harness，再构建签名包。
- [x] 更新 DESIGN、HANDOVER、UI-DESIGN 和 I37，明确保留限制与验证级别。
- [x] 敏感信息扫描，分批本地提交；资源隔离对照不冒充真机验收。
