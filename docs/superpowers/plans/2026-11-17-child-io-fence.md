# 子进程句柄继承窗口实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 关闭本项目描述符创建到CLOEXEC标记之间与子进程spawn重叠的窗口，避免子进程意外延长私有通道寿命。
**Architecture:** Rust child_io统一短互斥；创建/标记和spawn参与同一栅栏，网络收发、wait和输出读取在栅栏外。Swift通过C ABI取得已标记私有FD，显式映射stdin/stdout/stderr。
**Tech Stack:** Rust/std/socket2/libc，Swift Foundation薄壳；无新增依赖。
**Spec:** DESIGN.md §53.3及本轮§54；维护者2026-11-17明确要求修复。

## Global Constraints
- 不安装、不改当前网络、不发布；真实I37仍需授权。
- 保留信号重置、签名/UID检查、固定执行路径、凭据与日志标准通道。
- 不在锁内做网络收发、阻塞accept、readDataToEnd、wait或子进程运行。
- 创建失败/标记失败用所有权关闭FD，不遗失本应传给子进程的标准通道。

## Review Focus
- 不完整创建区域内不能exec；无关子进程不延长pipe/duplex EOF。
- 大输出读取先于wait，FileHandle映射后父端及时关闭，避免转换Foundation Pipe时新死锁。
- Spawn失败释放栅栏；现有重连/掉线保护没有新退出或自动回退行为。
- 全部自有Rust网络FD、wake pipe与Command路径登记，Settings双工通道和dup同样标记。
- 原端口失败可能兼有临时端口竞争，压力测试与继承窗口证据分别记录，不混称唯一原因。

## Tasks
- [x] TDD先跑两条失败回归，再实现child_io同步与CLOEXEC。
- [x] 将Rust socket/accept/raw-route/pipe创建与spawn/status统一登记。
- [x] Swift匿名pipe/Settings socketpair经Rust创建；原stdin/out/err映射并关闭父端不用的端点。
- [x] 增加真实私有管道/标准输入输出/EOF/大输出capture接线测试，更新独立Swift harness依赖。
- [x] 完整Rust/Swift构建与原有场景、并行压力（25轮）；隔离资源对照另行记录，不冒充真机验收。
- [ ] 隐私审查、代码/文档提交及Claude定向复核。
