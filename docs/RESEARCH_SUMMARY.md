# 开源项目调研与提取总结

调研快照：2026-08-26

目标不是找一个“能 SSH 的 MCP”，而是组合结构化命令、参数级安全检查、主机策略、外部审批、脚本内容绑定、最小权限执行、防重放、审计和资源限制。

## 结论

没有发现一个项目同时完整满足：无任意 shell + 远端 argv/shell=False + 钉钉外部审批 + 脚本 SHA256 审批 + Agent 二次判级 + 一次性 nonce + 最小权限 OS 边界。因此项目提取不同实现的成熟思想，重新定义最终安全边界。

## 参考项目

### tufantunc/ssh-mcp

提取命令分级、角色/环境矩阵、审批绑定、host-key pinning、配额、审计和“上传也属于 destructive”的思想。没有照搬任意 SSH command string、交互 shell、通用 SFTP 或未知命令回落为 safe。

### tumf/mcp-shell-server

重点吸收结构化 `list[str]` + `create_subprocess_exec`、无 `shell=True`、最小环境、timeout/output cap 和参数级 escape 检查。历史 allowlist bypass 也说明 `shell=False` 不是完整沙箱，因此通用 sed/awk/git/tar 等在 MVP 中保持默认拒绝。

### Aegis-SSH-MCP

参考短生命周期 SSH session、host-scoped rule profile、无持久 shell/PTY/agent-forwarding 的思路。

### agent2ssh

参考 daemon approval queue、risk gate、scoped token、webhook HMAC、执行 gate、限流和审计，但不开放 PTY、隧道、通用 SFTP 等宽能力面。

### mcp-ssh-manager

参考多主机配置和工程化拆分，不直接作为底座，因为部署/sudo/数据库/备份/隧道/同步等功能面超出“AI 日常排障”的安全需求。

## DingTalk / Hermes 调研结论

DingTalk 官方互动卡片支持 REST 投放与 Stream callback；callback 提供真实用户身份。若 Hermes 已用同一 DingTalk 应用建立 Stream，Ops Guard 不应再起第二条同凭据 Stream。因此 v0.2.0 形成两种模式：Hermes 持有 Stream 并用确定性 HMAC bridge 转发，或 Ops Guard 使用独立 DingTalk 应用持有自己的 Stream。

## 最终原则

- 请求保持 structured argv，远端 Agent `shell=False`。
- unknown command = deny。
- 请求摘要绑定 host/argv/risk/expiry/nonce/script hash。
- 脚本使用内容寻址和 SHA256 防 TOCTOU。
- Agent 二次判级并拒绝网关风险降级。
- HMAC envelope + one-use nonce 防批准请求重放。
- Gateway 不向模型暴露 SSH key、任意 shell、approve 能力或审批 capability URL。
