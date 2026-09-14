# Roadmap

## v0.1.0：安全执行基础（完成）

- MCP structured argv
- unknown deny / argument-level policy
- immutable script SHA256
- SQLite approval state machine
- fixed SSH transport
- Remote Agent HMAC / nonce / policy replay
- trusted executable resolution
- hash-chain audit

## v0.2.0-v0.2.2（完成）

- Hermes + DingTalk 同会话互动卡片审批。
- 独立 DingTalk Stream 审批模式和完整 Runbook。
- 非 root Dockerfile、Docker Compose 独立 Stream 部署。
- Hermes 固定 stdio wrapper，不授予 docker-group 权限。
- Remote Agent 默认继续宿主机最小权限部署。

## v0.3：Typed Operations / Risk Routing

- 高频诊断与变更逐步改成 typed tools。
- `dev/staging/prod + critical service + batch scope + command risk` 计算审批层级。
- same-chat / ops-group / dual-approval / deny 自动分流。

## v0.4：组织审批

- RBAC：主机组 × 风险 × 申请人 × 审批人。
- 双人审批、申请人/审批人分离、值班组和超时升级。

## v0.5：凭据与隔离

- Vault/KMS、OpenSSH CA 短期证书、typed privileged helper、systemd/container sandbox、seccomp/SELinux/AppArmor。

## v0.6：HA / 审计

- PostgreSQL/HA approval store、Worker lease、外部不可变审计锚点、Prometheus/OpenTelemetry、fuzz security regression。
