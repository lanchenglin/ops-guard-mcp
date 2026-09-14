# 实施状态：v0.2.2

更新时间：2026-08-26

## 已交付链路

```text
Hermes/MCP structured argv
  -> default-deny policy
  -> exact request digest
  -> SQLite PENDING approval
  -> DingTalk interactive card
  -> authenticated card callback userId
  -> immutable APPROVED/REJECTED state
  -> atomic execution claim
  -> fixed SSH + signed envelope
  -> Remote Agent re-verification
  -> argv/shell=False
  -> bounded result + hash-chain audit
```

## v0.2.2 Docker / Compose 部署

- 非 root Dockerfile 和安全默认 Compose。
- Gateway/Approval Daemon/DingTalk standalone Stream 常驻容器。
- 默认不发布 8765 审批端口。
- `/var/lib/ops-guard` named volume，SSH 文件只读挂载。
- DingTalk ID discovery tools profile。
- Hermes 固定 root-owned stdio wrapper，避免 docker-group/Docker Socket 权限。
- 生产 Remote Agent 仍推荐宿主机最小权限服务。
- 完整操作手册：`docs/DOCKER_COMPOSE_STANDALONE.md`。

## v0.2.1 独立 Stream 部署加固

- 完整 Runbook、固定审批群配置模板、DingTalk ID 发现脚本。
- standalone Stream SDK/凭据 fail-fast。
- Stream 线程异常退出时停止 daemon，交给 systemd 重启。
- 首次上线推荐 `auto_execute_on_approval=false` 先验证审批状态链。

## v0.2.0 Hermes 同会话审批

- DingTalk 企业互动卡片 REST 创建与投放。
- `callback_owner=hermes|ops_guard`。
- Hermes 确定性 callback bridge，HMAC + timestamp + nonce。
- MCP schema 不暴露审批路由或 approve/reject。
- APPROVED/REJECTED 终态不可翻转。

## 测试

```text
PYTHONPATH=src python -m unittest discover -s tests -v
Ran 51 tests
OK
```

上线前仍需使用真实 DingTalk 应用、卡片模板、Hermes 实例与测试 SSH 主机联调。
