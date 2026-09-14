# Security Policy

生产安全不变量和威胁模型见：

```text
docs/SECURITY_MODEL.md
```

最关键的生产要求：

1. 模型没有 SSH key、任意 shell、approve/reject tool。
2. DingTalk 审批以互动卡片 callback `userId` 为身份，不解析聊天中的“确认”。
3. Hermes 场景使用 `callback_owner="hermes"`，不要让相同 DingTalk Client ID 同时运行第二个 Ops Guard Stream。
4. Hermes callback bridge 使用 HMAC、timestamp、one-use nonce；bridge secret 不进入 MCP 上下文。
5. `allowed_approver_user_ids` 在生产必须配置。
6. Remote Agent 必须使用非 root、无通用 sudo 的专用账户。
7. 生产脚本默认关闭。
8. Gateway/Hermes/Agent 应分账户或容器运行。

漏洞报告不要在公开 Issue 中包含：凭据、SSH 地址/私钥、DingTalk secrets、bridge secret、审批 capability URL 或针对真实生产环境的利用细节。发现泄漏后立即轮换相关凭据。

## Docker / Compose deployment boundary (v0.2.2)

The Docker deployment intentionally containerizes the Gateway/Approval Daemon/DingTalk Stream, not the production host-management Agent.

Security requirements:

- run the Ops Guard container as non-root;
- do not mount `/var/run/docker.sock` into Hermes or Ops Guard;
- do not add the Hermes service account to the Docker group;
- use the fixed root-owned `docker/ops-guard-mcp-stdio` wrapper when host-side Hermes must reach the containerized stdio MCP;
- keep SSH private keys outside the image and mount them read-only;
- keep the approval HTTP port unpublished in standalone Stream mode;
- keep production Remote Agent as a least-privilege host service unless a separate container threat model is explicitly designed.

Granting Docker Socket access or a privileged host-management container can bypass the execution boundary this project is intended to enforce.
