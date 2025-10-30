# TODO（当前阶段：Phase VII-A · MVP）

> 本清单聚焦 P0 任务，遵循：单一职责、可验证、可在独立分支交付。

---

## P0 · 接口骨架与最小闭环

- 健康检查端点
  - 路径：GET `/health`
  - 完成标准：200 OK，`{"status":"ok","time":"<local>"}`
  - 验证：`curl --max-time 5 -i http://127.0.0.1:8080/health`
  - 分支建议：`feature/health-endpoint`

- WebFinger 端点
  - 路径：GET `/.well-known/webfinger?resource=acct:<name>@<host>`
  - 完成标准：200 OK，JRD 格式，`links[].rel=self` 指向 Actor URL
  - 验证：`curl --max-time 8 -s "http://127.0.0.1:8080/.well-known/webfinger?resource=acct:alice@localhost" | jq`
  - 分支建议：`feature/webfinger`

- Actor Profile 端点
  - 路径：GET `/users/<name>`
  - 完成标准：200 OK，`application/activity+json`，含 `@context/id/type/inbox/outbox`
  - 验证：`curl --max-time 8 -H "Accept: application/activity+json" http://127.0.0.1:8080/users/alice | jq`
  - 分支建议：`feature/actor-profile`

- Outbox 占位
  - 路径：GET `/users/<name>/outbox`
  - 完成标准：200 OK，`OrderedCollection` 空集合
  - 验证：`curl --max-time 8 -H "Accept: application/activity+json" http://127.0.0.1:8080/users/alice/outbox | jq`
  - 分支建议：`feature/outbox`

- Inbox 占位（含 shared inbox）
  - 路径：POST `/users/<name>/inbox`、POST `/inbox`
  - 完成标准：202 Accepted（占位实现，不做签名校验）
  - 验证：`curl --max-time 10 -X POST -H 'Content-Type: application/activity+json' -d '{}' http://127.0.0.1:8080/inbox -i`
  - 分支建议：`feature/inbox`

---

## P0 · 框架与规范统一

- 全局 ID 与时间规范
  - 内容：scru128 生成 ID；时间统一使用 `chrono::Local::now().naive_local()`
  - 完成标准：接口/日志示例与文档更新
  - 分支建议：`chore/id-time-conventions`

- 配置约定与运行参数
  - 内容：约定 `AP_BASE_URL`（Actor URL 拼接）、`AP_LISTEN`（监听地址）
  - 完成标准：README/PLAN 同步说明，示例命令可运行
  - 分支建议：`chore/config-baseline`

---

## 注意

- 本阶段不引入签名校验、不做分发重试与队列
- PR 前需确保通过 `cargo check` / `cargo clippy`（若已有代码）
- 提交遵循 Conventional Commits；每个 TODO 对应独立分支与 PR
