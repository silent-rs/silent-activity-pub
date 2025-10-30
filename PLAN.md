# 项目计划（PLAN）· silent-activity-pub

> 本计划文档用于明确阶段目标、里程碑、优先级与技术选型，并指导 `TODO.md` 的任务拆解与分支管理。

---

## 1. 项目总体目标

- 构建符合 W3C ActivityPub/ActivityStreams 的高性能、可扩展协议实现
- 作为 Silent 生态的联邦中枢，提供跨实例/跨域/跨协议的社交与协作能力
- 提供标准端点、可靠分发、签名认证、对象存储与可观测性
- 统一 ID/时间规范：`scru128` + `chrono::Local::now().naive_local()`

---

## 2. 版本里程碑（Phase VII）

### Phase VII-A · 最小可用联邦节点（MVP）
- 交付：健康检查、WebFinger、Actor Profile、基础收/发箱
- 验收：
  - WebFinger 返回符合 RFC7033
  - `Accept: application/activity+json` 返回 Actor Profile
  - inbox/outbox 基础活动收发闭环
- 状态：规划中

#### 需求拆解（接口清单）

- GET `/health`
  - 200 OK，`application/json`：`{"status":"ok","time":"<local>"}`
- GET `/.well-known/webfinger?resource=acct:<name>@<host>`
  - 200 OK，`application/jrd+json`
  - `links[].rel=self`，`type=application/activity+json` 指向 Actor URL
- GET `/users/<name>`（Actor Profile）
  - 200 OK，`application/activity+json`
  - 至少包含：`@context`、`id`、`type=Person`、`preferredUsername`、`inbox`、`outbox`
- GET `/users/<name>/outbox`
  - 200 OK，`application/activity+json`，`OrderedCollection` 空集合即可
- POST `/users/<name>/inbox` 与 POST `/inbox`（shared inbox）
  - 202 Accepted；不做签名校验，仅作为占位

#### 非功能性约束

- ID 生成：全局使用 `scru128`
- 时间：`chrono::Local::now().naive_local()`
- 日志：结构化日志，默认 `info`，可通过 `RUST_LOG` 调整
- 路由：使用 Silent 路由装配，根路由统一注入配置（如 `AP_BASE_URL`）

#### 验收清单（可执行场景）

- 通过 curl/jq 验证 health、webfinger、actor、inbox/outbox 行为
- HEAD 命中时对 GET 进行回退（如无专用 HEAD 处理）
- 统一返回正确的 `Content-Type`

### Phase VII-B · 签名与可靠投递
- 交付：HTTP Signatures、投递队列、重试与去重、基础指标
- 验收：
  - 按目标实例完成签名、回源校验与指数退避
  - 幂等与去重生效（基于活动 ID）
  - 暴露请求成功率/延迟/重试次数等指标
- 状态：规划中

### Phase VII-C · 对象与媒体存储
- 交付：Object Store 抽象、附件存储、silent-nas 集成、GC 策略
- 验收：
  - 对象与附件可独立生命周期管理
  - 存储后端可替换（本地/分布式）
- 状态：规划中

### Phase VII-D · CRDT 与可观测性
- 交付：与 silent-crdt 集成的冲突合并、日志/指标/追踪完善、运维工具
- 验收：
  - 对象冲突可通过 CRDT 策略达成最终一致
  - tracing、metrics、logs 可用于定位联邦链路问题
- 状态：规划中

---

## 3. 功能优先级排序

- P0（当前迭代优先）：
  - WebFinger、Actor Profile、健康检查
  - inbox/outbox 基础闭环（未签名）
- P1：
  - HTTP Signatures、分发队列与重试、幂等与去重
  - 指标与基本追踪
- P2：
  - Object Store 抽象与 silent-nas 集成
  - CRDT 合并、可观测性完善、运维工具

---

## 4. 技术选型说明

- 语言/框架：Rust + Silent
- ID：`scru128`；时间：`chrono::Local::now().naive_local()`
- 网络：HTTP(S)，遵循 ActivityPub/ActivityStreams 标准
- 签名：HTTP Signatures（优先），后续可扩展 LD-Signatures
- 存储：本地/分布式可替换，通过 trait + adapter 解耦
- 可观测性：tracing + metrics（Prometheus 友好）

---

## 5. 时间节点规划（滚动更新）

- 2025-11：完成 Phase VII-A 骨架与端到端联调（本地）
- 2025-12：完成基础签名与可靠投递（Phase VII-B）
- 2026-01：对象/媒体存储与 silent-nas 打通（Phase VII-C）
- 2026-02：CRDT 与可观测性完善（Phase VII-D）

注：时间为当前规划目标，实际以里程碑交付为准滚动调整。

---

## 6. 依赖与前置条件

- 规范：ActivityPub、ActivityStreams 2.0、RFC7033（WebFinger）
- 生态依赖：silent-nas、silent-mqtt、silent-grpc、silent-crdt（按阶段接入）
- 工具链：Rust stable、cargo、（可选）OpenSSL/LibreSSL、jq

---

## 7. 与 TODO 的对应关系

- 本文档给出“是什么/为什么/到哪里”；`TODO.md` 负责“如何做/下一步是什么”
- 每个里程碑拆分为可验证的 TODO 项，单分支开发，PR 合并
