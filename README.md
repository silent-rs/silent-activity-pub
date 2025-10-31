# silent-activity-pub · Silent‑Odyssey Phase VII

> 面向去中心化未来的 ActivityPub 协议栈，实现 Silent 生态的联邦社交与跨域互联。

`silent-activity-pub` 旨在构建一套符合 W3C ActivityPub/ActivityStreams 规范的高性能、可扩展协议实现，为 Silent 生态（Rust · Silent Web 框架）提供联邦通信、对象流转、加密签名与消息路由等能力。

- 语言与框架：Rust + [Silent](https://github.com/silent-rs/silent)
- 目标：作为 Silent 生态的联邦中枢，支撑跨实例、跨域、跨协议的社交与协作
- 阶段标识：Silent‑Odyssey 第七阶段（Phase VII）

---

## 环境要求

- Rust：稳定版（建议使用 rustup 安装最新 stable）
- 操作系统：Linux / macOS / Windows（需可用的构建工具链）
- 可选依赖：
  - OpenSSL/LibreSSL（如需启用 TLS 或签名相关的本地依赖）
  - `jq`（示例命令输出美化）

> 若你的环境较“干净”，建议先执行 `rustup update` 以确保工具链最新。

## 功能概述

| 模块 | 职责 | 关键能力 | 当前状态 |
| --- | --- | --- | --- |
| Federation Server | 联邦节点 HTTP 接入与路由 | ActivityPub 端点、签名校验、收发队列 | 规划中 |
| Activity Stream | ActivityStreams 2.0 对象与活动 | Actor/Object/Activity 模型、收件箱/发件箱 | 规划中 |
| Signature & Auth | 签名与认证 | HTTP Signatures, LD-Signatures, CSR/Key 管理 | 规划中 |
| Object Store | 对象与附件存储 | 本地/远程存储、版本与引用、GC | 规划中 |
| Delivery & Queue | 分发与重试 | Backoff、幂等、去重、批量投递 | 规划中 |
| Federation Discovery | 跨域发现 | WebFinger、NodeInfo、Host‑Meta | 规划中 |
| CRDT Sync | 协同与最终一致 | 与 silent-crdt 集成，支持离线合并 | 规划中 |
| Observability | 可观测性 | 结构化日志、指标、追踪 | 规划中 |

> ID 规则：系统全局使用 `scru128` 生成高可用 ID，避免 UUID 冲突；时间戳默认使用 `chrono::Local::now().naive_local()`。

---

## 架构设计

```mermaid
flowchart LR
  subgraph Client[Clients]
    A1[Web / Mobile]
    A2[Server-to-Server]
  end

  subgraph Edge[Federation Server]
    G1[HTTP API\nActivityPub Endpoints]
    G2[Signature & Auth\nHTTP-Signatures, LD-Signatures]
    G3[Delivery & Queue\nBackoff / Retries]
  end

  subgraph Core[Core Services]
    C1[Activity Stream\nActor / Object / Activity]
    C2[Object Store\nMedia / Attachments]
    C3[Discovery\nWebFinger / NodeInfo]
    C4[CRDT Sync\nsilent-crdt]
  end

  subgraph Infra[Silent Ecosystem]
    I1[silent-nas\n分布式存储]
    I2[silent-mqtt\n消息分发]
    I3[silent-grpc\n跨服务 RPC]
  end

  Client -->|HTTP(S)| G1
  G1 --> G2
  G1 --> G3
  G1 --> C1
  C1 --> C2
  C1 --> C3
  C1 <---> C4

  C2 --> I1
  G3 --> I2
  Core --> I3
```

---

## 快速启动

> 提示：以下命令为项目标准启动方式；若当前仓库尚未完成对应二进制实现，运行可能失败，建议作为集成参考使用。

- 运行服务（开发模式）

```bash
# 环境准备
rustup default stable
cargo --version

# 依赖检查与构建（第一次构建会较慢）
cargo check
cargo clippy --no-deps -D warnings

# 启动（开发模式）
RUST_LOG=info cargo run --bin silent-activity-pub
```

- 健康检查（示例端点）

```bash
# 假设服务监听在 127.0.0.1:8080
curl --max-time 5 -s http://127.0.0.1:8080/health | jq
# 返回示例：
# {
#   "status": "ok",
#   "time": "2025-10-30 13:45:12",
#   "request_id": "0u5r85s0b3l7h4k9m1c2e6f7g8d9j0n1"
# }
```

- WebFinger 查询（联邦发现示例）

```bash
curl --max-time 8 -s \
  "http://127.0.0.1:8080/.well-known/webfinger?resource=acct:alice@localhost" | jq
```

- Host-Meta（联邦发现）

```bash
curl --max-time 5 -i http://127.0.0.1:8080/.well-known/host-meta
```

- NodeInfo（节点信息）

```bash
curl --max-time 5 -s http://127.0.0.1:8080/.well-known/nodeinfo | jq
curl --max-time 5 -s http://127.0.0.1:8080/nodeinfo/2.1 | jq
```

- Actor Profile 获取（ActivityStreams 示例）

```bash
curl --max-time 8 -H "Accept: application/activity+json" \
  http://127.0.0.1:8080/users/alice | jq
```

- 发送 Activity 到 inbox（签名示例略）

```bash
curl --max-time 10 -X POST \
  -H "Content-Type: application/activity+json" \
  -d @- http://127.0.0.1:8080/inbox <<'JSON'
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://localhost/activities/like-1",
  "type": "Like",
  "actor": "https://localhost/users/alice",
  "object": "https://remote.example.com/notes/123"
}
JSON
```

- 接口文档（Swagger UI）

```bash
# 生成自业务路由的 OpenAPI 文档并挂载在 /docs
# 启动后访问：http://127.0.0.1:8080/docs
open http://127.0.0.1:8080/docs || true
```

---

## 签名与投递（Phase VII-B 进展）

- 入站验签
  - 支持 HMAC-SHA256 与 hs2019（RSA/Ed25519），优先使用共享密钥 HMAC；否则自动根据 key 文档类型选择 RSA 或 Ed25519
  - 完整解析 `Signature` 头：`keyId`、`algorithm`、`headers`、`signature`、`created`、`expires`
  - 签名串依据 `headers` 顺序构造，支持伪头 `(request-target)`、`(created)`、`(expires)`
  - 强校验时间：允许的时间偏移由 `AP_SIGN_MAX_SKEW_SEC` 控制（对 `created`/`expires` 生效）
  - 错误响应统一：当验签失败或日期无效时，返回 JSON 错误体，并设置 `WWW-Authenticate: Signature ...`

- 出站签名与投递
  - 签名算法动态选择：由 `AP_SIGN_ALG=hmac|rsa|ed25519` 与 `AP_SIGN_PRIV_KEY_PATH=<PEM>` 控制；缺省回退到 HMAC
  - 每次投递自动附带 `Idempotency-Key`（正文 SHA256 的 Base64）
  - 支持 http/https 通道；指数退避重试由 `AP_BACKOFF_*` 参数控制
  - 支持“内存/持久化”出站队列：默认内存队列（tokio mpsc），可切换 sled 后端（简易持久化）

- 主要配置项（TOML）
  - 签名：`sign_enable`、`sign_alg`、`sign_priv_key_path`、`sign_key_id`、`sign_shared_secret`、`sign_max_skew_sec`
  - 退避：`backoff_base_ms`、`backoff_max_ms`、`backoff_max_retries`
  - HTTP：`http_timeout_ms`
  - 队列：`queue_backend`（memory|sled）、`queue_cap`、`queue_workers`、`queue_poll_ms`
  - 说明：可用环境变量覆盖 TOML；强烈建议以 TOML 为主，环境变量仅做临时覆盖（如 CI/容器部署）

- 错误响应规范
  - 401 UNAUTHORIZED：
    - 头：`WWW-Authenticate: Signature realm="activitypub", error="<code>", error_description="<desc>"`
    - 体：`{"error":"<code>","error_description":"<desc>"}`
    - 常见 code：`invalid_date`、`invalid_signature`
  - 400 BAD REQUEST：Digest 校验失败时返回 `invalid_digest`


## 配置与运行

- 端口与地址：默认监听 `0.0.0.0:8080`（可在配置中调整）
- 日志等级：通过环境变量 `RUST_LOG` 控制，推荐 `info`/`debug`
- 时间与 ID：
  - ID 一律使用 `scru128` 生成，高可用且可排序
  - 时间戳使用 `chrono::Local::now().naive_local()`，统一本地时间
- 配置优先级：TOML 配置文件 > 环境变量覆盖 > 内置默认值
- 配置文件路径：默认 `config/app.toml`，可通过环境变量 `AP_CONFIG` 指定；提供示例 `config/app.example.toml`

### 配置文件示例（config/app.toml）

```toml
# 服务
base_url = "http://127.0.0.1:8080"
listen_addr = "0.0.0.0:8080"

# 签名
sign_enable = false
sign_key_id = "local#main"
sign_shared_secret = ""
sign_max_skew_sec = 300
sign_alg = "hmac"        # hmac|rsa|ed25519
sign_priv_key_path = ""   # 当 rsa/ed25519 时必需

# 退避重试
backoff_base_ms = 500
backoff_max_ms = 10000
backoff_max_retries = 3

# 去重
dedup_backend = "memory"  # memory|sled
sled_path = "./data/dedup.sled"

# 出站 HTTP
http_timeout_ms = 10000
delivery_http = false      # true 则实际发送 HTTP/HTTPS，否则仅日志

# 出站队列
queue_backend = "memory"   # memory|sled
queue_cap = 1000           # 仅 memory 有效
queue_workers = 2          # 仅 memory 有效
queue_poll_ms = 500        # 仅 sled 有效
```

> 可以使用环境变量覆盖 TOML 中的配置（如 `AP_BASE_URL`、`AP_LISTEN` 等）。推荐以 TOML 为主。

### 快速开始（使用示例配置）

```bash
# 复制示例配置并修改
cp config/app.example.toml config/app.toml

# 启动（建议设置日志等级）
RUST_LOG=info cargo run --bin silent-activity-pub
```

### MVP 快速验证脚本

提供 `scripts/verify_mvp.sh` 进行端点与 HEAD 回退验证：

```bash
# 使用默认 BASE_URL 与用户名
bash scripts/verify_mvp.sh

# 或指定 BASE_URL 与用户名（或用环境变量 BASE_URL/NAME 覆盖）
bash scripts/verify_mvp.sh http://127.0.0.1:8080 alice

# 脚本参数/行为
# - 所有请求使用 --max-time（默认 8s，可用 MAX_TIME 覆盖）
# - 校验 health、.well-known/*、nodeinfo/2.1、users/<name>、users/<name>/outbox
# - 对 GET 验证 Content-Type，对相应端点执行 HEAD=200 回退检查
```

> 安全提示：私钥与签名材料应保存在专用密钥管理中（如 KMS 或受限文件权限），严禁提交到仓库。

---
## 去重与幂等

- 入站去重（Inbox）：
  - 机制：基于 `activity.id` 的去重，返回 202 并加头 `X-Deduplicated: true`
  - 后端选择：
    - `AP_DEDUP_BACKEND=memory` 使用内存 LRU+TTL（默认，TTL=10分钟）
    - `AP_DEDUP_BACKEND=sled` 使用 sled 持久化（建议设置 `AP_SLED_PATH`）
  - 相关文件：`src/utils/dedup.rs`

- 出站幂等：
  - 每次投递添加 `Idempotency-Key`（正文 SHA256 的 Base64），便于对端去重

---

## 开发命令速查

```bash
# 代码检查
cargo check
cargo clippy --no-deps -D warnings

# 格式化
cargo fmt --all

# 运行
RUST_LOG=info cargo run --bin silent-activity-pub

# 测试（若有）
cargo test -- --nocapture
```

## 模块结构（建议）

```text
src/
├─ main.rs                # 入口：Silent 启动与路由装配
├─ config/                # 配置与环境管理（本地时间、密钥、端口）
├─ federation/            # 联邦协议：端点、入站/出站、重试
│  ├─ discovery.rs        # WebFinger / NodeInfo / Host-Meta
│  ├─ delivery.rs         # 投递队列与退避
│  └─ routes.rs           # /.well-known/* / inbox / outbox
├─ activity/              # ActivityStreams 模型与服务
│  ├─ models.rs           # Actor/Object/Activity/Collection
│  ├─ inbox.rs            # 收件箱处理
│  └─ outbox.rs           # 发件箱处理
├─ auth/                  # 签名与认证
│  ├─ http_sign.rs        # HTTP Signatures
│  └─ ld_sign.rs          # Linked Data Signatures（扩展）
├─ store/                 # 对象与附件存储
│  ├─ object.rs           # Object Store 抽象
│  └─ media.rs            # 媒体管道（与 silent-nas 集成）
├─ types/                 # 通用类型：ID(scru128)、时间、错误
├─ observability/         # 日志/指标/追踪
└─ utils/                 # 辅助工具：序列化、URL、验证
```

> 代码检查：优先使用 `cargo check` / `cargo clippy`；前端（若有）使用 `yarn build`。

---

## 文档与约定

- 文档约定：除 `README.md` 外的文档统一放置于 `docs/` 目录
- 路线与任务：
  - 在 `PLAN.md` 维护阶段目标、优先级与技术选型
  - 在 `TODO.md` 细化当前迭代任务，遵循单一职责与可验证标准
- 分支策略：每个 TODO 独立分支，命名 `feature/<功能>` 或 `fix/<问题>`，从最新 `main`/`develop` 创建
- 提交规范：遵循 Conventional Commits，例如：

```text
feat(api): 添加联邦端点
fix(core): 修复收件箱幂等性问题
refactor(db): 优化对象存储抽象
```

> PR 合并前请确保本地通过 `cargo check` / `cargo clippy`，且需求整理文档已覆盖当次改动。

## 与 Silent 其他子项目的集成

- silent-nas：
  - 用作对象与媒体的后端存储层，提供本地/分布式存储抽象
  - 与 `store::media` 模块对接，支持零拷贝/分片上传/版本化
- silent-mqtt：
  - 作为联邦分发与站内通知的消息总线
  - 与 `federation::delivery` 集成，实现重试、批量与去重
- silent-crdt：
  - 用于离线编辑与最终一致性合并
  - 与 `activity` 层结合，在对象冲突时进行 CRDT 合并
- silent-grpc：
  - 作为跨服务通信与内部 API 的高速通道
  - 与 `core` 服务交互，暴露治理与管理接口

> 以上集成遵循模块解耦策略：通过 trait 与 adapter 绑定依赖，便于在不同部署形态下替换实现。

---

## 参考规范与实现

- W3C ActivityPub：https://www.w3.org/TR/activitypub/
- W3C ActivityStreams 2.0：https://www.w3.org/TR/activitystreams-core/
- WebFinger：https://www.rfc-editor.org/rfc/rfc7033
- 参考实现：Mastodon、Misskey、Akkoma 等

> 设计时优先与主流实现互操作，并保持扩展点（签名、路由、对象模型）可替换。

---

## 指标与可观测性

- 指标端点：`GET /metrics`（Prometheus 文本格式）
- 指标维度：
  - `delivery_total{scheme, result, code}`：出站投递计数（scheme: http/https；result: ok/error；code: HTTP 状态码，异常为 0）
  - `delivery_duration_ms{scheme}`：出站投递耗时直方图（单位 ms）
  - `inbound_total{endpoint, result}`：入站处理计数（endpoint: inbox；result: ok/unauthorized/duplicate）
  - `dedup_total{backend, result}`：去重命中统计（backend: memory/sled；result: hit/miss）
  - `delivery_queue_total{backend, event}`：队列事件计数（backend: memory/sled；event: enqueued/dequeued/dropped）
  - `delivery_queue_depth`：当前队列深度（Gauge）

---

## 实际部署建议

- 进程与用户
  - 使用非 root 用户运行（例如专用用户 `ap`），限制只读配置与私钥权限（`chmod 600`）。
  - 日志通过 `RUST_LOG` 控制，生产建议 `info` 或更细粒度模块化设置。

- 目录与持久化
  - 配置文件：`config/app.toml`（或通过 `AP_CONFIG` 指定绝对路径）。
  - 数据目录：`sled_path` 指向持久化目录（例如 `/var/lib/silent-activity-pub/dedup.sled`）。
  - 队列后端：如使用 `queue_backend = "sled"`，建议将同一 `sled_path` 放到持久化卷中。

- 反向代理与 TLS
  - 建议使用 Nginx/Caddy/Traefik 作为 TLS 终结，在其后运行本服务（`listen_addr` 为内网绑定）。
  - 反代应透传 `Host` 与 `X-Forwarded-*` 头，并确保 `base_url` 与外部访问一致。

- Systemd 示例（/etc/systemd/system/silent-activity-pub.service）
  - 以非 root 用户/组运行，并指定工作目录与配置路径。

```ini
[Unit]
Description=Silent ActivityPub Node
After=network-online.target
Wants=network-online.target

[Service]
User=ap
Group=ap
WorkingDirectory=/opt/silent-activity-pub
Environment=RUST_LOG=info
Environment=AP_CONFIG=/opt/silent-activity-pub/config/app.toml
ExecStart=/usr/bin/env cargo run --release --bin silent-activity-pub
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

- Docker 运行（示例）

```Dockerfile
FROM rust:1 as build
WORKDIR /work
COPY . .
RUN cargo build --release --bin silent-activity-pub

FROM debian:stable-slim
RUN useradd -m -u 10001 ap
WORKDIR /app
COPY --from=build /work/target/release/silent-activity-pub /usr/local/bin/
COPY config/app.example.toml /app/config/app.toml
USER ap
ENV RUST_LOG=info AP_CONFIG=/app/config/app.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/silent-activity-pub"]
```

运行命令（挂载自定义配置/密钥）：

```bash
docker run --rm -p 8080:8080 \
  -v $(pwd)/config/app.toml:/app/config/app.toml:ro \
  -v $(pwd)/keys:/app/keys:ro \
  -e RUST_LOG=info \
  ghcr.io/your-org/silent-activity-pub:latest
```

- 健康检查与监控
  - 健康检查：`GET /health`，可用于负载均衡器探活。
  - 指标：`GET /metrics`（Prometheus），建议采集并设置告警（如 5xx 比例、投递错误率）。

- 安全与密钥
  - 私钥文件建议使用 PKCS#8 格式，放置在只读目录并限制权限；配置文件中仅引用路径，不直接嵌入私钥内容。
  - 定期轮换密钥，必要时通过配置变更并重启服务应用新密钥。

- 配置变更与发布
  - 当前版本不支持热重载；修改 `config/app.toml` 后需重启服务。
  - 生产环境建议使用蓝绿/滚动发布，确保 `/health` 通过后再切换流量。

### 出站队列与 Outbox 行为

- `POST /users/<name>/outbox` 行为为“入队”：
  - 请求体：`{"inbox":"<url>","activity":{...}}`
  - 正常：返回 `{ "status": "queued" }`
  - 队列已满：返回 503 + `{ "error": "queue_full" }`

## 计划（Plan）

| 阶段 | 目标 | 关键交付 | 状态 |
| --- | --- | --- | --- |
| Phase VII-A | 最小可用联邦节点（MVP） | 健康检查、WebFinger、Actor Profile、基础收/发箱 | 规划中 |
| Phase VII-B | 签名与可靠投递 | HTTP Signatures、投递队列、重试与去重、指标 | 规划中 |
| Phase VII-C | 对象与媒体存储 | Object Store、silent-nas 集成、GC 策略 | 规划中 |
| Phase VII-D | CRDT 与可观测性 | CRDT 合并、追踪/日志/指标、运维工具 | 规划中 |

> 计划与 TODO 管理：请在 `PLAN.md` 与 `TODO.md` 中持续维护阶段目标、依赖与验收标准；每个 TODO 建议独立分支 `feature/<name>` 开发并通过 PR 合并。

---

## 贡献指南

- 提交 PR 流程
  - 从最新 `main`/`develop` 创建分支：`feature/<功能名>` 或 `fix/<问题>`
  - 开发前先核对/更新需求文档；提交前运行 `cargo check`/`cargo clippy`
  - PR 标题遵循 Conventional Commits（示例：`feat(api): 添加联邦端点`）
  - 通过代码审查后合并；合并后删除功能分支
- 参与协议设计
  - 参考 W3C ActivityPub / ActivityStreams 规范与实作实践（Mastodon、Misskey 等）
  - 在讨论区提交设计提案（ADR），对对象模型、端点、安全与扩展进行评审
  - 坚持“ID 使用 scru128、本地时间使用 chrono::Local”的一致性规则

---

## License

本项目采用 Apache License 2.0 开源协议。

```text
Copyright (c) Silent Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

如需我基于此 README 初始化 `PLAN.md` 与 `TODO.md` 并完善最小可运行骨架，请告诉我，我可以在独立分支上为你搭好脚手架与示例端点。
