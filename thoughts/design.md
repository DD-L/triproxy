# 跨平台内网穿透代理服务 - 技术规格

## 架构拓扑
A(内网Agent) <--TCP+RSA+AES--> B(公网Relay) <--TCP+RSA+AES--> C(客户端Controller)
- **B 双端口**: 一端口接 A（agent），一端口接 C（client），角色隔离、防火墙易配置
- **租户**: 当前部署为 1:1:1，协议及 B 侧数据结构全面使用 `agent_id` 索引，支持多租户扩展（多个 A 实例）；`allowed_agents` 列表可配置多个 agent 指纹

## 核心安全机制
- **主控认证**: RSA-2048 双向验证，仅在主控连接建立时执行一次
- **密钥协商**: 主控连接协商 AES 密钥用于控制通道加密
- **数据连接认证**: 轻量令牌验证（令牌通过已加密主控连接分发），无需重复 RSA
- **本地凭证**: 可选预共享 `AUTH_KEY`，仅存于本机配置文件
- **公网全加密**: 所有经公网传输的数据均 AES 加密 + 随机 IV，明文不过网

## 平台支持
- **A/B/C**: 全平台 Windows/Linux 兼容
- **语言**: 纯 Python3（asyncio + cryptography + Web/WebSocket）；若无法满足再考虑混合（Python3 优先 → Node.js 备选 → C++ 最后手段）
- **运维脚本**: sh/ps1/bat/py 均可，支持跨平台

## 连接模型（A-B / C-B 对称）
- **主控连接**: A、C 各与 B 保持一条长连接（心跳/控制指令），完整 RSA 握手 + AES 协商；断线重连需重新认证，旧令牌全部作废
- **数据连接池**: B 通过 POOL_ALLOC 集中控制分配，A/C 按指令创建数据连接（动态伸缩：并发高时扩容，低时缩容，不活跃时可清零；无软件层硬上限，仅受硬件资源约束）
- **令牌机制**（三层，均一次性随机生成、绝不复用）:
  - `pool_token`: 每条池连接唯一，标识连接归属，通过主控连接下发
  - `session_id`: 每次会话唯一，B 按此配对 A 侧和 C 侧连接
  - `data_key`: 每次会话唯一 AES 密钥 + 随机 IV，A-C 端到端加密，B 仅桥接密文字节
- **会话流程**: C 发起请求 → B 生成 session_id + data_key 通过主控连接通知 A/C → B 从双方池中各取一条连接配对 → 会话结束释放回池（旧 session_id + data_key 作废）
- **心跳**: 主控连接 + 池中空闲连接均心跳保活

## 高可用设计
- **心跳**: 所有长连接（主控 + 池连接）统一心跳保活（interval=100s, dead_timeout=300s）
- **断线恢复**: A/C 主动重连 B，重连后重新 RSA 认证，重建连接池
- **进程守护**: A/B/C 任意服务崩溃/非正常结束，自动重启拉起（推荐自实现 watchdog）

## 三模式代理系统（可同时启用，互不影响）

### 模式1: 定向流量代理（多实例支持）
- **功能**: C 本地端口 → A 环境特定目标服务
- **配置示例**:
  - `127.0.0.1:3005` <-> `http://target1.cn:80`
  - `127.0.0.1:3006` <-> `http://target2.cn:80`
- **特性**: 支持动态增删改，多定向规则并行运行
- **示例**: C 主机上 AI Agent 配置 BaseURL: `http://127.0.0.1:3005` 等价于在 A 主机配置 `http://target1.cn:80`

### 模式2: 通用 HTTP/Socks5 代理
- **功能**: C 本地端口作为标准代理，全流量转发至 A 环境
- **配置**: `127.0.0.1:3000`
- **效果**: 浏览器设置代理后即相当于在 A 环境直接上网

### 模式3: 远程 Shell/Web Terminal（多会话支持）
- **实现**: Web Terminal，前端 xterm.js；C 本地 Web 提供浏览器访问 A 的 Shell
- **配置**: `http://127.0.0.1:3001`（与控制面板同端口）
- **特性**: 动态多会话、完整键盘映射（Ctrl+C/Z、方向键等）、会话 Kill/关闭、自动适配 A 端 OS（Linux pty / Windows ConPTY）

## A 端 Web 控制台
- **绑定**: `http://127.0.0.1:3002`（端口可配置）
- **功能**: 管理 A-B 连接/断线、查看状态
- **独立密码**: 与 AUTH_KEY 无关；存储 `SHA256(password)`，不存明文
- **HTTP 安全登录**（Challenge-Response）: 服务端返回一次性 `nonce` → 浏览器 JS 计算 `SHA256(SHA256(password) + nonce)` → 提交 hash 验证，密码不过网
- **改密**: 本地 Web 或 C 远程均可修改，改后立即生效；C 远程改密走加密控制通道
- **密码提交**: 新密码经客户端 JS `SHA256(new_password)` 后传输，服务端存储 hash

## C 端控制面板
- **Web**: 与 Shell 服务共用 `http://127.0.0.1:3001`，同一应用路由：`/dashboard` 控制面板、`/terminal` Shell
- **实时管理**: 各模式启停、定向规则动态增删改、Shell 会话查看/关闭
- **配置持久化**: 动态变更同时写回配置文件

## 配置项

### A (Agent)
```yaml
agent_id: "default"       # 预留多租户扩展
relay_host: "b.example.com"
relay_port_agent: 8080    # B 的 agent 端口
rsa_private_key: "/path/to/agent_key.pem"
rsa_public_key: "/path/to/relay_cert.pem"
auth_key: "optional_pre_shared_secret"
web_console_port: 3002    # A 端 Web 控制台
web_console_password_hash: "<SHA256>"  # 首次启动时引导设置
heartbeat_interval: 100
auto_restart: true
log_level: "info"
```

### B (Relay)
```yaml
bind_port_agent: 8080   # 接 A
bind_port_client: 8081  # 接 C
rsa_private_key: "/path/to/relay_key.pem"
allowed_agents: ["agent_cert_fingerprint1"]
allowed_clients: ["client_cert_fingerprint1"]   # RSA-2048 双向验证，C 也需被 B 验证
auth_key: "optional_pre_shared_secret"
heartbeat_timeout: 100
dead_timeout: 300           # 3 倍心跳周期后判定连接死亡
auto_restart: true
log_level: "info"
```

### C (Controller)
```yaml
relay_host: "b.example.com"
relay_port_client: 8081  # B 的 client 端口
rsa_private_key: "/path/to/client_key.pem"
rsa_public_key: "/path/to/relay_cert.pem"
auth_key: "optional_pre_shared_secret"

services:
  directed:
    - local_port: 3005
      target_url: "http://target1.cn:80"
      enabled: true
  general:
    local_port: 3000
    enabled: true
  shell:
    local_port: 3001
    enabled: true
    
heartbeat_interval: 100
auto_restart: true
log_level: "info"
```

## 技术实现要求
- **高并发**: 全异步（asyncio/uvloop）；其它可选 Node: cluster+worker_threads, C++: asio/io_uring
- **加密**: cryptography（RSA+AES）
- **进程守护**: 自实现 watchdog 优先，备选 systemd/Windows Service/PM2
- **Shell**: 前端 xterm.js；A 端 Linux(pty/fork)、Windows(ConPTY/CreatePseudoConsole)
- **代码质量**: 工程最佳实践，可复用成熟库/框架，甚至可配置开源软件
- **离线可用**: 所有前端第三方库（xterm.js、SHA256 等）均本地打包，禁止 CDN 引用，确保内网/离线环境可用

## 调试支持
- **单机调试**: agent/relay/client 可在同一主机运行进行功能调试
- **日志分级**: 支持 debug/info/warn/error 多级日志输出

## 交付物
1. `agent/` - A 端程序（跨平台）
2. `relay/` - B 端程序（跨平台）
3. `client/` - C 端程序 + Web 控制面板（跨平台）
4. `certs/` - RSA 密钥生成脚本与说明
5. `deploy/` - 各平台部署脚本（systemd service, Windows Service, PM2 config）
6. `README.md` - 架构说明、配置详解、故障排查
