# 本地开发代理配置指南

## 问题说明

PandaWiki 使用 Caddy 作为动态反向代理，根据端口/域名将请求路由到不同的知识库。但是：

- ❌ Caddy 在 macOS 上使用 `network_mode: host` 和 Unix socket 有兼容性问题
- ❌ Docker Desktop for Mac 不完全支持 host 网络模式

因此，本地开发需要替代方案。

---

## 架构说明

### 生产环境架构

```
用户请求
  ↓
Caddy (动态反向代理，监听多个端口)
  ↓
根据端口/域名路由到对应知识库
  ├─→ 知识库 A (端口 3000)
  ├─→ 知识库 B (端口 3001)
  └─→ 管理后台 (端口 2443)
```

### 本地开发架构（方案对比）

#### 方案一：使用 Nginx 代理（推荐用于多知识库测试）

```
用户请求
  ↓
Nginx (简单反向代理)
  ├─→ 端口 3000 → 前端应用 (localhost:3010) + 后端 API (localhost:8000)
  └─→ 端口 2443 → 管理后台 (localhost:5173)
```

#### 方案二：直接访问（推荐用于单知识库开发）

```
用户直接访问
  ├─→ 管理后台: http://localhost:5173
  ├─→ 后端 API: http://localhost:8000
  └─→ 前端应用: http://localhost:3010 (需要手动传递 kb_id)
```

---

## 方案一：使用 Nginx 代理

### 优点
- ✅ 更接近生产环境
- ✅ 可以测试多个知识库
- ✅ 自动处理 KB-ID 注入

### 缺点
- ⚠️ 需要额外的 Nginx 容器
- ⚠️ 配置稍复杂

### 使用步骤

#### 1. 启动代理

```bash
# 启动 Nginx 代理
docker compose -f docker-compose.local-proxy.yml up -d

# 查看状态
docker ps | grep local-proxy
```

#### 2. 访问服务

- **管理后台**: http://localhost:2443
- **知识库前端**: http://localhost:3000?kb_id=你的知识库ID

#### 3. 获取知识库 ID

在管理后台中：
1. 进入知识库列表
2. 点击知识库设置
3. 复制知识库 ID

#### 4. 访问知识库

```
http://localhost:3000?kb_id=ec7bff51-754d-439a-b1b2-90876fc9f455
```

---

## 方案二：直接访问（推荐）

### 优点
- ✅ 最简单
- ✅ 无需额外配置
- ✅ 适合单知识库开发

### 缺点
- ⚠️ 需要手动传递 kb_id
- ⚠️ 与生产环境有差异

### 使用步骤

#### 1. 启动服务

```bash
# 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 启动后端
./run-api.sh

# 启动管理后台
./run-admin.sh

# 启动前端应用（可选）
cd web/app && pnpm dev
```

#### 2. 访问管理后台

```
http://localhost:5173
```

登录并创建知识库，获取知识库 ID。

#### 3. 修改前端应用配置

有两种方式让前端应用知道 KB-ID：

**方式 A：通过环境变量（推荐）**

编辑 `web/app/.env.local`：

```env
# 默认知识库 ID（用于本地开发）
NEXT_PUBLIC_DEFAULT_KB_ID=你的知识库ID
```

然后重启前端：

```bash
cd web/app
pnpm dev
```

访问：`http://localhost:3010`

**方式 B：通过 URL 参数**

直接在 URL 中传递：

```
http://localhost:3010?kb_id=你的知识库ID
```

#### 4. 修改前端代码支持默认 KB-ID

如果前端代码不支持默认 KB-ID，可以临时修改：

```typescript
// web/app/src/app/layout.tsx 或相关文件
const kbId = searchParams.kb_id || process.env.NEXT_PUBLIC_DEFAULT_KB_ID || '';
```

---

## 方案三：使用 hosts 文件（高级）

如果你需要测试自定义域名：

### 1. 修改 hosts 文件

```bash
# macOS/Linux
sudo nano /etc/hosts

# 添加：
127.0.0.1 kb1.local
127.0.0.1 kb2.local
```

### 2. 配置 Nginx

修改 `local-dev-proxy.conf`，添加基于域名的路由。

### 3. 访问

```
http://kb1.local:3000
http://kb2.local:3000
```

---

## 推荐的本地开发工作流

### 日常开发（单知识库）

```bash
# 1. 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 启动后端
./run-api.sh

# 3. 启动管理后台
./run-admin.sh

# 4. 在管理后台操作
# 访问 http://localhost:5173
# 创建知识库、添加文档、配置模型等

# 5. 如果需要测试前端应用
cd web/app
# 编辑 .env.local 添加 NEXT_PUBLIC_DEFAULT_KB_ID
pnpm dev
# 访问 http://localhost:3010
```

### 测试多知识库

```bash
# 1. 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 启动代理
docker compose -f docker-compose.local-proxy.yml up -d

# 3. 启动后端和前端
./run-api.sh
./run-admin.sh
cd web/app && pnpm dev

# 4. 访问
# 管理后台: http://localhost:2443
# 知识库 1: http://localhost:3000?kb_id=xxx
# 知识库 2: http://localhost:3000?kb_id=yyy
```

---

## 常见问题

### Q: 为什么前端应用报错 "kb_id is required"？

**A**: 这是正常的！前端应用需要知道要显示哪个知识库。解决方案：

1. 通过 URL 参数传递：`?kb_id=xxx`
2. 配置默认 KB-ID（见方案二）
3. 使用 Nginx 代理（见方案一）

### Q: Caddy 为什么不工作？

**A**: Caddy 在 macOS 的 Docker Desktop 上使用 Unix socket 有兼容性问题。这是 Docker Desktop for Mac 的限制，不是 bug。

### Q: 生产环境会有这个问题吗？

**A**: 不会。生产环境在 Linux 上运行，Caddy 工作正常。这只是本地开发的问题。

### Q: 我应该使用哪个方案？

**A**: 
- 日常开发单个知识库：**方案二**（直接访问）
- 测试多知识库功能：**方案一**（Nginx 代理）
- 测试自定义域名：**方案三**（hosts 文件）

---

## 总结

本地开发环境的核心问题是 Caddy 的兼容性。我们提供了三种解决方案：

1. ✅ **Nginx 代理**：最接近生产环境
2. ✅ **直接访问**：最简单，适合日常开发
3. ✅ **hosts 文件**：用于测试自定义域名

选择适合你的方案即可。大多数情况下，**方案二（直接访问）**就足够了。
