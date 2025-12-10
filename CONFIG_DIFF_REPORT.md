# 配置差异分析报告

## 📊 对比时间
2024-12-11

## 🔍 对比范围
- 本地配置 vs 服务器配置 (root@8.140.221.27)
- 文件：`.env`, `docker-compose.yml`

## ✅ 发现的差异

### 1. .env 文件差异

#### 服务器有但本地缺少的变量：
```bash
NEXT_PUBLIC_WEB_SEARCH_URL=https://llm.webinfra.cloud/c/new?endpoint=Deepseek&model=deepseek-chat&sidebar=hidden&navbar=hidden
```

**影响**：
- 前端无法使用互联网检索功能
- 该变量需要 `NEXT_PUBLIC_` 前缀才能在客户端使用

**解决方案**：✅ 已添加到本地 `.env` 文件

---

### 2. docker-compose.yml app 服务差异

#### 服务器有但本地缺少的环境变量：
```yaml
app:
  environment:
    - TARGET=http://panda-wiki-api:8000
    - STATIC_FILE_TARGET=http://panda-wiki-api:8000
    - NEXT_PUBLIC_WEB_SEARCH_URL=${NEXT_PUBLIC_WEB_SEARCH_URL}
```

**影响**：
- 本地使用 Docker Compose 部署时，前端容器无法正确连接后端 API
- 静态文件请求会失败
- 互联网检索功能不可用

**解决方案**：✅ 已添加到本地 `docker-compose.yml`

---

### 3. 镜像版本差异

#### 服务器使用的镜像：
```yaml
nginx:
  image: panda-wiki-admin/frontend:main  # 本地构建的镜像

app:
  image: panda-wiki-app/frontend:main    # 本地构建的镜像
```

#### 本地使用的镜像：
```yaml
nginx:
  image: chaitin-registry.cn-hangzhou.cr.aliyuncs.com/chaitin/panda-wiki-nginx:v3.34.2

app:
  image: chaitin-registry.cn-hangzhou.cr.aliyuncs.com/chaitin/panda-wiki-app:v3.34.2
```

**说明**：
- 服务器使用本地构建并部署的镜像（通过 deploy 脚本）
- 本地默认使用官方镜像仓库的镜像
- 这是正常的，部署时会自动替换

---

## 📋 完整配置对比

### .env 变量列表

| 变量名 | 本地 | 服务器 | 状态 |
|--------|------|--------|------|
| TIMEZONE | ✅ | ✅ | 一致 |
| SUBNET_PREFIX | ✅ | ✅ | 一致 |
| POSTGRES_PASSWORD | ✅ | ✅ | 一致 |
| NATS_PASSWORD | ✅ | ✅ | 一致 |
| JWT_SECRET | ✅ | ✅ | 一致 |
| S3_SECRET_KEY | ✅ | ✅ | 一致 |
| QDRANT_API_KEY | ✅ | ✅ | 一致 |
| REDIS_PASSWORD | ✅ | ✅ | 一致 |
| ADMIN_PASSWORD | ✅ | ✅ | 一致 |
| ADMIN_PORT | ✅ | ✅ | 一致 |
| NEXT_PUBLIC_WEB_SEARCH_URL | ✅ (新增) | ✅ | 已修复 |

### docker-compose.yml app 服务环境变量

| 变量名 | 本地 | 服务器 | 状态 |
|--------|------|--------|------|
| TARGET | ✅ (新增) | ✅ | 已修复 |
| STATIC_FILE_TARGET | ✅ (新增) | ✅ | 已修复 |
| NEXT_PUBLIC_WEB_SEARCH_URL | ✅ (新增) | ✅ | 已修复 |

---

## 🔧 已应用的修复

### 1. 更新 `.env` 文件
```bash
# 添加互联网检索URL
NEXT_PUBLIC_WEB_SEARCH_URL=https://llm.webinfra.cloud/c/new?endpoint=Deepseek&model=deepseek-chat&sidebar=hidden&navbar=hidden
```

### 2. 更新 `docker-compose.yml`
```yaml
app:
  container_name: panda-wiki-app
  restart: always
  image: chaitin-registry.cn-hangzhou.cr.aliyuncs.com/chaitin/panda-wiki-app:v3.34.2
  environment:
    - TARGET=http://panda-wiki-api:8000
    - STATIC_FILE_TARGET=http://panda-wiki-api:8000
    - NEXT_PUBLIC_WEB_SEARCH_URL=${NEXT_PUBLIC_WEB_SEARCH_URL}
  networks:
    panda-wiki:
      ipv4_address: "${SUBNET_PREFIX:-169.254.15}.112"
```

---

## ✅ 验证清单

- [x] 对比 `.env` 文件
- [x] 对比 `docker-compose.yml`
- [x] 识别缺失的环境变量
- [x] 更新本地配置文件
- [x] 验证配置一致性

---

## 📝 注意事项

### 环境变量优先级

在 Docker Compose 中，环境变量的优先级为：
1. `docker-compose.yml` 中的 `environment` 配置（最高优先级）
2. `.env` 文件中的变量
3. 容器内的默认值

### Next.js 环境变量

- `NEXT_PUBLIC_*` 前缀的变量会暴露到客户端
- 其他变量只在服务端可用
- Docker 容器中需要在启动时传入环境变量

### 本地开发 vs Docker 部署

**本地开发**（使用 `start-local-dev.sh`）：
- 前端使用 `web/app/.env.dev` 或 `.env.local`
- 直接运行 Next.js dev server
- 不使用 Docker Compose 的 app 服务

**Docker 部署**（使用 `docker-compose.yml`）：
- 前端使用 Docker 容器
- 环境变量通过 `docker-compose.yml` 传入
- 需要配置 `TARGET` 等变量

---

## 🎯 结论

所有配置差异已识别并修复。本地配置现在与服务器配置保持一致，确保：

1. ✅ Docker Compose 部署时前端可以正确连接后端
2. ✅ 互联网检索功能可用
3. ✅ 静态文件请求正常
4. ✅ 所有环境变量完整

---

## 📚 相关文档

- [CONFIG_GUIDE.md](CONFIG_GUIDE.md) - 配置文件使用指南
- [CONFIG_QUICK_REF.md](CONFIG_QUICK_REF.md) - 配置快速参考
- [docker-compose.yml](docker-compose.yml) - Docker Compose 配置
