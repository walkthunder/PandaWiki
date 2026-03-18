# PandaWiki 本地开发环境快速启动指南

## 🚀 一键启动（推荐）

如果你是第一次使用，请按以下步骤操作：

### 1. 环境初始化（仅首次需要）

```bash
# 初始化开发环境（安装依赖、创建目录、拉取镜像）
./init-local-dev.sh
```

### 2. 启动所有服务

```bash
# 一键启动所有服务
./start-local-dev.sh
```

### 3. 验证服务状态

```bash
# 检查所有服务状态
./check-local-dev.sh

# 运行功能测试
./test-local-dev.sh
```

### 4. 访问应用

- **Web App**: http://localhost:3010
- **API 文档**: http://localhost:8000/swagger/index.html
- **MinIO 控制台**: http://localhost:9001
- **Qdrant 控制台**: http://localhost:6333/dashboard

**默认登录信息**:
- 用户名: `admin`
- 密码: `admin123`

---

## 📋 服务列表

| 服务 | 端口 | 说明 | 健康检查 |
|------|------|------|----------|
| Web App | 3010 | 前端应用 | http://localhost:3010 |
| API 服务 | 8000 | 后端 API | http://localhost:8000/api/v1/health |
| PostgreSQL | 5432 | 主数据库 | `docker exec panda-wiki-postgres pg_isready` |
| Redis | 6379 | 缓存 | `docker exec panda-wiki-redis redis-cli ping` |
| MinIO | 9000 | 对象存储 | http://localhost:9000/minio/health/live |
| MinIO Console | 9001 | 存储管理界面 | http://localhost:9001 |
| NATS | 4222 | 消息队列 | - |
| Qdrant | 6333 | 向量数据库 | http://localhost:6333/health |
| Raglite | 8080 | RAG 服务 | http://localhost:8080/health |
| Caddy | - | 反向代理 | - |
| Crawler | - | 文档爬虫 | - |

---

## 🔧 常用命令

### 服务管理
```bash
# 启动所有服务
./start-local-dev.sh

# 停止所有服务
./stop-local-dev.sh

# 检查服务状态
./check-local-dev.sh

# 运行功能测试
./test-local-dev.sh

# 重启所有服务
./stop-local-dev.sh && ./start-local-dev.sh
```

### 日志查看
```bash
# 查看 API 日志
tail -f logs/api.log

# 查看 Consumer 日志
tail -f logs/consumer.log

# 查看 Web App 日志
tail -f logs/app.log

# 查看所有 Docker 服务日志
docker compose -f docker-compose.dev.yml logs -f

# 查看特定服务日志
docker compose -f docker-compose.dev.yml logs -f postgres
docker compose -f docker-compose.dev.yml logs -f redis
docker compose -f docker-compose.dev.yml logs -f raglite
```

### 数据库操作
```bash
# 连接 PostgreSQL
docker exec -it panda-wiki-postgres psql -U panda-wiki -d panda-wiki

# 连接 Redis
docker exec -it panda-wiki-redis redis-cli -a admin123

# 查看数据库表
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\dt"
```

---

## 🐛 故障排查

### 问题 1: 端口被占用
```bash
# 查看端口占用
lsof -i :8000  # API
lsof -i :3010  # Web App
lsof -i :5432  # PostgreSQL

# 停止所有服务后重启
./stop-local-dev.sh
./start-local-dev.sh
```

### 问题 2: Docker 服务启动失败
```bash
# 查看 Docker 服务状态
docker compose -f docker-compose.dev.yml ps

# 查看服务日志
docker compose -f docker-compose.dev.yml logs postgres
docker compose -f docker-compose.dev.yml logs redis

# 重新拉取镜像
docker compose -f docker-compose.dev.yml pull

# 完全重启 Docker 服务
docker compose -f docker-compose.dev.yml down -v
docker compose -f docker-compose.dev.yml up -d
```

### 问题 3: API 服务启动失败
```bash
# 查看 API 日志
tail -f logs/api.log

# 检查配置文件
ls -la backend/config.dev.yml

# 手动启动 API（调试模式）
cd backend
DATA_DIR=./data SSL_DIR=./data/ssl CONFIG_FILE=config.dev.yml go run ./cmd/api
```

### 问题 4: Web App 启动失败
```bash
# 查看 Web App 日志
tail -f logs/app.log

# 检查前端配置
ls -la web/app/.env.dev web/app/.env.local

# 手动启动 Web App（调试模式）
cd web/app
pnpm dev
```

### 问题 5: 数据库连接失败
```bash
# 检查 PostgreSQL 状态
docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki

# 检查数据库连接
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "SELECT 1;"

# 重启数据库
docker compose -f docker-compose.dev.yml restart postgres
```

---

## ⚙️ 配置说明

### 环境变量 (.env)
```bash
# 数据库密码
POSTGRES_PASSWORD=admin123

# Redis 密码
REDIS_PASSWORD=admin123

# JWT 密钥
JWT_SECRET=admin123

# MinIO 密钥
S3_SECRET_KEY=admin123

# 管理员密码
ADMIN_PASSWORD=admin123
```

### 后端配置 (backend/config.dev.yml)
- 数据库连接配置
- Redis 连接配置
- MinIO 存储配置
- RAG 服务配置
- 消息队列配置

### 前端配置 (web/app/.env.dev)
- API 服务地址
- 静态文件服务地址
- 默认知识库 ID
- 互联网检索 URL

---

## 📁 目录结构

```
PandaWiki/
├── init-local-dev.sh           # 环境初始化脚本
├── start-local-dev.sh          # 启动脚本
├── stop-local-dev.sh           # 停止脚本
├── check-local-dev.sh          # 状态检查脚本
├── test-local-dev.sh           # 功能测试脚本
├── docker-compose.dev.yml      # Docker 服务配置
├── .env                        # 环境变量
├── logs/                       # 日志目录
│   ├── api.log                 # API 服务日志
│   ├── consumer.log            # Consumer 服务日志
│   ├── app.log                 # Web App 日志
│   ├── api.pid                 # API 进程 ID
│   ├── consumer.pid            # Consumer 进程 ID
│   └── app.pid                 # Web App 进程 ID
├── data/                       # 数据持久化目录
│   ├── postgres/               # PostgreSQL 数据
│   ├── redis/                  # Redis 数据
│   ├── minio/                  # MinIO 数据
│   ├── qdrant/                 # Qdrant 数据
│   └── raglite/                # Raglite 数据
├── backend/
│   ├── config.dev.yml          # 后端开发配置
│   └── data/                   # 后端数据目录
└── web/app/
    ├── .env.dev                # 前端开发配置
    └── .env.local              # 当前使用的配置
```

---

## 🔐 默认凭据

### 应用登录
- **用户名**: admin
- **密码**: admin123

### 服务凭据
- **PostgreSQL**: 用户名 `panda-wiki`, 密码 `admin123`
- **Redis**: 密码 `admin123`
- **MinIO**: 用户名 `s3panda-wiki`, 密码 `admin123`
- **NATS**: 用户名 `panda-wiki`, 密码 `admin123`
- **Qdrant**: API Key `admin123`

---

## 💡 开发提示

### 1. 热重载
- **后端**: 修改代码后需要重启 API 服务
- **前端**: 支持热重载，修改后自动刷新

### 2. 数据持久化
- 所有数据存储在 `data/` 目录
- 删除该目录会清空所有数据
- 建议定期备份重要数据

### 3. 性能优化
- 首次启动需要下载 Docker 镜像，耗时较长
- 后续启动会复用已有镜像，速度较快
- 建议分配足够的 Docker 资源（内存 >= 4GB）

### 4. 网络配置
- 所有服务使用 host 网络模式
- 确保所需端口未被其他程序占用
- 如有端口冲突，可修改 docker-compose.dev.yml

---

## 📚 相关文档

- [详细脚本说明](LOCAL_DEV_SCRIPTS.md)
- [开发规范](DEVELOPMENT_RULES.md)
- [配置指南](CONFIG_GUIDE.md)
- [部署指南](DEPLOYMENT_CHECKLIST.md)
- [项目结构](PROJECT_STRUCTURE.md)

---

## 🤝 获得帮助

如果遇到问题：

1. **查看日志**: `tail -f logs/api.log`
2. **检查状态**: `./check-local-dev.sh`
3. **运行测试**: `./test-local-dev.sh`
4. **重启服务**: `./stop-local-dev.sh && ./start-local-dev.sh`
5. **查看文档**: 阅读相关 Markdown 文档
6. **提交 Issue**: 在项目仓库中提交问题报告

---

**最后更新**: 2025-12-10