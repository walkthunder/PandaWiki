# 本地开发环境配置总结

## ✅ 已完成的配置

### 1. 创建的文件

#### Docker 配置
- **`docker-compose.local.yml`**: 本地开发专用的 Docker Compose 配置
  - 只包含依赖服务（PostgreSQL、Redis、MinIO、NATS、Qdrant、Raglite、Caddy）
  - 不包含 api 和 consumer（方便本地调试）
  - 所有端口映射到 localhost

#### 启动脚本
- **`run-api.sh`**: 快速启动 API 服务的脚本
- **`run-consumer.sh`**: 快速启动 Consumer 服务的脚本
- **`start-local-dev.sh`**: 一键启动所有依赖服务的脚本
- **`stop-local-dev.sh`**: 停止本地开发环境的脚本

#### 配置文件
- **`backend/config.local.yml`**: 本地开发配置模板
- **`backend/migration`**: 符号链接到 `store/pg/migration`（解决迁移路径问题）

#### VS Code 配置
- **`.vscode/launch.json`**: 调试配置
  - 🚀 Debug API Server
  - 🔄 Debug Consumer
  - 🗄️ Run Migration
- **`.vscode/tasks.json`**: 任务配置
  - 启动/停止依赖服务
  - 运行数据库迁移
  - 生成代码

#### 文档
- **`LOCAL_DEV_QUICK_START.md`**: 快速启动指南
- **`LOCAL_DEV_GUIDE.md`**: 详细开发指南
- **`SETUP_SUMMARY.md`**: 本文件

### 2. 修改的文件

#### 后端代码修改
- **`backend/cmd/api/main.go`**: 添加 build tag 支持
- **`backend/telemetry/client.go`**: 支持 `DATA_DIR` 环境变量
- **`backend/setup/cert.go`**: 支持 `SSL_DIR` 环境变量

这些修改使得后端可以在本地开发环境运行，而不需要 Docker 容器的特定路径。

#### 前端配置
- **`web/app/.env`**: 已配置为连接本地后端
  ```properties
  TARGET=http://localhost:8000
  ```

## 🚀 如何使用

### 方式一：完整启动（推荐新手）

```bash
# 1. 启动所有依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 启动后端 API
./run-api.sh

# 3. 启动前端（新终端）
cd web/app && pnpm dev
```

### 方式二：使用 VS Code 调试

```bash
# 1. 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 在 VS Code 中按 F5，选择 "🚀 Debug API Server"

# 3. 启动前端（新终端）
cd web/app && pnpm dev
```

## 📋 服务端口

| 服务 | 端口 | 说明 |
|------|------|------|
| 后端 API | 8000 | Go 服务 |
| 前端 App | 3010 | Next.js 服务 |
| PostgreSQL | 5432 | 数据库 |
| Redis | 6379 | 缓存 |
| MinIO | 9000 | 对象存储 |
| MinIO Console | 9001 | MinIO 管理界面 |
| NATS | 4222 | 消息队列 |
| Qdrant | 6333 | 向量数据库 |
| Raglite | 8080 | RAG 服务 |

## 🔑 默认密码

所有服务的默认密码都是：`panda-wiki`

- PostgreSQL: `panda-wiki` / `panda-wiki`
- Redis: `panda-wiki`
- MinIO: `s3panda-wiki` / `panda-wiki`
- NATS: `panda-wiki` / `panda-wiki`
- JWT Secret: `panda-wiki`
- Admin Password: `panda-wiki`

## 🎯 开发优势

### 相比 Docker 部署的优势

1. **快速重启**: 修改代码后直接重启 Go 进程，无需重新构建 Docker 镜像
2. **断点调试**: 可以使用 VS Code 的断点调试功能
3. **实时日志**: 直接在终端查看日志，无需 `docker logs`
4. **性能更好**: 不经过 Docker 网络层，性能更好
5. **开发体验**: 更接近传统的本地开发体验

### 保留 Docker 的优势

1. **环境一致**: 依赖服务（数据库、Redis 等）仍然使用 Docker，保证环境一致
2. **快速启动**: 一条命令启动所有依赖服务
3. **隔离性好**: 依赖服务不会污染本地环境
4. **易于清理**: 可以快速删除所有数据重新开始

## 📝 注意事项

### 1. 环境变量

后端启动脚本 `run-api.sh` 和 `run-consumer.sh` 已经设置了所有必要的环境变量：

```bash
export PG_DSN="host=localhost user=panda-wiki password=panda-wiki dbname=panda-wiki port=5432 sslmode=disable TimeZone=Asia/Shanghai"
export MQ_NATS_SERVER="nats://localhost:4222"
export NATS_PASSWORD="panda-wiki"
export REDIS_ADDR="localhost:6379"
export REDIS_PASSWORD="panda-wiki"
export S3_ENDPOINT="localhost:9000"
export S3_SECRET_KEY="panda-wiki"
export JWT_SECRET="panda-wiki"
export ADMIN_PASSWORD="panda-wiki"
export RAG_CT_RAG_BASE_URL="http://localhost:8080/api/v1"
export DATA_DIR="./data"
export SSL_DIR="./data/ssl"
```

### 2. 数据持久化

- Docker 服务的数据存储在 `./data/` 目录下
- 后端的临时数据存储在 `./backend/data/` 目录下
- 这些目录已添加到 `.gitignore`

### 3. 迁移文件

创建了符号链接 `backend/migration -> backend/store/pg/migration`，解决了 golang-migrate 的路径问题。

### 4. 代码生成

如果修改了 API 或添加了新的依赖注入，需要运行：

```bash
cd backend
make generate
```

## 🐛 故障排查

### API 启动失败

1. 检查依赖服务是否启动：
   ```bash
   docker compose -f docker-compose.local.yml ps
   ```

2. 检查端口是否被占用：
   ```bash
   lsof -i :8000
   ```

3. 查看详细错误日志：
   ```bash
   ./run-api.sh
   ```

### 前端无法连接后端

1. 确认后端正在运行：
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

2. 检查前端配置：
   ```bash
   cat web/app/.env
   ```

3. 清除浏览器缓存并重新加载

### 数据库问题

1. 重置数据库：
   ```bash
   docker compose -f docker-compose.local.yml down -v
   docker compose -f docker-compose.local.yml up -d
   ```

2. 查看数据库日志：
   ```bash
   docker compose -f docker-compose.local.yml logs postgres
   ```

## 🎉 完成！

现在你已经拥有一个完整的本地开发环境，可以：

- ✅ 快速启动和停止服务
- ✅ 使用断点调试后端代码
- ✅ 实时查看日志
- ✅ 快速迭代开发
- ✅ 独立调试前端和后端

开始你的开发之旅吧！🚀
