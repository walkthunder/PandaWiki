# PandaWiki 本地开发快速启动指南

## 📋 前置要求

- Docker 20.x 及以上
- Go 1.21 及以上
- Node.js 18 及以上
- pnpm 包管理器

## 🚀 一键启动

### 启动所有服务

```bash
./start-local-dev.sh
```

这个脚本会自动完成以下操作：

1. ✅ 检查 Docker 状态
2. ✅ 启动 Docker 依赖服务（PostgreSQL、Redis、MinIO、NATS、Qdrant、Raglite、Caddy、Crawler）
3. ✅ 等待所有服务就绪
4. ✅ 自动配置后端配置文件（使用正确的密码）
5. ✅ 创建必要的数据目录
6. ✅ 启动 API 服务（后台运行）
7. ✅ 启动 Web App（后台运行）

### 停止所有服务

```bash
./stop-local-dev.sh
```

这个脚本会停止所有运行的服务，包括 Docker 容器和后台进程。

## 📝 服务信息

启动后，以下服务可用：

| 服务 | 地址 | 用户名 | 密码 |
|------|------|--------|------|
| **Web App** | http://localhost:3010 | admin | admin123 |
| **API 服务** | http://localhost:8000 | - | - |
| PostgreSQL | localhost:5432 | panda-wiki | admin123 |
| Redis | localhost:6379 | - | admin123 |
| MinIO | http://localhost:9000 | s3panda-wiki | admin123 |
| MinIO Console | http://localhost:9001 | s3panda-wiki | admin123 |
| NATS | localhost:4222 | panda-wiki | admin123 |
| Qdrant | http://localhost:6333 | - | API Key: admin123 |
| Raglite | http://localhost:8080 | - | - |

## 🔧 常用命令

### 查看日志

```bash
# 查看 API 日志
tail -f logs/api.log

# 查看 Web App 日志
tail -f logs/app.log

# 查看 Docker 服务日志
docker compose -f docker-compose.local.yml logs -f

# 查看特定服务日志
docker compose -f docker-compose.local.yml logs -f postgres
```

### 重启服务

```bash
# 重启所有服务
./stop-local-dev.sh && ./start-local-dev.sh

# 只重启 API 服务
kill $(cat logs/api.pid)
cd backend && DATA_DIR=./data SSL_DIR=./data/ssl go run ./cmd/api > ../logs/api.log 2>&1 &

# 只重启 Web App
kill $(cat logs/app.pid)
cd web/app && pnpm dev > ../../logs/app.log 2>&1 &
```

### 数据库操作

```bash
# 连接到 PostgreSQL
docker exec -it panda-wiki-postgres psql -U panda-wiki -d panda-wiki

# 连接到 Redis
docker exec -it panda-wiki-redis redis-cli -a admin123

# 运行数据库迁移
cd backend && go run cmd/migrate/main.go
```

## 📂 文件说明

### 自动生成的文件

- `backend/config.yml` - 后端配置文件（自动生成，使用 admin123 密码）
- `backend/data/` - 后端数据目录
- `backend/data/ssl/` - SSL 证书目录
- `logs/api.log` - API 服务日志
- `logs/app.log` - Web App 日志
- `logs/api.pid` - API 服务进程 ID
- `logs/app.pid` - Web App 进程 ID

### 配置文件

- `.env` - 环境变量配置（所有密码统一为 admin123）
- `docker-compose.local.yml` - Docker 本地开发配置
- `backend/config.local.yml` - 后端配置模板（参考用）
- `web/app/.env` - Web App 环境变量

## 🐛 故障排查

### 端口冲突

如果遇到端口冲突，可以：

1. 检查占用端口的进程：
```bash
lsof -i :8000  # API 端口
lsof -i :3010  # Web App 端口
lsof -i :5432  # PostgreSQL 端口
```

2. 停止冲突的进程或修改配置文件中的端口

### 服务启动失败

1. 查看日志：
```bash
tail -f logs/api.log
tail -f logs/app.log
docker compose -f docker-compose.local.yml logs
```

2. 检查 Docker 服务状态：
```bash
docker compose -f docker-compose.local.yml ps
```

3. 重新启动：
```bash
./stop-local-dev.sh
./start-local-dev.sh
```

### 数据库连接失败

确保 PostgreSQL 已完全启动：
```bash
docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki
```

### 清理并重新开始

```bash
# 停止所有服务
./stop-local-dev.sh

# 删除 Docker 数据卷（会清空所有数据）
docker compose -f docker-compose.local.yml down -v

# 删除数据目录
rm -rf data/ backend/data/

# 重新启动
./start-local-dev.sh
```

## 💡 开发技巧

### 使用 VS Code 调试

项目已配置好 VS Code 调试环境（`.vscode/launch.json`），可以：

1. 先启动 Docker 服务：
```bash
docker compose -f docker-compose.local.yml up -d
```

2. 在 VS Code 中按 `F5` 启动调试

### 热重载

- **Web App**: 使用 Next.js Turbopack，自动热重载
- **API 服务**: 可以使用 `air` 工具实现热重载：
```bash
cd backend
air
```

### 代码生成

```bash
cd backend

# 生成 Swagger 文档 + Wire 依赖注入
make generate

# 创建新的数据库迁移
make migrate_sql SEQ_NAME=your_migration_name
```

## 📚 相关文档

- [完整开发指南](LOCAL_DEV_GUIDE.md)
- [部署指南](DEPLOYMENT_GUIDE.md)
- [项目结构](PROJECT_STRUCTURE.md)
- [快速开始](QUICK_START.md)

## ⚙️ 配置说明

### 密码统一说明

所有服务的密码已统一配置为 `admin123`（来自 `.env` 文件）：

- PostgreSQL: admin123
- Redis: admin123
- NATS: admin123
- MinIO: admin123
- Qdrant API Key: admin123
- JWT Secret: admin123
- Admin 用户密码: admin123

### 修改密码

如需修改密码，请编辑以下文件：

1. `.env` - 修改所有服务的密码
2. 重新运行 `./start-local-dev.sh`（会自动更新 backend/config.yml）

## 🎯 下一步

1. 访问 http://localhost:3010 查看前端应用
2. 使用 admin/admin123 登录
3. 开始开发！

---

**提示**: 如果遇到问题，请先查看日志文件，大部分问题都能从日志中找到原因。
