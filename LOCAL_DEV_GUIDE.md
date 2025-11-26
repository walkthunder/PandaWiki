# 本地开发指南

本指南帮助你快速搭建本地开发环境，方便调试后端代码。

## 快速开始

### 方式一：使用自动化脚本（推荐）

```bash
# 一键启动所有依赖服务
./start-local-dev.sh
```

脚本会自动完成：
- ✅ 启动所有依赖服务（PostgreSQL、Redis、MinIO、NATS、Qdrant、Raglite、Caddy）
- ✅ 等待服务就绪
- ✅ 配置后端连接
- ✅ 运行数据库迁移

然后手动启动后端：

```bash
cd backend
go run cmd/api/main.go
```

API 服务将在 `http://localhost:8000` 启动。

### 方式二：使用 VS Code 调试（推荐）

1. 先启动依赖服务：
```bash
./start-local-dev.sh
```

2. 在 VS Code 中：
   - 按 `F5` 或点击"运行和调试"
   - 选择 "🚀 Debug API Server"
   - 设置断点，开始调试

### 方式三：手动启动

```bash
# 1. 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 等待服务就绪（约 10-20 秒）
sleep 15

# 3. 配置后端
cd backend
cp config.local.yml config.yml

# 4. 运行数据库迁移
go run cmd/migrate/main.go

# 5. 启动 API 服务
go run cmd/api/main.go
```

## 服务信息

启动后，以下服务可用：

| 服务 | 地址 | 用户名 | 密码 |
|------|------|--------|------|
| PostgreSQL | `localhost:5432` | `panda-wiki` | `panda-wiki` |
| Redis | `localhost:6379` | - | `panda-wiki` |
| MinIO | `http://localhost:9000` | `s3panda-wiki` | `panda-wiki` |
| MinIO Console | `http://localhost:9001` | `s3panda-wiki` | `panda-wiki` |
| NATS | `localhost:4222` | `panda-wiki` | `panda-wiki` |
| Qdrant | `http://localhost:6333` | - | API Key: `panda-wiki` |
| Raglite | `http://localhost:8080` | - | - |
| API Server | `http://localhost:8000` | - | - |

## 常用命令

### 启动/停止服务

```bash
# 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 停止依赖服务
docker compose -f docker-compose.local.yml down

# 查看服务状态
docker compose -f docker-compose.local.yml ps

# 查看服务日志
docker compose -f docker-compose.local.yml logs -f [service_name]
```

### 后端开发

```bash
cd backend

# 生成代码（Swagger 文档 + Wire 依赖注入）
make generate

# 运行数据库迁移
go run cmd/migrate/main.go

# 启动 API 服务
go run cmd/api/main.go

# 启动 Consumer 服务
go run cmd/consumer/main.go

# 代码检查
make lint

# 创建新的数据库迁移
make migrate_sql SEQ_NAME=your_migration_name
```

### 数据库操作

```bash
# 连接到 PostgreSQL
docker exec -it panda-wiki-postgres psql -U panda-wiki -d panda-wiki

# 连接到 Redis
docker exec -it panda-wiki-redis redis-cli -a panda-wiki

# 备份数据库
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > backup.sql

# 恢复数据库
docker exec -i panda-wiki-postgres psql -U panda-wiki panda-wiki < backup.sql
```

## VS Code 调试配置

项目已配置好 VS Code 调试环境，可用的调试配置：

- **🚀 Debug API Server**: 调试 API 服务
- **🔄 Debug Consumer**: 调试消息队列消费者
- **🗄️ Run Migration**: 运行数据库迁移

使用方法：
1. 在代码中设置断点
2. 按 `F5` 或点击"运行和调试"
3. 选择对应的调试配置
4. 开始调试

## 配置文件说明

### backend/config.local.yml

本地开发配置文件，所有服务地址都指向 `localhost`。

关键配置：
```yaml
http:
  port: 8000  # API 服务端口

pg:
  dsn: "host=localhost user=panda-wiki password=panda-wiki dbname=panda-wiki port=5432 sslmode=disable TimeZone=Asia/Shanghai"

redis:
  addr: "localhost:6379"
  password: "panda-wiki"

s3:
  endpoint: "localhost:9000"
  access_key: "s3panda-wiki"
  secret_key: "panda-wiki"
```

### docker-compose.local.yml

本地开发的 Docker Compose 配置，只包含依赖服务，不包含 api 和 consumer。

所有服务都映射到 localhost，方便本地代码连接。

## 常见问题

### 1. 端口冲突

如果遇到端口冲突，可以修改 `docker-compose.local.yml` 中的端口映射：

```yaml
postgres:
  ports:
    - "15432:5432"  # 改为其他端口
```

然后相应修改 `backend/config.local.yml` 中的连接地址。

### 2. 服务启动失败

检查服务状态：
```bash
docker compose -f docker-compose.local.yml ps
docker compose -f docker-compose.local.yml logs [service_name]
```

### 3. 数据库连接失败

确保 PostgreSQL 已完全启动：
```bash
docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki
```

### 4. 清理数据重新开始

```bash
# 停止并删除所有容器和数据卷
docker compose -f docker-compose.local.yml down -v

# 删除数据目录
rm -rf data/

# 重新启动
./start-local-dev.sh
```

## 开发工作流

### 日常开发流程

1. **启动依赖服务**（只需启动一次）
   ```bash
   ./start-local-dev.sh
   ```

2. **开发代码**
   - 修改代码
   - 在 VS Code 中按 `F5` 启动调试
   - 设置断点，测试功能

3. **提交代码前**
   ```bash
   cd backend
   make generate  # 生成代码
   make lint      # 代码检查
   ```

4. **停止服务**（下班或不需要时）
   ```bash
   docker compose -f docker-compose.local.yml down
   ```

### 调试技巧

1. **使用断点调试**
   - 在代码中设置断点
   - 使用 VS Code 的调试功能单步执行
   - 查看变量值和调用栈

2. **查看日志**
   ```bash
   # 查看所有服务日志
   docker compose -f docker-compose.local.yml logs -f
   
   # 查看特定服务日志
   docker compose -f docker-compose.local.yml logs -f postgres
   ```

3. **使用 Postman/curl 测试 API**
   ```bash
   # 测试健康检查
   curl http://localhost:8000/health
   
   # 测试登录
   curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"panda-wiki"}'
   ```

## 环境变量

如果需要覆盖配置，可以设置环境变量：

```bash
export POSTGRES_PASSWORD=your_password
export REDIS_PASSWORD=your_password
export S3_SECRET_KEY=your_secret
export JWT_SECRET=your_secret
```

或者在 `.env` 文件中配置（已在 `.gitignore` 中）。

## 生产环境部署

本地开发完成后，使用以下命令部署到生产环境：

```bash
# 构建并部署
./deploy/local-deploy.sh

# 远程重启服务
./deploy/remote-deploy.sh
```

详见 [README.md](README.md) 中的部署说明。
