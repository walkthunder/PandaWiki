# 本地开发快速启动指南

## ✅ 已完成配置

本地开发环境已经配置完成！你现在可以：
- ✅ 使用 Docker 运行依赖服务（PostgreSQL、Redis、MinIO、NATS 等）
- ✅ 本地运行后端 API 服务，方便调试
- ✅ 本地运行前端服务

## 🚀 快速启动

### 1. 启动依赖服务

```bash
# 启动所有依赖服务（PostgreSQL、Redis、MinIO、NATS、Qdrant、Raglite、Caddy）
docker compose -f docker-compose.local.yml up -d

# 查看服务状态
docker compose -f docker-compose.local.yml ps

# 查看服务日志
docker compose -f docker-compose.local.yml logs -f
```

### 2. 启动后端 API 服务

```bash
# 方式一：使用快速启动脚本（推荐）
./run-api.sh

# 方式二：手动启动
cd backend
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
go run ./cmd/api
```

API 服务将在 `http://localhost:8000` 启动。

### 3. 启动 Consumer 服务（可选）

如果需要调试消息队列处理：

```bash
./run-consumer.sh
```

### 4. 启动管理后台（必须先启动）

```bash
# 方式一：使用快速启动脚本（推荐）
./run-admin.sh

# 方式二：手动启动
cd web/admin
pnpm install  # 首次运行需要安装依赖
pnpm dev      # 启动开发服务器
```

管理后台将在 `http://localhost:5173` 启动。

**默认登录账号**：
- 用户名：`admin`
- 密码：`panda-wiki`

登录后，你需要先创建一个知识库。

### 5. 启动前端应用（可选）

```bash
cd web/app
pnpm install  # 首次运行需要安装依赖
pnpm dev      # 启动开发服务器
```

前端应用将在 `http://localhost:3010` 启动。

**注意**：前端应用需要知识库 ID 才能正常访问，所以必须先在管理后台创建知识库。

## 📋 服务信息

| 服务 | 地址 | 用户名 | 密码 |
|------|------|--------|------|
| **后端 API** | `http://localhost:8000` | - | - |
| **管理后台** | `http://localhost:5173` | `admin` | `panda-wiki` |
| **前端 App** | `http://localhost:3010` | - | - |
| PostgreSQL | `localhost:5432` | `panda-wiki` | `panda-wiki` |
| Redis | `localhost:6379` | - | `panda-wiki` |
| MinIO | `http://localhost:9000` | `s3panda-wiki` | `panda-wiki` |
| MinIO Console | `http://localhost:9001` | `s3panda-wiki` | `panda-wiki` |
| NATS | `localhost:4222` | `panda-wiki` | `panda-wiki` |
| Qdrant | `http://localhost:6333` | - | API Key: `panda-wiki` |
| Raglite | `http://localhost:8080` | - | - |

## 🐛 使用 VS Code 调试

项目已配置好 VS Code 调试环境（`.vscode/launch.json`）：

1. 确保依赖服务已启动
2. 在代码中设置断点
3. 按 `F5` 或点击"运行和调试"
4. 选择调试配置：
   - **🚀 Debug API Server**: 调试 API 服务
   - **🔄 Debug Consumer**: 调试消息队列消费者
   - **🗄️ Run Migration**: 运行数据库迁移

## 🛠️ 常用命令

### 后端开发

```bash
cd backend

# 生成代码（Swagger 文档 + Wire 依赖注入）
make generate

# 代码检查
make lint

# 创建新的数据库迁移
make migrate_sql SEQ_NAME=your_migration_name
```

### 前端开发

#### 管理后台

```bash
cd web/admin

# 安装依赖
pnpm install

# 启动开发服务器
pnpm dev

# 构建生产版本
pnpm build

# 代码格式化（在 web 根目录）
cd .. && pnpm format

# 代码检查
pnpm lint
```

#### 前端应用

```bash
cd web/app

# 安装依赖
pnpm install

# 启动开发服务器
pnpm dev

# 构建生产版本
pnpm build

# 代码格式化
pnpm format

# 代码检查
pnpm lint
```

### Docker 服务管理

```bash
# 启动所有依赖服务
docker compose -f docker-compose.local.yml up -d

# 停止所有服务
docker compose -f docker-compose.local.yml down

# 查看服务状态
docker compose -f docker-compose.local.yml ps

# 查看服务日志
docker compose -f docker-compose.local.yml logs -f [service_name]

# 重启某个服务
docker compose -f docker-compose.local.yml restart [service_name]
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

## 📝 开发工作流

### 日常开发

1. **启动依赖服务**（只需启动一次）
   ```bash
   docker compose -f docker-compose.local.yml up -d
   ```

2. **启动后端**
   ```bash
   ./run-api.sh
   ```

3. **启动管理后台**
   ```bash
   ./run-admin.sh
   ```
   
   访问 `http://localhost:5173`，使用 `admin` / `panda-wiki` 登录，创建知识库。

4. **启动前端应用**（可选）
   ```bash
   cd web/app && pnpm dev
   ```

5. **开发调试**
   - 修改代码
   - 浏览器访问管理后台 `http://localhost:5173`
   - 浏览器访问前端应用 `http://localhost:3010`
   - 使用 VS Code 断点调试后端
   - 使用浏览器开发者工具调试前端

5. **提交代码前**
   ```bash
   # 后端
   cd backend
   make generate  # 生成代码
   make lint      # 代码检查
   
   # 前端
   cd web/app
   pnpm format    # 格式化代码
   pnpm lint      # 代码检查
   ```

### 停止服务

```bash
# 停止后端（Ctrl+C）

# 停止前端（Ctrl+C）

# 停止依赖服务
docker compose -f docker-compose.local.yml down
```

## 🔧 配置文件说明

### 后端配置

- **`backend/config.local.yml`**: 本地开发配置模板
- **`backend/config.yml`**: 实际使用的配置（会被 `.gitignore` 忽略）
- **环境变量优先级**: 环境变量 > config.yml > 默认配置

### 前端配置

- **`web/app/.env`**: 前端环境配置
  ```properties
  TARGET=http://localhost:8000  # 后端 API 地址
  ```

### Docker 配置

- **`docker-compose.local.yml`**: 本地开发的 Docker Compose 配置
  - 只包含依赖服务，不包含 api 和 consumer
  - 所有服务端口都映射到 localhost

## ❓ 常见问题

### 1. 端口冲突

如果遇到端口冲突，可以修改相应的配置：

**后端端口**（默认 8000）：
```bash
# 修改 backend/config.yml
http:
  port: 8001  # 改为其他端口
```

**前端端口**（默认 3010）：
```bash
# 修改启动命令
pnpm dev -- -p 3011
```

**依赖服务端口**：
修改 `docker-compose.local.yml` 中的端口映射。

### 2. 数据库连接失败

确保 PostgreSQL 已完全启动：
```bash
docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki
```

### 3. Redis 认证失败

检查 Redis 密码配置：
```bash
docker exec panda-wiki-redis redis-cli -a panda-wiki ping
```

### 4. 前端无法连接后端

检查：
1. 后端是否正常运行：`curl http://localhost:8000/api/v1/health`
2. 前端配置是否正确：
   - 管理后台：检查 `web/admin/.env` 中的 `TARGET`
   - 前端应用：检查 `web/app/.env` 中的 `TARGET`
3. 浏览器控制台是否有 CORS 错误

### 5. 前端应用报错 "kb_id is required"

这是正常的！你需要：
1. 先启动管理后台 `./run-admin.sh`
2. 访问 `http://localhost:5173`
3. 使用 `admin` / `panda-wiki` 登录
4. 创建一个知识库
5. 然后才能正常使用前端应用

### 5. 清理数据重新开始

```bash
# 停止并删除所有容器和数据卷
docker compose -f docker-compose.local.yml down -v

# 删除本地数据目录
rm -rf data/
rm -rf backend/data/

# 重新启动
docker compose -f docker-compose.local.yml up -d
./run-api.sh
```

## 📚 更多文档

- **[LOCAL_DEV_GUIDE.md](LOCAL_DEV_GUIDE.md)**: 详细的本地开发指南
- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)**: 项目结构说明
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: 贡献指南
- **[README.md](README.md)**: 项目介绍和部署说明

## 🎯 下一步

现在你已经完成了本地开发环境的配置！可以开始：

1. 📖 阅读代码，了解项目结构
2. 🐛 设置断点，调试代码
3. ✨ 开发新功能
4. 🧪 编写测试
5. 📝 提交代码

祝开发愉快！🚀
