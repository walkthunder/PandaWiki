# PandaWiki 本地开发指南

## 快速开始

### 1. 一键启动所有服务

```bash
./dev.sh start
```

这个命令会自动：
- 启动所有 Docker 依赖服务（PostgreSQL、Redis、NATS、MinIO、Raglite 等）
- 配置后端环境
- 启动 API 服务 (http://localhost:8000)
- 启动 Consumer 服务（处理向量化任务）

### 2. 启动管理后台

```bash
cd web/admin
pnpm install  # 首次运行需要安装依赖
pnpm dev
```

访问：http://localhost:5173
- 用户名：`admin`
- 密码：`panda-wiki`

### 3. 启动前端应用（可选）

```bash
cd web/app
pnpm install  # 首次运行需要安装依赖
pnpm dev
```

访问：http://localhost:3010

## 常用命令

```bash
# 查看服务状态
./dev.sh status

# 查看 API 日志
./dev.sh logs api

# 查看 Consumer 日志
./dev.sh logs consumer

# 停止所有服务
./dev.sh stop

# 重启所有服务
./dev.sh restart

# 清理并重启
./dev.sh clean
```

## 服务端口

| 服务 | 端口 | 说明 |
|------|------|------|
| API | 8000 | 后端 API 服务 |
| 管理后台 | 5173 | 管理控制台 |
| 前端应用 | 3010 | 用户访问的知识库界面 |
| PostgreSQL | 5432 | 数据库 |
| Redis | 6379 | 缓存 |
| MinIO | 9000 | 对象存储 |
| MinIO Console | 9001 | MinIO 管理界面 |
| NATS | 4222 | 消息队列 |
| Qdrant | 6333 | 向量数据库 |
| Raglite | 8080 | RAG 服务 |

## 开发流程

### 1. 创建知识库

1. 访问管理后台：http://localhost:5173
2. 登录（admin / panda-wiki）
3. 点击"创建知识库"
4. 填写知识库信息并保存

### 2. 创建文档

1. 在知识库中点击"新建文档"
2. 编辑文档内容
3. 保存文档

### 3. 发布文档

1. 在文档列表中选择要发布的文档
2. 点击"发布"按钮
3. 填写版本信息
4. 确认发布

**重要**：只有发布后的文档才能：
- 在前端应用中显示
- 被 AI 搜索和问答

### 4. 查看向量化状态

发布文档后，Consumer 服务会自动处理向量化任务。在文档列表中可以看到 RAG 状态：
- `BASIC_PENDING`: 等待处理
- `BASIC_RUNNING`: 基础处理中
- `ENHANCE_PENDING`: 等待增强
- `ENHANCE_RUNNING`: 增强处理中
- `ENHANCE_SUCCEEDED`: 处理成功 ✅
- `ENHANCE_FAILED`: 处理失败

## 故障排查

### API 服务启动失败

```bash
# 查看日志
./dev.sh logs api

# 检查端口占用
lsof -ti:8000

# 重启服务
./dev.sh restart
```

### Consumer 服务无法处理任务

```bash
# 查看日志
./dev.sh logs consumer

# 检查 NATS 连接
docker logs panda-wiki-nats

# 重启 Consumer
./dev.sh stop
./dev.sh start
```

### 数据库连接失败

```bash
# 检查 PostgreSQL 状态
docker ps | grep postgres

# 查看数据库日志
docker logs panda-wiki-postgres

# 重启数据库
docker restart panda-wiki-postgres
```

### 向量化任务失败

```bash
# 检查 Raglite 服务
curl http://localhost:8080/health

# 查看 Raglite 日志
docker logs panda-wiki-raglite

# 重启 Raglite
docker restart panda-wiki-raglite
```

## 环境变量

所有环境变量都在 `dev.sh` 中配置，主要包括：

```bash
PG_DSN="host=localhost user=panda-wiki password=panda-wiki dbname=panda-wiki port=5432"
MQ_NATS_SERVER="nats://localhost:4222"
REDIS_ADDR="localhost:6379"
S3_ENDPOINT="localhost:9000"
RAG_CT_RAG_BASE_URL="http://localhost:8080/api/v1"
JWT_SECRET="panda-wiki"
ADMIN_PASSWORD="panda-wiki"
```

## 清理数据

```bash
# 停止所有服务
./dev.sh stop

# 删除 Docker 卷（会清空所有数据）
docker compose -f docker-compose.local.yml down -v

# 重新启动
./dev.sh start
```

## 更多文档

- [完整开发指南](LOCAL_DEV_GUIDE.md)
- [数据库迁移指南](DATABASE_MIGRATION_GUIDE.md)
- [快速开始](QUICK_START.md)
