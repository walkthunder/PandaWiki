# PandaWiki 本地开发脚本说明

本文档介绍了 PandaWiki 本地开发环境的一键启动脚本及相关工具。

## 📜 脚本列表

### 1. `start-local-dev.sh` - 一键启动脚本

**功能**: 自动启动所有本地开发所需的服务

**使用方法**:
```bash
./start-local-dev.sh
```

**执行流程**:
1. 检查 Docker 是否运行
2. 启动 Docker 依赖服务（PostgreSQL、Redis、MinIO、NATS、Qdrant、Raglite、Caddy、Crawler）
3. 等待所有服务就绪（自动健康检查）
4. 自动生成 `backend/config.yml` 配置文件（使用正确的密码）
5. 创建必要的数据目录（`backend/data/`, `backend/data/ssl/`）
6. 后台启动 API 服务（端口 8000）
7. 后台启动 Web App（端口 3010）
8. 显示所有服务的访问地址和凭据

**输出文件**:
- `backend/config.yml` - 自动生成的后端配置
- `logs/api.log` - API 服务日志
- `logs/app.log` - Web App 日志
- `logs/api.pid` - API 服务进程 ID
- `logs/app.pid` - Web App 进程 ID

---

### 2. `stop-local-dev.sh` - 停止脚本

**功能**: 停止所有本地开发服务

**使用方法**:
```bash
./stop-local-dev.sh
```

**执行流程**:
1. 停止 Web App 进程
2. 停止 API 服务进程
3. 停止所有 Docker 容器
4. 清理 PID 文件

---

### 3. `check-local-dev.sh` - 状态检查脚本

**功能**: 检查所有服务的运行状态

**使用方法**:
```bash
./check-local-dev.sh
```

**检查项目**:
- Docker 服务状态（8 个容器）
- 应用服务端口监听状态
- 服务端点健康检查
- 进程运行状态
- 日志文件存在性
- 配置文件完整性

**输出示例**:
```
========================================
📊 PandaWiki 本地开发环境状态
========================================

Docker 服务:
  ✓ Docker
  ✓ PostgreSQL
  ✓ Redis
  ...

应用服务:
  ✓ API 服务 (端口 8000, PID: 12345)
  ✓ Web App (端口 3010, PID: 67890)
  ...
```

---

## 🔧 配置说明

### 自动配置

`start-local-dev.sh` 脚本会自动生成 `backend/config.yml`，包含以下配置：

```yaml
# 所有密码统一为 admin123
admin_password: "admin123"

pg:
  dsn: "host=localhost user=panda-wiki password=admin123 ..."

redis:
  password: "admin123"

auth:
  jwt:
    secret: "admin123"

s3:
  secret_key: "admin123"

mq:
  nats:
    password: "admin123"
```

### 密码来源

所有密码来自项目根目录的 `.env` 文件：

```bash
POSTGRES_PASSWORD=admin123
REDIS_PASSWORD=admin123
NATS_PASSWORD=admin123
JWT_SECRET=admin123
S3_SECRET_KEY=admin123
QDRANT_API_KEY=admin123
ADMIN_PASSWORD=admin123
```

### 修改密码

如需修改密码：

1. 编辑 `.env` 文件
2. 重新运行 `./start-local-dev.sh`（会自动更新配置）

---

## 📂 目录结构

```
PandaWiki/
├── start-local-dev.sh          # 一键启动脚本
├── stop-local-dev.sh           # 停止脚本
├── check-local-dev.sh          # 状态检查脚本
├── LOCAL_DEV_QUICK_START.md    # 快速启动指南
├── LOCAL_DEV_SCRIPTS.md        # 本文档
├── logs/                       # 日志目录（自动创建）
│   ├── api.log                 # API 服务日志
│   ├── app.log                 # Web App 日志
│   ├── api.pid                 # API 进程 ID
│   └── app.pid                 # Web App 进程 ID
├── backend/
│   ├── config.yml              # 自动生成的配置文件
│   ├── config.local.yml        # 配置模板（参考）
│   └── data/                   # 数据目录（自动创建）
│       └── ssl/                # SSL 证书目录
└── .env                        # 环境变量（密码配置）
```

---

## 🚀 快速开始

### 第一次使用

```bash
# 1. 克隆项目
git clone <repository>
cd PandaWiki

# 2. 确保 Docker 正在运行
docker info

# 3. 一键启动
./start-local-dev.sh

# 4. 访问应用
open http://localhost:3010
```

### 日常开发

```bash
# 启动服务
./start-local-dev.sh

# 检查状态
./check-local-dev.sh

# 查看日志
tail -f logs/api.log
tail -f logs/app.log

# 停止服务
./stop-local-dev.sh
```

---

## 🐛 故障排查

### 问题 1: 端口被占用

**症状**: 启动失败，提示端口已被占用

**解决方案**:
```bash
# 查看占用端口的进程
lsof -i :8000  # API
lsof -i :3010  # Web App

# 停止旧进程
./stop-local-dev.sh

# 重新启动
./start-local-dev.sh
```

### 问题 2: Docker 服务未启动

**症状**: 脚本提示 "Docker 未运行"

**解决方案**:
```bash
# macOS
open -a Docker

# 等待 Docker 启动后重试
./start-local-dev.sh
```

### 问题 3: 服务启动失败

**症状**: 脚本执行完成但服务无法访问

**解决方案**:
```bash
# 1. 检查状态
./check-local-dev.sh

# 2. 查看日志
tail -f logs/api.log
tail -f logs/app.log

# 3. 查看 Docker 日志
docker compose -f docker-compose.local.yml logs

# 4. 完全重启
./stop-local-dev.sh
docker compose -f docker-compose.local.yml down -v
./start-local-dev.sh
```

### 问题 4: 配置文件错误

**症状**: API 服务启动失败，日志显示配置错误

**解决方案**:
```bash
# 删除旧配置
rm backend/config.yml

# 重新生成
./start-local-dev.sh
```

---

## 💡 高级用法

### 只启动 Docker 服务

```bash
docker compose -f docker-compose.local.yml up -d
```

### 手动启动 API 服务

```bash
cd backend
DATA_DIR=./data SSL_DIR=./data/ssl go run ./cmd/api
```

### 手动启动 Web App

```bash
cd web/app
pnpm dev
```

### 使用 VS Code 调试

1. 启动 Docker 服务：
```bash
docker compose -f docker-compose.local.yml up -d
```

2. 在 VS Code 中按 `F5` 启动调试

### 查看实时日志

```bash
# API 日志
tail -f logs/api.log

# Web App 日志
tail -f logs/app.log

# Docker 所有服务日志
docker compose -f docker-compose.local.yml logs -f

# 特定 Docker 服务日志
docker compose -f docker-compose.local.yml logs -f postgres
```

---

## 📊 服务端口映射

| 服务 | 容器端口 | 主机端口 | 说明 |
|------|---------|---------|------|
| PostgreSQL | 5432 | 5432 | 数据库 |
| Redis | 6379 | 6379 | 缓存 |
| MinIO | 9000 | 9000 | 对象存储 |
| MinIO Console | 9001 | 9001 | MinIO 管理界面 |
| NATS | 4222 | 4222 | 消息队列 |
| Qdrant | 6333 | 6333 | 向量数据库 |
| Raglite | 8080 | 8080 | RAG 服务 |
| Caddy | - | host | 反向代理 |
| API | - | 8000 | 后端 API |
| Web App | - | 3010 | 前端应用 |

---

## 🔐 默认凭据

| 服务 | 用户名 | 密码 | 说明 |
|------|--------|------|------|
| Web App | admin | admin123 | 管理员账号 |
| PostgreSQL | panda-wiki | admin123 | 数据库 |
| Redis | - | admin123 | 缓存 |
| MinIO | s3panda-wiki | admin123 | 对象存储 |
| NATS | panda-wiki | admin123 | 消息队列 |
| Qdrant | - | admin123 | API Key |

---

## 📝 注意事项

1. **首次启动**: 首次启动可能需要较长时间（下载 Docker 镜像）
2. **数据持久化**: 数据存储在 `data/` 目录，删除该目录会清空所有数据
3. **日志文件**: 日志文件会持续增长，建议定期清理
4. **端口冲突**: 确保所需端口未被其他程序占用
5. **Docker 资源**: 确保 Docker 有足够的内存和磁盘空间

---

## 🔗 相关文档

- [快速启动指南](LOCAL_DEV_QUICK_START.md) - 详细的使用说明
- [完整开发指南](LOCAL_DEV_GUIDE.md) - 深入的开发文档
- [部署指南](DEPLOYMENT_GUIDE.md) - 生产环境部署
- [项目结构](PROJECT_STRUCTURE.md) - 代码结构说明

---

## 🤝 贡献

如果你发现脚本有问题或有改进建议，欢迎提交 Issue 或 Pull Request。

---

**最后更新**: 2025-12-10
