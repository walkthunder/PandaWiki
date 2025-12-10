# PandaWiki 开发指南

## 📖 文档索引

### 快速开始
- **[README_DEV.md](README_DEV.md)** - 本地开发快速开始（推荐）
- **[LOCAL_DEV_README.md](LOCAL_DEV_README.md)** - 详细的本地开发指南
- [QUICK_START.md](QUICK_START.md) - 项目快速开始

### 专题指南
- [DATABASE_MIGRATION_GUIDE.md](DATABASE_MIGRATION_GUIDE.md) - 数据库迁移指南
- [MIGRATION_QUICK_REFERENCE.md](MIGRATION_QUICK_REFERENCE.md) - 迁移快速参考
- [TEST_CHECKLIST.md](TEST_CHECKLIST.md) - 测试检查清单
- [KNOWN_ISSUES.md](KNOWN_ISSUES.md) - 已知问题

### 项目信息
- [README.md](README.md) - 项目主文档
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) - 项目结构说明
- [CONTRIBUTING.md](CONTRIBUTING.md) - 贡献指南
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - 行为准则
- [SECURITY.md](SECURITY.md) - 安全政策

## 🚀 启动脚本

### 统一启动脚本（推荐）
```bash
./dev.sh start      # 启动所有服务
./dev.sh stop       # 停止所有服务
./dev.sh restart    # 重启服务
./dev.sh status     # 查看状态
./dev.sh logs api   # 查看日志
```

### 单独启动脚本
```bash
./run-api.sh        # 启动 API 服务
./run-consumer.sh   # 启动 Consumer 服务
./run-admin.sh      # 启动管理后台
./run-app.sh        # 启动前端应用
```

## 🔧 开发工具

### 数据库脚本
```bash
./scripts/backup-database.sh      # 备份数据库
./scripts/rollback-migration.sh   # 回滚迁移
```

### 验证脚本
```bash
./verify-setup.sh   # 验证环境设置
```

## 📁 目录结构

```
PandaWiki/
├── backend/              # 后端 Go 代码
│   ├── cmd/             # 命令行入口
│   ├── api/             # API 处理器
│   ├── domain/          # 领域模型
│   ├── repo/            # 数据仓库
│   ├── usecase/         # 业务逻辑
│   └── migration/       # 数据库迁移
├── web/                 # 前端代码
│   ├── admin/          # 管理后台
│   └── app/            # 用户应用
├── scripts/            # 工具脚本
├── docs/               # 文档
│   └── archive/        # 归档文档
├── dev.sh              # 统一启动脚本
└── README_DEV.md       # 开发快速开始
```

## 🎯 开发流程

### 1. 环境准备
```bash
# 安装依赖
# - Docker & Docker Compose
# - Go 1.21+
# - Node.js 18+
# - pnpm

# 启动服务
./dev.sh start
```

### 2. 后端开发
```bash
# 启动 API（带热重载）
cd backend
go run ./cmd/api

# 运行测试
go test ./...

# 代码生成
make generate
```

### 3. 前端开发
```bash
# 管理后台
cd web/admin
pnpm dev

# 用户应用
cd web/app
pnpm dev
```

### 4. 数据库操作
```bash
# 创建迁移
cd backend
go run cmd/migrate/main.go create <migration_name>

# 运行迁移
go run cmd/migrate/main.go

# 回滚迁移
./scripts/rollback-migration.sh
```

## 🐛 调试技巧

### 查看日志
```bash
# API 日志
./dev.sh logs api

# Consumer 日志
./dev.sh logs consumer

# Docker 服务日志
docker logs panda-wiki-postgres
docker logs panda-wiki-raglite
```

### 检查服务
```bash
# 查看所有服务状态
./dev.sh status

# 检查端口占用
lsof -ti:8000  # API
lsof -ti:5173  # 管理后台
lsof -ti:3010  # 前端应用
```

### 数据库调试
```bash
# 连接数据库
docker exec -it panda-wiki-postgres psql -U panda-wiki -d panda-wiki

# 查看表
\dt

# 查看数据
SELECT * FROM nodes LIMIT 10;
```

## 📝 代码规范

### Go 代码
- 使用 `gofmt` 格式化
- 遵循 Go 标准项目布局
- 添加必要的注释和文档

### TypeScript/React 代码
- 使用 ESLint 和 Prettier
- 遵循 React Hooks 规范
- 组件使用 TypeScript 类型

### Git 提交
```bash
# 提交格式
feat: 添加新功能
fix: 修复 bug
docs: 更新文档
refactor: 重构代码
test: 添加测试
chore: 构建/工具变更
```

## 🔗 相关链接

- [项目主页](README.md)
- [快速开始](README_DEV.md)
- [详细指南](LOCAL_DEV_README.md)
- [问题追踪](KNOWN_ISSUES.md)

## 💡 提示

1. **首次启动**：使用 `./dev.sh start` 会自动配置所有服务
2. **文档发布**：记得发布文档后才能在前端搜索
3. **向量化**：Consumer 服务会自动处理，查看 RAG 状态确认完成
4. **端口冲突**：如遇端口占用，使用 `lsof -ti:<port>` 查找并关闭
5. **数据清理**：使用 `./dev.sh clean` 清理并重启

## 🆘 获取帮助

- 查看 [KNOWN_ISSUES.md](KNOWN_ISSUES.md) 了解常见问题
- 查看日志文件排查错误
- 使用 `./dev.sh status` 检查服务状态
