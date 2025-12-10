# 开发环境改进日志

## 2025-11-26 - 本地开发环境优化

### ✨ 新增功能

#### 1. 统一启动脚本 `dev.sh`
- 一键启动所有服务（Docker + API + Consumer）
- 自动检查和等待服务就绪
- 支持查看状态、日志、重启等操作
- 后台运行服务，支持日志查看

**使用方法：**
```bash
./dev.sh start      # 启动
./dev.sh stop       # 停止
./dev.sh status     # 状态
./dev.sh logs api   # 日志
```

#### 2. 文档整理
- 创建 `README_DEV.md` - 快速开始指南
- 创建 `LOCAL_DEV_README.md` - 详细开发指南
- 创建 `DEVELOPMENT.md` - 完整开发文档索引
- 归档过时文档到 `docs/archive/`

#### 3. 保留的单独启动脚本
- `run-api.sh` - 单独启动 API
- `run-consumer.sh` - 单独启动 Consumer
- `run-admin.sh` - 启动管理后台
- `run-app.sh` - 启动前端应用

### 🐛 Bug 修复

#### 1. 知识库发布功能修复
**问题：** 发布文档时报错 "create kb release failed"

**根本原因：**
1. `node_releases` 表的 `doc_id` 字段是 NOT NULL，但代码未设置
2. `Update().Find()` 链式调用错误
3. 代码结构体有 `OriginalURL` 字段，但数据库表中没有

**解决方案：**
- 添加 `DocID: ""` 字段初始化
- 将 `Update().Find()` 分成两个独立操作
- 使用 `Omit("original_url")` 忽略不存在的字段

**修改文件：**
- `backend/repo/pg/node.go`
- `backend/usecase/knowledge_base.go`

#### 2. 文档向量化问题修复
**问题：** 文档 RAG 状态一直是 `BASIC_PENDING`，无法搜索

**根本原因：**
- 调试时临时注释了 MQ 向量化调用
- Docker 容器中的 consumer 无法连接数据库
- 已发布文档没有触发向量化任务

**解决方案：**
- 恢复 MQ 向量化调用代码
- 启动本地 consumer 服务处理任务
- 重新发布文档触发向量化

**结果：**
- 所有文档状态变为 `ENHANCE_SUCCEEDED`
- 可以正常进行智能问答和搜索

### 📝 文档变更

#### 新增文档
- `README_DEV.md` - 开发快速开始
- `LOCAL_DEV_README.md` - 详细开发指南
- `DEVELOPMENT.md` - 开发文档索引
- `CHANGELOG_DEV.md` - 本文档

#### 归档文档
移动到 `docs/archive/`：
- `FIRST_TIME_SETUP.md`
- `SETUP_SUMMARY.md`
- `LOCAL_DEV_QUICK_START.md`
- `LOCAL_DEV_PROXY_GUIDE.md`
- `start-local-dev.sh`

#### 保留文档
- `README.md` - 项目主文档
- `QUICK_START.md` - 快速开始
- `DATABASE_MIGRATION_GUIDE.md` - 数据库迁移
- `MIGRATION_QUICK_REFERENCE.md` - 迁移参考
- `PROJECT_STRUCTURE.md` - 项目结构
- `TEST_CHECKLIST.md` - 测试清单
- `KNOWN_ISSUES.md` - 已知问题
- `CONTRIBUTING.md` - 贡献指南
- `CODE_OF_CONDUCT.md` - 行为准则
- `SECURITY.md` - 安全政策

### 🔧 技术改进

#### 1. 启动流程优化
**之前：**
- 需要手动启动多个服务
- 需要手动检查服务状态
- 日志分散在多个终端

**现在：**
- 一键启动所有服务
- 自动检查服务就绪
- 统一日志管理

#### 2. 开发体验提升
- 清晰的文档结构
- 简化的启动命令
- 完善的故障排查指南
- 统一的服务管理

### 📊 服务架构

```
┌─────────────────────────────────────────┐
│         dev.sh (统一管理)                │
├─────────────────────────────────────────┤
│  Docker Services (docker-compose)       │
│  ├─ PostgreSQL (5432)                   │
│  ├─ Redis (6379)                        │
│  ├─ NATS (4222)                         │
│  ├─ MinIO (9000/9001)                   │
│  ├─ Qdrant (6333)                       │
│  └─ Raglite (8080)                      │
├─────────────────────────────────────────┤
│  Backend Services (Go)                  │
│  ├─ API (8000)                          │
│  └─ Consumer (后台)                      │
├─────────────────────────────────────────┤
│  Frontend (手动启动)                     │
│  ├─ Admin (5173)                        │
│  └─ App (3010)                          │
└─────────────────────────────────────────┘
```

### 🎯 使用建议

#### 日常开发
```bash
# 启动开发环境
./dev.sh start

# 启动前端（新终端）
cd web/admin && pnpm dev

# 查看状态
./dev.sh status

# 查看日志
./dev.sh logs api
```

#### 调试问题
```bash
# 查看服务状态
./dev.sh status

# 查看详细日志
./dev.sh logs api
./dev.sh logs consumer

# 重启服务
./dev.sh restart

# 清理重启
./dev.sh clean
```

#### 停止服务
```bash
# 停止所有服务
./dev.sh stop
```

### 🔮 未来改进

- [ ] 添加前端自动启动选项
- [ ] 集成健康检查端点
- [ ] 添加性能监控
- [ ] 支持多环境配置切换
- [ ] 添加自动化测试脚本

### 📚 相关文档

- [快速开始](README_DEV.md)
- [详细指南](LOCAL_DEV_README.md)
- [完整文档](DEVELOPMENT.md)
