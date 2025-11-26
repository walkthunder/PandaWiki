# 快速开始 - 本地开发

## 🚀 一键启动

```bash
# 1. 启动依赖服务和检查环境
./start-all.sh

# 2. 启动后端 API（新终端）
./run-api.sh

# 3. 启动管理后台（新终端）
./run-admin.sh

# 4. 启动前端应用（新终端，可选）
./run-app.sh
```

---

## 📋 服务地址

| 服务 | 地址 | 用途 | 账号 |
|------|------|------|------|
| **管理后台** | http://localhost:5173 | 管理知识库、文档、配置 | admin / panda-wiki |
| **前端应用** | http://localhost:3010 | 用户访问知识库的界面 | - |
| **后端 API** | http://localhost:8000 | API 服务 | - |

---

## 🎯 典型工作流

### 场景一：开发后端功能

```bash
# 1. 启动依赖服务
docker compose -f docker-compose.local.yml up -d

# 2. 启动后端（支持断点调试）
./run-api.sh

# 3. 在 VS Code 中设置断点，开始调试
```

### 场景二：开发管理后台

```bash
# 1. 启动依赖服务和后端
docker compose -f docker-compose.local.yml up -d
./run-api.sh

# 2. 启动管理后台
./run-admin.sh

# 3. 访问 http://localhost:5173 开发
```

### 场景三：开发前端应用

```bash
# 1. 启动依赖服务和后端
docker compose -f docker-compose.local.yml up -d
./run-api.sh

# 2. 启动前端应用（会自动配置知识库 ID）
./run-app.sh

# 3. 访问 http://localhost:3010 开发
```

### 场景四：完整测试

```bash
# 终端 1: 后端
./run-api.sh

# 终端 2: 管理后台
./run-admin.sh

# 终端 3: 前端应用
./run-app.sh

# 终端 4: Consumer（如果需要）
./run-consumer.sh
```

---

## 🛠️ 常用命令

### 启动服务

```bash
./run-api.sh        # 启动后端 API
./run-admin.sh      # 启动管理后台
./run-app.sh        # 启动前端应用
./run-consumer.sh   # 启动消息队列消费者
```

### 验证环境

```bash
./verify-setup.sh   # 验证所有服务状态
```

### 数据库操作

```bash
./scripts/backup-database.sh      # 备份数据库
./scripts/migrate-database.sh     # 执行数据库迁移
./scripts/rollback-migration.sh   # 回滚迁移
```

### Docker 服务

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

---

## 🐛 VS Code 调试

1. 确保依赖服务已启动
2. 按 `F5` 或点击"运行和调试"
3. 选择调试配置：
   - **🚀 Debug API Server**: 调试后端 API
   - **🔄 Debug Consumer**: 调试消息队列消费者
   - **🗄️ Run Migration**: 运行数据库迁移

---

## 📝 开发提示

### 热重载

- ✅ 后端：修改代码后自动重新编译（Go）
- ✅ 管理后台：自动热重载（Vite）
- ✅ 前端应用：自动热重载（Next.js）

### 端口占用

如果端口被占用，可以修改：
- 后端：`backend/config.yml` 中的 `http.port`
- 管理后台：`web/admin/package.json` 中的 `dev` 脚本
- 前端应用：`web/app/package.json` 中的 `dev` 脚本

### 知识库 ID

前端应用会自动使用最新创建的知识库。如果需要切换：

1. 编辑 `web/app/.env.local`
2. 修改 `NEXT_PUBLIC_DEFAULT_KB_ID`
3. 重启前端应用

或者通过 URL 参数：
```
http://localhost:3010?kb_id=你的知识库ID
```

---

## ❓ 常见问题

### Q: 前端应用报错 "kb_id is required"？

**A**: 运行 `./run-app.sh` 会自动配置知识库 ID。或者手动编辑 `web/app/.env.local`。

### Q: Caddy 容器一直重启？

**A**: 这是正常的，macOS 上 Caddy 有兼容性问题。本地开发不需要 Caddy，可以忽略。

### Q: 如何切换知识库？

**A**: 
1. 方式一：编辑 `web/app/.env.local`，修改 `NEXT_PUBLIC_DEFAULT_KB_ID`
2. 方式二：访问 `http://localhost:3010?kb_id=新的知识库ID`

### Q: 如何重置环境？

**A**:
```bash
# 停止所有服务
docker compose -f docker-compose.local.yml down -v

# 删除数据
rm -rf data/ backend/data/

# 重新启动
./start-all.sh
```

---

## 📚 更多文档

- [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md) - 首次使用指南
- [LOCAL_DEV_QUICK_START.md](LOCAL_DEV_QUICK_START.md) - 详细快速启动
- [LOCAL_DEV_GUIDE.md](LOCAL_DEV_GUIDE.md) - 完整开发指南
- [LOCAL_DEV_PROXY_GUIDE.md](LOCAL_DEV_PROXY_GUIDE.md) - 代理配置指南
- [DATABASE_MIGRATION_GUIDE.md](DATABASE_MIGRATION_GUIDE.md) - 数据库迁移指南

---

## ✅ 检查清单

启动前：
- [ ] Docker 已安装并运行
- [ ] Go 已安装（1.21+）
- [ ] Node.js 已安装（18+）
- [ ] pnpm 已安装

首次启动：
- [ ] 运行 `./start-all.sh` 检查环境
- [ ] 运行 `./run-api.sh` 启动后端
- [ ] 运行 `./run-admin.sh` 启动管理后台
- [ ] 访问 http://localhost:5173 创建知识库
- [ ] 运行 `./run-app.sh` 启动前端应用

开发中：
- [ ] 使用 VS Code 断点调试
- [ ] 查看实时日志
- [ ] 测试功能
- [ ] 提交代码前运行 `make lint`

---

祝开发愉快！🎉
