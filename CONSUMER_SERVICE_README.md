# Consumer 服务说明

## 什么是 Consumer 服务？

Consumer 服务是 PandaWiki 系统中的关键组件，负责处理文档的异步索引和向量化任务。它监听消息队列中的事件，将文档内容上传到 RAG（检索增强生成）系统进行向量化存储。

## 为什么需要 Consumer 服务？

### 核心功能

1. **文档索引** - 将新创建或更新的文档上传到 RAG 系统
2. **向量化处理** - 对文档内容进行向量化，支持语义搜索
3. **权限同步** - 同步文档的访问权限到 RAG 系统
4. **文档删除** - 从 RAG 系统中删除已删除的文档

### 搜索功能依赖

**没有 Consumer 服务，搜索功能将无法正常工作：**

- 用户搜索时返回空结果
- 新上传的文档无法被检索
- 文档更新后搜索结果不会更新
- 权限变更不会同步到搜索系统

## 工作原理

```
用户操作 → API 服务 → 消息队列 → Consumer 服务 → RAG 系统
   ↓           ↓           ↓            ↓           ↓
创建文档    发送事件    接收任务      处理文档    存储向量
```

### 消息队列事件类型

Consumer 服务处理以下类型的事件：

1. **upsert** - 新增或更新文档
2. **delete** - 删除文档
3. **update_group_ids** - 更新文档权限
4. **summary** - 生成文档摘要

## 启动和管理

### 自动启动（推荐）

使用一键启动脚本，Consumer 服务会自动启动：

```bash
./start-local-dev.sh
```

### 手动启动

如果需要单独启动 Consumer 服务：

```bash
cd backend
CONFIG_FILE=config.dev.yml go run ./cmd/consumer
```

### 后台运行

```bash
cd backend
nohup CONFIG_FILE=config.dev.yml go run ./cmd/consumer > ../logs/consumer.log 2>&1 &
```

## 监控和调试

### 查看日志

```bash
# 实时查看 Consumer 日志
tail -f logs/consumer.log

# 查看最近的错误
grep -i error logs/consumer.log | tail -10
```

### 检查服务状态

```bash
# 使用检查脚本
./check-local-dev.sh

# 手动检查进程
ps aux | grep "go run ./cmd/consumer"
```

### 常见日志信息

- `successfully subscribed to topic` - 成功连接到消息队列
- `upsert node content vector success` - 文档索引成功
- `delete node content vector success` - 文档删除成功
- `failed to subscribe to topic` - 消息队列连接失败

## 故障排查

### 问题：搜索返回空结果

**可能原因：**
1. Consumer 服务未启动
2. 消息队列连接失败
3. RAG 服务不可用

**解决方案：**
```bash
# 1. 检查 Consumer 服务状态
./check-local-dev.sh

# 2. 查看 Consumer 日志
tail -f logs/consumer.log

# 3. 重启 Consumer 服务
pkill -f "go run ./cmd/consumer"
cd backend && nohup CONFIG_FILE=config.dev.yml go run ./cmd/consumer > ../logs/consumer.log 2>&1 &
```

### 问题：Consumer 启动失败

**常见错误：**
- `nats: no stream matches subject` - NATS 流配置问题
- `failed to connect to database` - 数据库连接失败
- `failed to send request to caddy` - Caddy 配置问题（可忽略）

**解决方案：**
```bash
# 1. 确保所有依赖服务正常运行
docker compose -f docker-compose.dev.yml ps

# 2. 检查配置文件
cat backend/config.dev.yml

# 3. 重启依赖服务
docker compose -f docker-compose.dev.yml restart
```

## 性能优化

### 批量处理

Consumer 服务支持批量处理文档，提高索引效率：

- 单次处理多个文档更新
- 智能去重，避免重复处理
- 错误重试机制

### 监控指标

关注以下指标来监控 Consumer 性能：

- 消息处理速度
- 错误率
- 队列积压情况
- RAG 系统响应时间

## 开发注意事项

### 本地开发

在本地开发环境中，Consumer 服务是必需的：

1. **必须启动** - 否则搜索功能不工作
2. **配置正确** - 确保能连接到所有依赖服务
3. **日志监控** - 及时发现和解决问题

### 生产部署

在生产环境中：

1. **高可用** - 部署多个 Consumer 实例
2. **监控告警** - 设置服务监控和告警
3. **资源限制** - 合理配置内存和 CPU 限制
4. **日志管理** - 配置日志轮转和归档

## 相关文档

- [本地开发脚本说明](LOCAL_DEV_SCRIPTS.md)
- [项目结构说明](PROJECT_STRUCTURE.md)
- [部署指南](DEPLOYMENT_CHECKLIST.md)

---

**重要提醒：Consumer 服务是搜索功能的核心依赖，务必确保其正常运行！**