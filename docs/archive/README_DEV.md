# PandaWiki 本地开发

## 🚀 快速开始

### 一键启动

```bash
# 启动所有服务
./dev.sh start

# 查看状态
./dev.sh status
```

### 启动前端

```bash
# 管理后台
cd web/admin && pnpm dev
# 访问 http://localhost:5173

# 用户应用
cd web/app && pnpm dev  
# 访问 http://localhost:3010
```

### 默认账号

- 用户名: `admin`
- 密码: `panda-wiki`

## 📝 常用命令

```bash
./dev.sh start      # 启动所有服务
./dev.sh stop       # 停止所有服务
./dev.sh restart    # 重启服务
./dev.sh status     # 查看状态
./dev.sh logs api   # 查看 API 日志
./dev.sh logs consumer  # 查看 Consumer 日志
```

## 🔧 服务端口

| 服务 | 端口 | 地址 |
|------|------|------|
| API | 8000 | http://localhost:8000 |
| 管理后台 | 5173 | http://localhost:5173 |
| 前端应用 | 3010 | http://localhost:3010 |
| PostgreSQL | 5432 | localhost:5432 |
| Redis | 6379 | localhost:6379 |
| MinIO | 9000 | http://localhost:9000 |
| Raglite | 8080 | http://localhost:8080 |

## 📚 详细文档

- [本地开发详细指南](LOCAL_DEV_README.md)
- [数据库迁移](DATABASE_MIGRATION_GUIDE.md)
- [快速开始](QUICK_START.md)

## ⚠️ 注意事项

1. **发布文档后才能搜索**：文档需要先发布，Consumer 服务会自动处理向量化
2. **向量化状态**：在文档列表查看 RAG 状态，`ENHANCE_SUCCEEDED` 表示可以搜索
3. **端口占用**：确保 8000、5173、3010 等端口未被占用

## 🐛 故障排查

```bash
# 查看服务状态
./dev.sh status

# 查看日志
./dev.sh logs api
./dev.sh logs consumer

# 重启服务
./dev.sh restart

# 清理重启
./dev.sh clean
```

## 🎯 开发流程

1. 启动服务: `./dev.sh start`
2. 访问管理后台创建知识库
3. 创建并发布文档
4. 等待向量化完成（查看 RAG 状态）
5. 在前端应用测试搜索和问答
