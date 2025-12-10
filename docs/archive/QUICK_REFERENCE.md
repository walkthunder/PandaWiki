# 快速参考

## 🚀 一键启动

```bash
./dev.sh start
```

## 📝 常用命令

| 命令 | 说明 |
|------|------|
| `./dev.sh start` | 启动所有服务 |
| `./dev.sh stop` | 停止所有服务 |
| `./dev.sh restart` | 重启服务 |
| `./dev.sh status` | 查看状态 |
| `./dev.sh logs api` | 查看 API 日志 |
| `./dev.sh logs consumer` | 查看 Consumer 日志 |

## 🌐 服务地址

| 服务 | 地址 | 说明 |
|------|------|------|
| API | http://localhost:8000 | 后端 API |
| 管理后台 | http://localhost:5173 | 控制台 |
| 前端应用 | http://localhost:3010 | 用户界面 |
| MinIO | http://localhost:9000 | 对象存储 |
| Raglite | http://localhost:8080 | RAG 服务 |

## 🔑 默认账号

```
用户名: admin
密码: panda-wiki
```

## 📱 启动前端

```bash
# 管理后台
cd web/admin && pnpm dev

# 用户应用
cd web/app && pnpm dev
```

## 🐛 故障排查

```bash
# 查看状态
./dev.sh status

# 查看日志
./dev.sh logs api

# 重启
./dev.sh restart

# 检查端口
lsof -ti:8000
```

## 📚 文档

- [README_DEV.md](README_DEV.md) - 快速开始
- [LOCAL_DEV_README.md](LOCAL_DEV_README.md) - 详细指南
- [DEVELOPMENT.md](DEVELOPMENT.md) - 完整文档

## 💡 提示

1. 发布文档后才能搜索
2. 查看 RAG 状态确认向量化完成
3. `ENHANCE_SUCCEEDED` = 可以搜索 ✅
