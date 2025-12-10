# PandaWiki

PandaWiki 是一款 AI 驱动的开源知识库搭建系统。

## 🚀 快速开始

### 本地开发

一键启动所有本地开发服务：

```bash
./start-local-dev.sh
```

详细说明请查看：
- [快速启动指南](LOCAL_DEV_QUICK_START.md) - 推荐新手阅读
- [脚本详细说明](LOCAL_DEV_SCRIPTS.md) - 脚本功能说明
- [完整开发指南](LOCAL_DEV_GUIDE.md) - 深入的开发文档

### 生产部署

#### 1. 本地打包构建并传输到服务器

```bash
./deploy/local-deploy.sh
```

> 默认会构建 panda-wiki-api 和 panda-wiki-consumer 镜像，并传输到 root@8.140.221.27

#### 2. 服务重启

```bash
./deploy/remote-deploy.sh
```

详细说明请查看：
- [部署指南](DEPLOYMENT_GUIDE.md)
- [部署总结](DEPLOYMENT_SUMMARY.md)

## 📚 文档

### 开发相关
- [本地开发快速启动](LOCAL_DEV_QUICK_START.md) - 一键启动本地环境
- [本地开发脚本说明](LOCAL_DEV_SCRIPTS.md) - 脚本功能详解
- [完整开发指南](LOCAL_DEV_GUIDE.md) - 详细的开发文档
- [数据库迁移指南](DATABASE_MIGRATION_GUIDE.md) - 数据库变更管理

### 部署相关
- [部署指南](DEPLOYMENT_GUIDE.md) - 生产环境部署
- [部署总结](DEPLOYMENT_SUMMARY.md) - 部署流程总结

### 其他
- [快速开始](QUICK_START.md) - 项目快速上手
- [项目结构](PROJECT_STRUCTURE.md) - 代码结构说明
- [从这里开始](START_HERE.md) - 新手入门

## 🛠️ 常用命令

### 本地开发

```bash
# 启动所有服务
./start-local-dev.sh

# 检查服务状态
./check-local-dev.sh

# 停止所有服务
./stop-local-dev.sh

# 查看日志
tail -f logs/api.log
tail -f logs/app.log
```

### 部署

```bash
# 构建并部署
./deploy/local-deploy.sh

# 远程重启
./deploy/remote-deploy.sh
```

## 🔧 配置说明

### 本地开发

- 所有密码统一为 `admin123`（来自 `.env` 文件）
- API 服务: http://localhost:8000
- Web App: http://localhost:3010
- 默认账号: admin / admin123

### 生产部署

- 使用 docker-compose.yml 配置
- 环境变量在 .env 文件中配置

## 📝 注意事项

### 本地开发 vs 生产部署

**TARGET 配置差异**：
- 本地开发: `TARGET=http://localhost:8000`
- Docker Compose 部署: `TARGET=http://panda-wiki-api:8000`

**密码配置**：
- 本地开发使用 `admin123`（.env 文件）
- 生产环境请修改 .env 文件中的密码

## 🐛 故障排查

遇到问题？请查看：
1. [本地开发快速启动指南](LOCAL_DEV_QUICK_START.md) - 故障排查章节
2. 运行 `./check-local-dev.sh` 检查服务状态
3. 查看日志文件: `logs/api.log` 和 `logs/app.log`

## 📦 项目结构

```
PandaWiki/
├── backend/              # 后端 Go 代码
├── web/
│   ├── app/             # 前端应用（用户访问）
│   └── admin/           # 管理后台
├── scripts/             # 脚本工具
├── docs/                # 文档
└── deploy/              # 部署脚本
```

详细说明请查看 [项目结构文档](PROJECT_STRUCTURE.md)。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

请查看 [LICENSE](LICENSE) 文件。