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

### 安全相关 🔒
- [文档安全检查工具](docs/SECURITY_CHECK.md) - 检查上传文档是否包含敏感信息

### 运维相关
- [备份与恢复指南](BACKUP_GUIDE.md) - 数据备份和恢复完整方案
- [运维脚本说明](scripts/README.md) - 巡检和备份脚本使用
- [服务器巡检报告](SERVER_INSPECTION_REPORT.md) - 最新巡检结果

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

### 运维管理

```bash
# 服务器巡检
./scripts/server-inspection.sh

# 数据备份（需先部署到服务器）
./scripts/deploy-backup-script.sh  # 部署备份脚本
ssh root@8.140.221.27 "cd /root && ./scripts/backup-to-cos.sh"  # 执行备份
```

## 🔧 配置说明

本项目区分开发环境和生产环境的配置文件，详细说明请查看 [配置文件使用指南](CONFIG_GUIDE.md)。

### 配置文件结构

**后端配置**：
- `backend/config.yml` - 生产环境配置（不提交到 Git）
- `backend/config.dev.yml` - 开发环境配置（可提交）

**前端配置**：
- `web/app/.env` - 生产环境配置（不提交到 Git）
- `web/app/.env.dev` - 开发环境配置（可提交）

### 本地开发

启动脚本会自动使用开发环境配置：
- 后端使用 `backend/config.dev.yml`
- 前端使用 `web/app/.env.dev`
- 所有密码统一为 `admin123`
- API 服务: http://localhost:8000
- Web App: http://localhost:3010
- 默认账号: admin / admin123

### 生产部署

生产环境使用独立的配置文件：
- 后端使用 `backend/config.yml`（需手动创建）
- 前端使用 `web/app/.env`（需手动创建）
- 请修改所有默认密码

## 📝 注意事项

### 配置文件管理

1. **不要将生产配置提交到 Git**
   - `backend/config.yml` 和 `web/app/.env` 已在 `.gitignore` 中
   
2. **开发配置可以安全提交**
   - `backend/config.dev.yml` 和 `web/app/.env.dev` 不包含敏感信息

3. **首次部署**
   - 需要手动创建生产环境配置文件
   - 参考开发配置文件的格式，修改为生产环境的值

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