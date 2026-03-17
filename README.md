# PandaWiki

PandaWiki 是一款 AI 驱动的开源知识库搭建系统。

> PandaWiki 是由 AI 大模型驱动的 Wiki 系统，在未配置大模型的情况下 AI 创作、AI 问答、AI 搜索 等功能无法正常使用。
> 
首次登录时会提示需要先配置 AI 模型，可自行选择一键配置或手动配置。

<div align="center">
  <img src="/images/model-config-1.png" width="800" />
  <p><em>一键自动配置 AI 模型</em></p>

  <img src="/images/model-config-2.png" width="800" />
  <p><em>手动自定义配置 AI 模型</em></p>
</div>

"知识库" 是一组文档的集合，PandaWiki 将会根据知识库中的文档，为不同的知识库分别创建 "Wiki 网站"。
<img src="/images/createkb.png" width="800" />

### 💪 开始使用

- 访问 **控制台** 来管理你的知识库并上传文档等待学习成功
- 访问 **Wiki 网站** 使用知识库并测试AI问答效果
<img src="/images/AI-QA.png" width="700" />

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

# 检查开发环境状态
./check-local-dev.sh

# 停止所有服务
./stop-local-dev.sh
```

### 生产部署

```bash
# 本地构建并传输
./deploy/local-deploy.sh

# 服务器重启
./deploy/remote-deploy.sh
```

### 运维管理

```bash
# 服务器巡检
./scripts/server-inspection.sh

# 数据备份
./scripts/backup-to-cos.sh

# 安全检查
./scripts/security-check.sh
```