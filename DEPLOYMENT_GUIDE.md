# PandaWiki 部署指南

## 🚀 安全部署流程

### 快速开始

```bash
# 本地部署（自动备份）
./deploy/safe-deploy.sh local

# 远程部署（自动备份）
./deploy/safe-deploy.sh remote -h 8.140.221.27
```

## 📋 部署前准备

### 1. 检查环境

```bash
# 检查 Docker
docker --version

# 检查连接（远程部署）
ssh root@8.140.221.27 "echo 'Connection OK'"
```

### 2. 备份数据库

**强烈建议在部署前手动备份数据库！**

```bash
# 本地备份
./scripts/backup-database-full.sh --local

# 远程备份
./scripts/backup-database-full.sh --remote 8.140.221.27
```

## 🛡️ 安全部署

### 使用安全部署脚本（推荐）

安全部署脚本会自动：
1. 备份数据库
2. 确认部署操作
3. 执行部署
4. 保存备份记录

```bash
# 本地部署
./deploy/safe-deploy.sh local

# 远程部署
./deploy/safe-deploy.sh remote \
  --host 8.140.221.27 \
  --user root \
  --path /root

# 跳过备份（不推荐）
./deploy/safe-deploy.sh remote --skip-backup
```

### 环境变量配置

```bash
# 设置环境变量
export REMOTE_HOST=8.140.221.27
export REMOTE_USER=root
export REMOTE_PATH=/root

# 执行部署
./deploy/safe-deploy.sh remote
```

## 💾 数据库备份

### 完整备份工具

```bash
# 本地备份
./scripts/backup-database-full.sh --local

# 远程备份
./scripts/backup-database-full.sh \
  --remote 8.140.221.27 \
  --user root \
  --path /root

# 保留最近 60 个备份
./scripts/backup-database-full.sh --local --keep 60

# 列出所有备份
./scripts/backup-database-full.sh --list
```

### 备份文件位置

```
backups/
├── database/           # 本地备份
│   └── 202511/        # 按月份组织
│       ├── panda-wiki_local_20251126_120000.sql.gz
│       └── panda-wiki_local_20251126_120000.sql.gz.meta
└── remote/            # 远程备份
    ├── panda-wiki_remote_20251126_120000.sql.gz
    └── panda-wiki_remote_20251126_120000.sql.gz.meta
```

### 备份元数据

每个备份都有对应的 `.meta` 文件，包含：
- 备份时间
- 文件大小
- MD5 校验和
- 来源信息

## 🔄 数据库恢复

### 恢复工具

```bash
# 列出可用备份
./scripts/restore-database.sh --list

# 恢复到本地
./scripts/restore-database.sh \
  backups/database/202511/panda-wiki_local_20251126_120000.sql.gz

# 恢复到远程
./scripts/restore-database.sh \
  --remote 8.140.221.27 \
  --user root \
  backups/remote/panda-wiki_remote_20251126_120000.sql.gz

# 强制恢复（不提示确认）
./scripts/restore-database.sh --force backup.sql.gz
```

### 恢复流程

1. 工具会显示备份文件信息
2. 提示确认操作
3. 建议先备份当前数据库
4. 执行恢复
5. 验证结果

## 📦 部署类型

### 本地部署

适用于：
- 开发环境
- 测试环境
- 本地服务器

```bash
./deploy/safe-deploy.sh local
```

### 远程部署

适用于：
- 生产环境
- 远程服务器

```bash
./deploy/safe-deploy.sh remote -h 8.140.221.27
```

## 🔍 部署检查

### 部署前检查

```bash
# 检查服务状态
docker ps

# 检查磁盘空间
df -h

# 检查备份目录
ls -lh backups/database/
```

### 部署后验证

```bash
# 检查容器状态
docker ps | grep panda-wiki

# 检查日志
docker logs panda-wiki-api

# 测试 API
curl http://localhost:8000/health

# 测试管理后台
curl http://localhost:5173
```

## ⚠️ 注意事项

### 数据安全

1. **始终备份**：部署前务必备份数据库
2. **验证备份**：确保备份文件完整且可恢复
3. **保留多个备份**：建议保留至少 30 天的备份
4. **异地备份**：定期将备份文件复制到其他位置

### 部署安全

1. **测试环境**：先在测试环境验证
2. **低峰期部署**：选择用户较少的时间段
3. **回滚准备**：准备好回滚方案
4. **监控告警**：部署后密切监控服务状态

### 常见问题

#### 1. 备份失败

```bash
# 检查容器状态
docker ps | grep postgres

# 检查磁盘空间
df -h

# 手动备份
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > backup.sql
```

#### 2. 恢复失败

```bash
# 检查备份文件
gunzip -t backup.sql.gz

# 查看错误日志
docker logs panda-wiki-postgres

# 手动恢复
gunzip -c backup.sql.gz | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki
```

#### 3. 部署失败

```bash
# 查看容器日志
docker logs panda-wiki-api

# 回滚到之前的版本
docker compose down
docker compose up -d

# 恢复数据库
./scripts/restore-database.sh <backup-file>
```

## 📊 备份策略建议

### 自动备份

```bash
# 添加到 crontab
# 每天凌晨 2 点备份
0 2 * * * cd /path/to/PandaWiki && ./scripts/backup-database-full.sh --local

# 每周日凌晨 3 点备份远程
0 3 * * 0 cd /path/to/PandaWiki && ./scripts/backup-database-full.sh --remote 8.140.221.27
```

### 备份保留策略

- **每日备份**：保留 7 天
- **每周备份**：保留 4 周
- **每月备份**：保留 12 个月
- **重要节点**：永久保留（如版本发布前）

## 🔗 相关文档

- [快速开始](README_DEV.md)
- [数据库迁移](DATABASE_MIGRATION_GUIDE.md)
- [开发指南](DEVELOPMENT.md)

## 📞 紧急联系

如遇紧急问题：
1. 立即停止部署
2. 检查备份文件
3. 查看错误日志
4. 准备回滚方案

## 🎯 最佳实践

1. **部署前**：
   - 备份数据库
   - 通知团队
   - 准备回滚方案

2. **部署中**：
   - 监控日志
   - 验证服务
   - 记录问题

3. **部署后**：
   - 验证功能
   - 检查性能
   - 更新文档
