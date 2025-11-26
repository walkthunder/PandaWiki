# 部署和备份系统总结

## ✅ 完成的工作

### 1. 创建安全部署脚本

**文件：** `deploy/safe-deploy.sh`

**功能：**
- 部署前自动备份数据库
- 确认操作提示
- 支持本地和远程部署
- 完整的错误处理

**使用：**
```bash
# 本地部署
./deploy/safe-deploy.sh local

# 远程部署
./deploy/safe-deploy.sh remote -h 8.140.221.27
```

### 2. 完整备份工具

**文件：** `scripts/backup-database-full.sh`

**功能：**
- 支持本地和远程备份
- 自动压缩备份文件
- 生成备份元数据（时间、大小、MD5）
- 自动清理旧备份
- 按月份组织备份文件

**使用：**
```bash
# 本地备份
./scripts/backup-database-full.sh --local

# 远程备份
./scripts/backup-database-full.sh --remote 8.140.221.27

# 列出备份
./scripts/backup-database-full.sh --list
```

### 3. 数据库恢复工具

**文件：** `scripts/restore-database.sh`

**功能：**
- 列出可用备份
- 显示备份信息
- 恢复前自动备份当前数据
- 支持本地和远程恢复
- 安全确认机制

**使用：**
```bash
# 列出备份
./scripts/restore-database.sh --list

# 恢复本地
./scripts/restore-database.sh backups/database/202511/backup.sql.gz

# 恢复远程
./scripts/restore-database.sh -r 8.140.221.27 backups/remote/backup.sql.gz
```

### 4. 部署文档

**文件：**
- `DEPLOYMENT_GUIDE.md` - 完整部署指南
- `DEPLOYMENT_QUICK_REF.md` - 快速参考

## 🛡️ 数据安全保障

### 自动备份机制

1. **部署前自动备份**
   - `safe-deploy.sh` 会在部署前自动备份
   - 可以选择跳过（不推荐）

2. **恢复前自动备份**
   - `restore-database.sh` 会在恢复前提示备份当前数据
   - 防止误操作导致数据丢失

3. **备份保留策略**
   - 默认保留最近 30 个备份
   - 可配置保留数量
   - 自动清理旧备份

### 备份文件组织

```
backups/
├── database/              # 本地备份
│   ├── 202511/           # 按月份组织
│   │   ├── panda-wiki_local_20251126_120000.sql.gz
│   │   └── panda-wiki_local_20251126_120000.sql.gz.meta
│   └── 202512/
└── remote/               # 远程备份
    ├── panda-wiki_remote_20251126_120000.sql.gz
    └── panda-wiki_remote_20251126_120000.sql.gz.meta
```

### 备份元数据

每个备份都有 `.meta` 文件：
```json
{
  "backup_file": "panda-wiki_local_20251126_120000.sql.gz",
  "timestamp": "20251126_120000",
  "date": "2025-11-26 12:00:00",
  "source": "local",
  "size": "2.5M",
  "md5": "abc123..."
}
```

## 📋 部署检查清单

### 部署前

- [ ] 备份数据库
- [ ] 检查磁盘空间
- [ ] 验证备份文件
- [ ] 通知团队
- [ ] 准备回滚方案

### 部署中

- [ ] 监控日志
- [ ] 检查服务状态
- [ ] 验证容器运行
- [ ] 记录问题

### 部署后

- [ ] 测试核心功能
- [ ] 检查数据完整性
- [ ] 验证 API 响应
- [ ] 更新文档

## 🔄 回滚流程

### 快速回滚

```bash
# 1. 列出备份
./scripts/restore-database.sh --list

# 2. 恢复数据库
./scripts/restore-database.sh backups/database/202511/backup.sql.gz

# 3. 重启服务
docker compose restart api consumer
```

### 完整回滚

```bash
# 1. 停止服务
docker compose down

# 2. 恢复数据库
./scripts/restore-database.sh <backup-file>

# 3. 回滚代码（如需要）
git checkout <previous-commit>

# 4. 重新部署
docker compose up -d
```

## 📊 部署流程对比

### 之前的流程

```bash
# 手动步骤多
1. 手动备份数据库
2. 运行 deploy/local-deploy.sh
3. 检查服务状态
4. 如果失败，手动恢复
```

**问题：**
- 容易忘记备份
- 没有自动验证
- 回滚困难

### 现在的流程

```bash
# 一键完成
./deploy/safe-deploy.sh local
```

**改进：**
- ✅ 自动备份数据库
- ✅ 确认操作提示
- ✅ 完整错误处理
- ✅ 备份记录和元数据
- ✅ 简单的恢复流程

## 🎯 最佳实践

### 1. 定期备份

```bash
# 添加到 crontab
0 2 * * * cd /path/to/PandaWiki && ./scripts/backup-database-full.sh --local
```

### 2. 部署前测试

```bash
# 在测试环境先验证
./deploy/safe-deploy.sh local

# 验证功能
curl http://localhost:8000/health
```

### 3. 保留重要备份

```bash
# 版本发布前的备份
cp backups/database/202511/backup.sql.gz backups/important/v1.0.0-pre.sql.gz
```

### 4. 验证备份

```bash
# 定期测试恢复流程
./scripts/restore-database.sh --list
```

## 🚨 紧急情况处理

### 数据丢失

```bash
# 1. 立即停止服务
docker compose down

# 2. 查找最近的备份
./scripts/restore-database.sh --list

# 3. 恢复数据库
./scripts/restore-database.sh <最近的备份>

# 4. 重启服务
docker compose up -d
```

### 部署失败

```bash
# 1. 查看日志
docker logs panda-wiki-api

# 2. 如果数据库有问题，恢复备份
./scripts/restore-database.sh <部署前的备份>

# 3. 回滚代码
git checkout <previous-commit>

# 4. 重新部署
./deploy/safe-deploy.sh local
```

## 📞 支持

遇到问题：
1. 查看 [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
2. 检查日志文件
3. 验证备份文件
4. 联系技术支持

## 🎉 总结

现在你有了：
- ✅ 安全的部署流程
- ✅ 自动备份机制
- ✅ 简单的恢复工具
- ✅ 完整的文档
- ✅ 最佳实践指南

**记住：部署前务必备份！** 🛡️
