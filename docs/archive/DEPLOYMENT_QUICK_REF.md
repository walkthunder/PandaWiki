# 部署快速参考

## 🚀 快速部署

```bash
# 本地部署（自动备份）
./deploy/safe-deploy.sh local

# 远程部署（自动备份）
./deploy/safe-deploy.sh remote -h 8.140.221.27
```

## 💾 备份命令

```bash
# 本地备份
./scripts/backup-database-full.sh --local

# 远程备份
./scripts/backup-database-full.sh --remote 8.140.221.27

# 列出备份
./scripts/backup-database-full.sh --list
```

## 🔄 恢复命令

```bash
# 列出可用备份
./scripts/restore-database.sh --list

# 恢复本地
./scripts/restore-database.sh backups/database/202511/backup.sql.gz

# 恢复远程
./scripts/restore-database.sh -r 8.140.221.27 backups/remote/backup.sql.gz
```

## 📁 备份位置

```
backups/
├── database/    # 本地备份
└── remote/      # 远程备份
```

## ⚠️ 重要提示

1. **部署前必须备份**
2. **验证备份文件**
3. **保留多个备份**
4. **测试恢复流程**

## 🔍 检查命令

```bash
# 检查服务
docker ps

# 查看日志
docker logs panda-wiki-api

# 测试 API
curl http://localhost:8000/health
```

## 📚 详细文档

查看 [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) 获取完整指南。
