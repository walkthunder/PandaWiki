# 数据库迁移快速参考

## 🎯 一键迁移（推荐）

```bash
# 自动备份 + 迁移 + 验证
./scripts/migrate-database.sh
```

---

## 📋 常用命令

### 备份数据库

```bash
# 创建备份
./scripts/backup-database.sh

# 手动备份
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > backup.sql
```

### 执行迁移

```bash
# 使用脚本（推荐）
./scripts/migrate-database.sh

# 手动执行
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql
```

### 验证迁移

```bash
# 检查字段是否存在
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url

# 预期输出：
# original_url | text | | | ''::text
```

### 回滚迁移

```bash
# 使用脚本
./scripts/rollback-migration.sh

# 手动回滚
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql
```

### 恢复备份

```bash
# 从备份恢复
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backup.sql

# 从压缩备份恢复
gunzip -c backup.sql.gz | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki
```

---

## 🚀 生产环境迁移流程

### 1. 准备阶段

```bash
# SSH 到服务器
ssh user@your-server

# 进入项目目录
cd /path/to/panda-wiki

# 拉取最新代码
git pull origin main
```

### 2. 备份阶段

```bash
# 创建备份
./scripts/backup-database.sh

# 验证备份
ls -lh backups/
```

### 3. 迁移阶段

```bash
# 执行迁移
./scripts/migrate-database.sh

# 或者通过部署脚本（会自动迁移）
./deploy/local-deploy.sh
./deploy/remote-deploy.sh
```

### 4. 验证阶段

```bash
# 检查服务状态
docker ps

# 查看后端日志
docker logs panda-wiki-api -f

# 测试功能
# 访问管理后台，创建文档
```

---

## ⚠️ 注意事项

### 安全保证

- ✅ 迁移前自动备份
- ✅ 非破坏性操作（只添加字段）
- ✅ 可以安全回滚
- ✅ 幂等性（可重复执行）

### 数据安全

- ✅ 不会丢失任何现有数据
- ✅ 新字段有默认值
- ✅ 不影响现有功能

### 停机时间

- ✅ 本地开发：无需停机
- ✅ 生产环境：建议在低峰期执行
- ⏱️ 预计耗时：< 1 秒（取决于数据量）

---

## 🐛 故障排查

### 问题：字段已存在

```bash
# 检查字段
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url

# 如果存在，说明迁移已完成
```

### 问题：迁移失败

```bash
# 查看数据库日志
docker logs panda-wiki-postgres

# 恢复备份
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backup.sql
```

### 问题：服务启动失败

```bash
# 查看后端日志
docker logs panda-wiki-api

# 检查数据库连接
docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki
```

---

## 📞 获取帮助

详细文档：[DATABASE_MIGRATION_GUIDE.md](DATABASE_MIGRATION_GUIDE.md)

---

## ✅ 检查清单

迁移前：
- [ ] 已备份数据库
- [ ] 已验证备份文件
- [ ] 已通知团队（生产环境）

迁移后：
- [ ] 字段已添加
- [ ] 服务正常运行
- [ ] 功能测试通过
- [ ] 日志无错误
