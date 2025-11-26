# 数据库迁移指南 - original_url 字段

## 📋 迁移概述

**迁移内容**：为 `nodes` 表添加 `original_url` 字段

**迁移文件**：
- `backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql`
- `backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql`

**影响范围**：
- 表：`nodes`
- 操作：添加新字段（非破坏性操作）
- 数据安全：✅ 不会丢失任何现有数据

---

## 🔒 安全保证

### 1. 迁移特点

- ✅ **非破坏性**：只添加新字段，不修改或删除现有字段
- ✅ **有默认值**：新字段默认值为空字符串 `''`
- ✅ **可回滚**：提供了 down 迁移文件
- ✅ **幂等性**：使用 `IF NOT EXISTS`，可以安全地重复执行

### 2. SQL 语句

```sql
-- 添加字段（安全）
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';

-- 回滚（如果需要）
ALTER TABLE nodes DROP COLUMN IF EXISTS original_url;
```

---

## 🚀 迁移流程

### 方式一：自动迁移（推荐）

#### 本地开发环境

```bash
# 1. 停止后端服务（如果正在运行）
# Ctrl+C 停止 ./run-api.sh

# 2. 重新启动后端（会自动运行迁移）
./run-api.sh
```

后端启动时会自动检测并运行新的迁移文件。

#### 生产环境

```bash
# 1. 备份数据库（重要！）
./scripts/backup-database.sh

# 2. 部署新版本
./deploy/local-deploy.sh
./deploy/remote-deploy.sh

# 3. 服务重启时会自动运行迁移
```

---

### 方式二：手动迁移（更安全）

如果你想更谨慎地控制迁移过程：

#### 步骤 1: 备份数据库

```bash
# 本地环境
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > backup_$(date +%Y%m%d_%H%M%S).sql

# 生产环境（SSH 到服务器后执行）
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > backup_$(date +%Y%m%d_%H%M%S).sql
```

#### 步骤 2: 验证备份

```bash
# 检查备份文件大小（应该大于 0）
ls -lh backup_*.sql

# 查看备份文件前几行
head -20 backup_*.sql
```

#### 步骤 3: 执行迁移

**本地环境：**

```bash
# 方式 A: 使用迁移脚本（推荐）
./scripts/migrate-database.sh

# 方式 B: 手动执行 SQL
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql
```

**生产环境：**

```bash
# SSH 到服务器后执行
cd /path/to/panda-wiki

# 方式 A: 使用迁移脚本
./scripts/migrate-database.sh

# 方式 B: 手动执行 SQL
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql
```

#### 步骤 4: 验证迁移

```bash
# 检查字段是否添加成功
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url

# 预期输出：
# original_url | text | | | ''::text
```

#### 步骤 5: 测试功能

```bash
# 重启后端服务
./run-api.sh  # 本地
# 或
docker restart panda-wiki-api  # 生产环境

# 测试创建文档功能
# 在管理后台创建一个文档，确认没有错误
```

---

## 🔄 回滚流程（如果需要）

如果迁移后发现问题，可以安全回滚：

### 步骤 1: 停止服务

```bash
# 本地
# Ctrl+C 停止 ./run-api.sh

# 生产环境
docker stop panda-wiki-api panda-wiki-consumer
```

### 步骤 2: 执行回滚

```bash
# 本地
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql

# 生产环境（SSH 到服务器）
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql
```

### 步骤 3: 验证回滚

```bash
# 检查字段是否已删除
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url

# 预期输出：无输出（字段已删除）
```

### 步骤 4: 恢复代码

```bash
# 切换到没有 original_url 字段的代码版本
git checkout <previous-commit>

# 重启服务
./run-api.sh  # 本地
# 或
docker start panda-wiki-api panda-wiki-consumer  # 生产环境
```

---

## 📊 迁移检查清单

### 迁移前

- [ ] 已备份数据库
- [ ] 已验证备份文件
- [ ] 已通知团队成员（生产环境）
- [ ] 已在测试环境验证迁移

### 迁移中

- [ ] 执行迁移 SQL
- [ ] 检查迁移日志无错误
- [ ] 验证字段已添加

### 迁移后

- [ ] 重启后端服务
- [ ] 测试创建文档功能
- [ ] 测试编辑文档功能
- [ ] 检查后端日志无错误
- [ ] 监控系统运行状态

---

## 🛠️ 故障排查

### 问题 1: 迁移执行失败

**错误信息**：`column "original_url" already exists`

**原因**：字段已经存在（可能之前手动添加过）

**解决方案**：
```bash
# 检查字段是否存在
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url

# 如果存在，迁移已完成，无需操作
```

### 问题 2: 创建文档时报错 "invalid field"

**原因**：代码已更新但数据库未迁移

**解决方案**：
```bash
# 执行迁移
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql

# 重启服务
./run-api.sh
```

### 问题 3: 需要恢复备份

**场景**：迁移后出现严重问题，需要恢复到迁移前状态

**解决方案**：
```bash
# 1. 停止所有服务
docker stop panda-wiki-api panda-wiki-consumer

# 2. 恢复数据库
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backup_YYYYMMDD_HHMMSS.sql

# 3. 切换到旧版本代码
git checkout <previous-commit>

# 4. 重启服务
docker start panda-wiki-api panda-wiki-consumer
```

---

## 📞 获取帮助

如果遇到问题：

1. 查看后端日志：
   ```bash
   # 本地
   ./run-api.sh
   
   # 生产环境
   docker logs panda-wiki-api -f
   ```

2. 查看数据库日志：
   ```bash
   docker logs panda-wiki-postgres -f
   ```

3. 检查数据库连接：
   ```bash
   docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki
   ```

4. 联系技术支持或在 GitHub 提 Issue

---

## ✅ 迁移完成确认

迁移成功的标志：

1. ✅ 字段已添加到数据库
   ```bash
   docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url
   ```

2. ✅ 后端服务正常启动，无错误日志

3. ✅ 可以正常创建和编辑文档

4. ✅ 管理后台功能正常

恭喜！迁移完成！🎉
