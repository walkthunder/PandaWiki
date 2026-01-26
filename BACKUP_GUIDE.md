# PandaWiki 备份与恢复指南

本文档提供 PandaWiki 系统的完整备份和恢复方案。

---

## 📋 目录

- [备份策略](#备份策略)
- [快速开始](#快速开始)
- [自动备份配置](#自动备份配置)
- [手动备份](#手动备份)
- [数据恢复](#数据恢复)
- [故障排查](#故障排查)

---

## 🎯 备份策略

### 备份内容

| 数据类型 | 大小 | 重要性 | 备份频率 | 保留时间 |
|---------|------|--------|---------|---------|
| **PostgreSQL** | ~8MB | 🔴 核心 | 每天 | 7天 |
| **MinIO** | ~1.3GB | 🔴 核心 | 每周 | 3天 |
| **Qdrant** | ~368MB | 🟡 重要 | 每周 | 3天 |

### 备份方式

- **自动备份**: 通过 cron 定时任务自动执行
- **手动备份**: 部署前或重大变更前手动执行
- **云端存储**: 所有备份自动上传到腾讯云 COS

### 备份特点

- ✅ **不停机备份**: 所有备份操作不影响服务运行
- ✅ **增量友好**: PostgreSQL 每天备份，MinIO/Qdrant 每周备份
- ✅ **云端同步**: 自动上传到腾讯云 COS，异地容灾
- ✅ **智能清理**: 本地自动清理过期备份，节省空间

---

## 🚀 快速开始

### 1. 部署备份脚本到服务器

```bash
# 在本地执行
./scripts/deploy-backup-script.sh
```

这个脚本会：
- 上传备份脚本到服务器
- 安装必要的依赖（腾讯云 COS SDK）
- 设置执行权限
- 提供 crontab 配置建议

### 2. 配置环境变量

确保服务器上的 `.env` 文件包含以下配置：

```bash
# 数据库密码
POSTGRES_PASSWORD=your_password

# 腾讯云 COS 配置
TENCENTCLOUD_SECRET_ID=your_secret_id
TENCENTCLOUD_SECRET_KEY=your_secret_key
TENCENTCLOUD_COS_BUCKET=your_bucket
TENCENTCLOUD_COS_REGION=ap-beijing
```

### 3. 测试备份

```bash
# SSH 到服务器
ssh root@8.140.221.27

# 执行一次测试备份
cd /root
./scripts/backup-to-cos.sh
```

### 4. 配置定时任务

```bash
# 在服务器上编辑 crontab
crontab -e

# 添加以下行
# 每天凌晨3点执行完整备份
0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1

# 每周日凌晨4点执行完整备份（额外保险）
0 4 * * 0 cd /root && bash scripts/backup-to-cos.sh >> logs/backup_weekly.log 2>&1
```

---

## ⚙️ 自动备份配置

### 推荐配置方案

#### 方案一：每日完整备份（简单）

```bash
# 每天凌晨3点备份所有数据
0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1
```

**优点**: 配置简单，数据最新  
**缺点**: 每天备份 MinIO (1.3GB) 较慢

#### 方案二：分离备份（推荐）

```bash
# 每天凌晨3点备份 PostgreSQL（快速）
0 3 * * * cd /root && bash scripts/backup-to-cos.sh --only postgres >> logs/backup_daily.log 2>&1

# 每周日凌晨4点备份所有数据（完整）
0 4 * * 0 cd /root && bash scripts/backup-to-cos.sh >> logs/backup_weekly.log 2>&1
```

**优点**: 平衡速度和完整性  
**缺点**: 需要修改脚本支持 `--only` 参数

#### 方案三：部署前备份（已实现）

部署脚本 `deploy/remote-deploy.sh` 已包含自动备份：

```bash
# 每次部署前自动备份 PostgreSQL
./deploy/local-deploy.sh  # 会自动触发备份
```

### 查看备份日志

```bash
# 查看最近的备份日志
ssh root@8.140.221.27 "tail -100 /root/logs/backup.log"

# 查看所有备份文件
ssh root@8.140.221.27 "ls -lh /root/backups/postgres/"
ssh root@8.140.221.27 "ls -lh /root/backups/minio/"
ssh root@8.140.221.27 "ls -lh /root/backups/qdrant/"
```

---

## 🔧 手动备份

### 完整备份

```bash
# SSH 到服务器
ssh root@8.140.221.27

# 执行完整备份
cd /root
./scripts/backup-to-cos.sh
```

### 仅备份 PostgreSQL（快速）

```bash
# 在服务器上执行
docker exec -e PGPASSWORD="your_password" panda-wiki-postgres \
    pg_dump -U panda-wiki -d panda-wiki \
    --format=plain --no-owner --no-acl | gzip > postgres_manual_$(date +%Y%m%d_%H%M%S).sql.gz
```

### 仅备份 MinIO

```bash
# 在服务器上执行
cd /root
tar -czf minio_manual_$(date +%Y%m%d_%H%M%S).tar.gz -C data minio
```

### 仅备份 Qdrant

```bash
# 在服务器上执行
cd /root
tar -czf qdrant_manual_$(date +%Y%m%d_%H%M%S).tar.gz -C data qdrant
```

---

## 🔄 数据恢复

### 恢复前准备

⚠️ **重要**: 恢复数据前请先备份当前数据！

```bash
# 1. 停止相关服务（可选，但推荐）
docker compose stop api consumer app

# 2. 备份当前数据
./scripts/backup-to-cos.sh
```

### 恢复 PostgreSQL

```bash
# 1. 从 COS 下载备份文件（或使用本地备份）
# 可以通过腾讯云控制台下载，或使用 COSCMD 工具

# 2. 解压备份文件
gunzip postgres_20251226_120000.sql.gz

# 3. 恢复数据库
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < postgres_20251226_120000.sql

# 4. 重启服务
docker compose restart api consumer
```

### 恢复 MinIO

```bash
# 1. 停止 MinIO 服务
docker compose stop minio

# 2. 备份当前数据（可选）
mv data/minio data/minio.backup

# 3. 解压备份文件
tar -xzf minio_20251226_120000.tar.gz -C data/

# 4. 启动 MinIO 服务
docker compose start minio

# 5. 验证数据
docker compose logs minio
```

### 恢复 Qdrant

```bash
# 1. 停止 Qdrant 服务
docker compose stop qdrant raglite

# 2. 备份当前数据（可选）
mv data/qdrant data/qdrant.backup

# 3. 解压备份文件
tar -xzf qdrant_20251226_120000.tar.gz -C data/

# 4. 启动 Qdrant 服务
docker compose start qdrant raglite

# 5. 验证数据
docker compose logs qdrant
```

### 完整恢复流程

```bash
# 1. 停止所有服务
docker compose down

# 2. 恢复 PostgreSQL
gunzip postgres_backup.sql.gz
docker compose up -d postgres
sleep 10
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < postgres_backup.sql

# 3. 恢复 MinIO
tar -xzf minio_backup.tar.gz -C data/

# 4. 恢复 Qdrant
tar -xzf qdrant_backup.tar.gz -C data/

# 5. 启动所有服务
docker compose up -d

# 6. 检查服务状态
docker compose ps
docker compose logs -f
```

---

## 🔍 故障排查

### 备份失败

#### 问题：PostgreSQL 备份失败

```bash
# 检查容器状态
docker ps | grep postgres

# 检查数据库连接
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "SELECT 1"

# 检查密码配置
cat .env | grep POSTGRES_PASSWORD
```

#### 问题：MinIO/Qdrant 备份失败

```bash
# 检查数据目录权限
ls -la data/minio
ls -la data/qdrant

# 检查磁盘空间
df -h
```

#### 问题：上传到 COS 失败

```bash
# 检查网络连接
ping cos.ap-beijing.myqcloud.com

# 检查 COS 配置
cat .env | grep TENCENTCLOUD

# 测试 COS SDK
python3 -c "import qcloud_cos; print('COS SDK OK')"

# 手动测试上传
python3 scripts/upload_backup_to_cos.py --help
```

### 恢复失败

#### 问题：PostgreSQL 恢复失败

```bash
# 检查备份文件完整性
gunzip -t postgres_backup.sql.gz

# 查看备份文件内容
gunzip -c postgres_backup.sql.gz | head -20

# 清空数据库后重试
docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```

#### 问题：MinIO/Qdrant 恢复后数据不正确

```bash
# 检查解压后的文件
ls -la data/minio/
ls -la data/qdrant/

# 检查文件权限
chown -R systemd-coredump:root data/minio
chown -R systemd-coredump:root data/qdrant

# 重启服务
docker compose restart minio qdrant raglite
```

### 查看备份状态

```bash
# 查看本地备份
ls -lh backups/postgres/
ls -lh backups/minio/
ls -lh backups/qdrant/

# 查看 COS 备份（需要安装 COSCMD）
coscmd list panda-wiki-backups/

# 查看备份日志
tail -100 logs/backup.log
```

---

## 📊 备份监控

### 检查备份是否正常运行

```bash
# 检查 crontab 配置
crontab -l

# 查看最近的备份日志
tail -50 /root/logs/backup.log

# 检查最新备份文件
ls -lt /root/backups/postgres/ | head -5
```

### 备份告警（可选）

可以配置备份失败时发送告警：

```bash
# 修改 crontab，添加邮件通知
0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1 || echo "Backup failed" | mail -s "PandaWiki Backup Failed" admin@example.com
```

---

## 📝 最佳实践

### 1. 定期测试恢复

**建议**: 每月测试一次完整恢复流程

```bash
# 在测试环境恢复备份
# 验证数据完整性
# 记录恢复时间
```

### 2. 多地备份

**建议**: 除了腾讯云 COS，还可以：
- 定期下载备份到本地
- 同步到其他云存储（阿里云 OSS、AWS S3）
- 使用 NAS 或外部硬盘存储

### 3. 监控备份大小

**建议**: 定期检查备份文件大小变化

```bash
# 查看备份大小趋势
du -sh backups/postgres/* | tail -10
du -sh backups/minio/* | tail -10
```

异常增长可能表示：
- 数据量正常增长
- 数据冗余或垃圾数据
- 需要清理或优化

### 4. 文档化恢复流程

**建议**: 将恢复流程文档化，确保团队成员都能执行

### 5. 备份加密（可选）

对于敏感数据，可以在上传前加密：

```bash
# 加密备份文件
gpg --symmetric --cipher-algo AES256 postgres_backup.sql.gz

# 解密备份文件
gpg --decrypt postgres_backup.sql.gz.gpg > postgres_backup.sql.gz
```

---

## 🔗 相关文档

- [服务器巡检指南](scripts/README.md#server-inspectionsh---服务器自动巡检)
- [部署指南](deploy/README.md)
- [配置指南](CONFIG_GUIDE.md)

---

## 📞 支持

如有问题，请：
1. 查看 [故障排查](#故障排查) 章节
2. 检查备份日志: `logs/backup.log`
3. 联系运维团队

---

**最后更新**: 2025-12-26  
**维护者**: PandaWiki 运维团队
