# 备份快速参考

## 🚀 快速开始

### 1. 部署备份脚本（首次）

```bash
./scripts/deploy-backup-script.sh
```

### 2. 配置定时任务

```bash
ssh root@8.140.221.27
crontab -e

# 添加：每天凌晨3点备份
0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1
```

### 3. 手动执行备份

```bash
ssh root@8.140.221.27 "cd /root && ./scripts/backup-to-cos.sh"
```

---

## 📋 常用命令

### 查看备份状态

```bash
# 查看备份日志
ssh root@8.140.221.27 "tail -50 /root/logs/backup.log"

# 查看本地备份文件
ssh root@8.140.221.27 "ls -lh /root/backups/postgres/"
ssh root@8.140.221.27 "ls -lh /root/backups/minio/"
ssh root@8.140.221.27 "ls -lh /root/backups/qdrant/"

# 查看磁盘空间
ssh root@8.140.221.27 "df -h"
```

### 手动备份单个服务

```bash
# 仅备份 PostgreSQL
ssh root@8.140.221.27 "docker exec -e PGPASSWORD='admin123' panda-wiki-postgres pg_dump -U panda-wiki -d panda-wiki | gzip > /root/postgres_manual.sql.gz"

# 仅备份 MinIO
ssh root@8.140.221.27 "cd /root && tar -czf minio_manual.tar.gz -C data minio"

# 仅备份 Qdrant
ssh root@8.140.221.27 "cd /root && tar -czf qdrant_manual.tar.gz -C data qdrant"
```

---

## 🔄 数据恢复

### PostgreSQL

```bash
# 1. 下载备份文件到本地
scp root@8.140.221.27:/root/backups/postgres/20251226/postgres_*.sql.gz ./

# 2. 上传到服务器（如果需要）
scp postgres_*.sql.gz root@8.140.221.27:/tmp/

# 3. 恢复
ssh root@8.140.221.27 "gunzip /tmp/postgres_*.sql.gz && docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < /tmp/postgres_*.sql"
```

### MinIO

```bash
# 1. 停止服务
ssh root@8.140.221.27 "docker compose -f /root/docker-compose.yml stop minio"

# 2. 恢复数据
ssh root@8.140.221.27 "cd /root && tar -xzf backups/minio/20251226/minio_*.tar.gz -C data/"

# 3. 启动服务
ssh root@8.140.221.27 "docker compose -f /root/docker-compose.yml start minio"
```

### Qdrant

```bash
# 1. 停止服务
ssh root@8.140.221.27 "docker compose -f /root/docker-compose.yml stop qdrant raglite"

# 2. 恢复数据
ssh root@8.140.221.27 "cd /root && tar -xzf backups/qdrant/20251226/qdrant_*.tar.gz -C data/"

# 3. 启动服务
ssh root@8.140.221.27 "docker compose -f /root/docker-compose.yml start qdrant raglite"
```

---

## 🔍 故障排查

### 备份失败

```bash
# 检查容器状态
ssh root@8.140.221.27 "docker ps"

# 检查磁盘空间
ssh root@8.140.221.27 "df -h"

# 检查环境变量
ssh root@8.140.221.27 "cat /root/.env | grep -E '(POSTGRES_PASSWORD|TENCENTCLOUD)'"

# 测试 COS 连接
ssh root@8.140.221.27 "python3 -c 'import qcloud_cos; print(\"OK\")'"
```

### 上传失败

```bash
# 检查网络
ssh root@8.140.221.27 "ping -c 3 cos.ap-beijing.myqcloud.com"

# 重新安装 COS SDK
ssh root@8.140.221.27 "pip3 install --upgrade cos-python-sdk-v5"

# 手动测试上传
ssh root@8.140.221.27 "cd /root && python3 scripts/upload_backup_to_cos.py --help"
```

---

## 📊 备份策略

| 服务 | 大小 | 频率 | 保留 | 重要性 |
|------|------|------|------|--------|
| PostgreSQL | ~8MB | 每天 | 7天 | 🔴 核心 |
| MinIO | ~1.3GB | 每周 | 3天 | 🔴 核心 |
| Qdrant | ~368MB | 每周 | 3天 | 🟡 重要 |

---

## 📞 紧急联系

- 备份脚本位置: `/root/scripts/backup-to-cos.sh`
- 备份日志: `/root/logs/backup.log`
- 本地备份: `/root/backups/`
- 云端备份: `cos://school-1253674045/panda-wiki-backups/`

---

**详细文档**: [BACKUP_GUIDE.md](BACKUP_GUIDE.md)
