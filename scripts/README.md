# PandaWiki 运维脚本

本目录包含 PandaWiki 项目的运维和管理脚本。

## 🔒 安全检查工具（新增）

### 文档安全检查脚本
用于检查生产环境中上传的文档是否包含敏感信息，防止数据泄露。

**脚本文件**:
- **security-check.sh** - Bash版本，快速检查文档名称
- **security_check.py** - Python版本，支持内容深度分析
- **scheduled-security-check.sh** - 定期自动检查脚本

**快速开始**:
```bash
# 检查所有文档
./scripts/security-check.sh --all

# 查看报告
cat security-reports/security_check_*.md

# 列出知识库
python3 scripts/security_check.py --list
```

**详细文档**:
- [安装配置指南](SECURITY_CHECK_SETUP.md)
- [使用说明](SECURITY_CHECK_README.md)
- [快速参考](../SECURITY_CHECK_QUICK_REF.md)

---

## 📋 脚本列表

### backup-to-cos.sh - 自动备份到腾讯云 COS

**功能**: 自动备份 PostgreSQL、MinIO、Qdrant 数据并上传到腾讯云对象存储

**使用方法**:

```bash
# 基本使用（从 .env 读取配置）
./scripts/backup-to-cos.sh

# 在服务器上执行（推荐）
ssh root@8.140.221.27 'cd /root && bash -s' < ./scripts/backup-to-cos.sh
```

**备份内容**:

- ✅ **PostgreSQL**: 完整数据库导出（约8MB，压缩后）
- ✅ **MinIO**: 对象存储数据（约1.3GB，包含所有文档和图片）
- ✅ **Qdrant**: 向量数据库（约368MB，AI检索数据）

**特点**:

- 🔒 **不停机备份**: 所有备份操作不影响服务运行
- ☁️ **云端存储**: 自动上传到腾讯云 COS，安全可靠
- 🗂️ **智能管理**: 本地保留7天（PostgreSQL）或3天（MinIO/Qdrant）
- 📊 **详细报告**: 生成备份报告，记录所有操作
- ⚡ **分块上传**: 大文件自动使用分块上传，提高成功率

**配置说明**:

脚本从 `.env` 文件读取以下配置:

```bash
# 数据库密码
POSTGRES_PASSWORD=your_password

# 腾讯云 COS 配置
TENCENTCLOUD_SECRET_ID=your_secret_id
TENCENTCLOUD_SECRET_KEY=your_secret_key
TENCENTCLOUD_COS_BUCKET=your_bucket
TENCENTCLOUD_COS_REGION=ap-beijing
```

**备份存储结构**:

```
本地备份:
./backups/
├── postgres/
│   └── 20251226/
│       └── postgres_20251226_120000.sql.gz
├── minio/
│   └── 20251226/
│       └── minio_20251226_120000.tar.gz
└── qdrant/
    └── 20251226/
        └── qdrant_20251226_120000.tar.gz

云端备份 (COS):
panda-wiki-backups/
└── 20251226/
    ├── postgres/
    │   └── postgres_20251226_120000.sql.gz
    ├── minio/
    │   └── minio_20251226_120000.tar.gz
    └── qdrant/
        └── qdrant_20251226_120000.tar.gz
```

**依赖安装**:

```bash
# 安装腾讯云 COS SDK
pip3 install cos-python-sdk-v5
```

**示例输出**:

```
==========================================
   PandaWiki 自动备份到腾讯云 COS
==========================================

[INFO] 加载环境变量配置...
[SUCCESS] 环境变量加载完成
[INFO] 检查依赖工具...
[SUCCESS] 依赖检查完成
[INFO] 开始备份 PostgreSQL 数据库...
[SUCCESS] PostgreSQL 备份完成: postgres_20251226_120000.sql.gz (大小: 8.1M)

[INFO] 开始备份 MinIO 对象存储...
[INFO] 正在压缩 MinIO 数据 (约1.3GB，可能需要几分钟)...
[SUCCESS] MinIO 备份完成: minio_20251226_120000.tar.gz (大小: 1.2G)

[INFO] 开始备份 Qdrant 向量数据库...
[SUCCESS] Qdrant 备份完成: qdrant_20251226_120000.tar.gz (大小: 350M)

[INFO] 开始上传备份文件到腾讯云 COS...
📤 开始上传: postgres_20251226_120000.sql.gz
   文件大小: 8.10 MB
   使用简单上传...
✅ 上传成功!

==========================================
           备份完成摘要
==========================================

备份时间: 2025-12-26 12:00:00
总耗时: 5分30秒

备份结果:
  PostgreSQL: ✅ 成功
  MinIO:      ✅ 成功
  Qdrant:     ✅ 成功

上传结果:
  成功: 3 个
  失败: 0 个

本地备份: ./backups
云端备份: cos://your-bucket/panda-wiki-backups/20251226/

[SUCCESS] 所有备份任务完成！
==========================================
```

**恢复数据**:

```bash
# 1. 从 COS 下载备份文件
# 可以通过腾讯云控制台或 COSCMD 工具下载

# 2. 恢复 PostgreSQL
gunzip postgres_20251226_120000.sql.gz
docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < postgres_20251226_120000.sql

# 3. 恢复 MinIO
docker compose stop minio
tar -xzf minio_20251226_120000.tar.gz -C ./data/
docker compose start minio

# 4. 恢复 Qdrant
docker compose stop qdrant
tar -xzf qdrant_20251226_120000.tar.gz -C ./data/
docker compose start qdrant
```

---

### server-inspection.sh - 服务器自动巡检

**功能**: 自动检测线上服务器状态并生成详细的巡检报告

**使用方法**:

```bash
# 基本使用 (使用默认配置)
./scripts/server-inspection.sh

# 自定义服务器配置
SERVER_IP=your.server.ip SERVER_USER=root ./scripts/server-inspection.sh

# 使用 SSH 密钥
SSH_KEY_PATH=~/.ssh/id_rsa ./scripts/server-inspection.sh
```

**配置说明**:

可以通过环境变量自定义配置:

```bash
export SERVER_IP="8.140.221.27"        # 服务器IP地址
export SERVER_USER="root"              # SSH 用户名
export PROJECT_PATH="/root"            # 项目路径
export SSH_KEY_PATH=""                 # SSH 密钥路径 (可选)
```

**生成的报告**:

- 报告位置: `./reports/server_inspection_YYYYMMDD_HHMMSS.md`
- 报告格式: Markdown
- 报告内容:
  - 系统资源状态 (磁盘、内存)
  - Docker 容器状态和资源使用
  - 安全性检查 (密码、配置)
  - 数据备份状态
  - 服务日志分析
  - 网络配置
  - 运维建议

**检查项目**:

- ✅ 磁盘空间使用率
- ✅ 内存使用率
- ✅ 容器运行状态
- ✅ 容器资源使用
- ✅ 数据备份情况
- ✅ 安全配置检查
- ✅ 服务日志分析
- ✅ 网络配置
- ✅ 健康度评分

**示例输出**:

```
==========================================
    PandaWiki 服务器自动巡检工具
==========================================

[INFO] 检查 SSH 连接到 root@8.140.221.27 ...
[SUCCESS] SSH 连接正常
[INFO] 收集系统资源信息...
[SUCCESS] 系统信息收集完成
[INFO] 收集 Docker 容器信息...
[SUCCESS] 容器信息收集完成 (运行中: 12/12)
...
[SUCCESS] 报告已生成: ./reports/server_inspection_20251226_120000.md

==========================================
           巡检完成摘要
==========================================

服务器: root@8.140.221.27
容器状态: 12/12 运行中
磁盘使用: 40% (✅ 正常)
内存使用: 58% (✅ 正常)
数据备份: 5 个 (✅ 正常)
安全状态: ⚠️ 使用默认密码

完整报告: ./reports/server_inspection_20251226_120000.md

[WARNING] 发现需要关注的问题，请查看完整报告
==========================================
```

## 🔧 故障排查

### SSH 连接失败

```bash
# 检查 SSH 连接
ssh root@8.140.221.27 "echo 'Connection OK'"

# 使用 SSH 密钥
ssh -i ~/.ssh/id_rsa root@8.140.221.27 "echo 'Connection OK'"
```

### 权限问题

```bash
# 确保脚本有执行权限
chmod +x scripts/server-inspection.sh
```

### 报告目录不存在

脚本会自动创建 `./reports` 目录，无需手动创建。

## 📅 建议使用频率

- **日常巡检**: 每周一次
- **重大变更前**: 部署前必须执行
- **故障排查**: 出现问题时立即执行
- **定期审计**: 每月生成报告存档

## 🔄 自动化运维

### 定时巡检

可以配置 cron 定时任务实现自动巡检:

```bash
# 编辑 crontab
crontab -e

# 每周一上午9点执行巡检
0 9 * * 1 cd /path/to/PandaWiki && ./scripts/server-inspection.sh

# 每天凌晨2点执行巡检
0 2 * * * cd /path/to/PandaWiki && ./scripts/server-inspection.sh
```

### 定时备份

**推荐配置**: 在服务器上配置定时备份任务

```bash
# 在服务器上编辑 crontab
ssh root@8.140.221.27
crontab -e

# 每天凌晨3点执行完整备份
0 3 * * * cd /root && /bin/bash /root/scripts/backup-to-cos.sh >> /root/logs/backup.log 2>&1

# 每周日凌晨4点执行完整备份（额外保险）
0 4 * * 0 cd /root && /bin/bash /root/scripts/backup-to-cos.sh >> /root/logs/backup_weekly.log 2>&1
```

**备份策略建议**:

- **每日备份**: PostgreSQL（数据量小，每天备份）
- **每周备份**: MinIO + Qdrant（数据量大，每周备份）
- **部署前备份**: 每次部署前自动备份（已在部署脚本中实现）

**分离备份脚本**（可选）:

如果想分别备份不同服务，可以修改脚本或创建多个版本:

```bash
# 仅备份 PostgreSQL（快速，每天）
./scripts/backup-to-cos.sh --only postgres

# 完整备份（慢，每周）
./scripts/backup-to-cos.sh
```

## 📧 报告通知

可以结合邮件或消息通知:

```bash
# 执行巡检并发送邮件
./scripts/server-inspection.sh && \
  mail -s "PandaWiki 巡检报告" admin@example.com < ./reports/server_inspection_*.md
```

## 🛡️ 安全建议

1. **保护 SSH 密钥**: 确保 SSH 密钥文件权限为 600
2. **限制脚本权限**: 脚本只需要读取权限，不需要写入服务器
3. **定期审查报告**: 及时发现和处理安全问题
4. **保存历史报告**: 用于趋势分析和问题追溯

## 📝 报告示例

查看 `SERVER_INSPECTION_REPORT.md` 了解完整的报告格式和内容。

## 🤝 贡献

欢迎提交改进建议和新功能！
