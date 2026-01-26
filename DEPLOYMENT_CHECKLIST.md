# 备份系统部署检查清单

使用此清单确保备份系统正确部署到生产环境。

---

## 📋 部署前检查

### 1. 本地准备

- [ ] 确认脚本文件存在
  ```bash
  ls -l scripts/backup-to-cos.sh
  ls -l scripts/upload_backup_to_cos.py
  ls -l scripts/deploy-backup-script.sh
  ```

- [ ] 确认脚本有执行权限
  ```bash
  chmod +x scripts/*.sh scripts/*.py
  ```

- [ ] 确认 .env 配置正确
  ```bash
  cat .env | grep TENCENTCLOUD
  ```

### 2. 服务器连接

- [ ] 测试 SSH 连接
  ```bash
  ssh root@8.140.221.27 "echo 'Connection OK'"
  ```

- [ ] 检查服务器磁盘空间
  ```bash
  ssh root@8.140.221.27 "df -h"
  ```

---

## 🚀 部署步骤

### 步骤 1: 部署脚本

- [ ] 执行部署脚本
  ```bash
  ./scripts/deploy-backup-script.sh
  ```

- [ ] 确认文件已上传
  ```bash
  ssh root@8.140.221.27 "ls -l /root/scripts/"
  ```

### 步骤 2: 安装依赖

- [ ] 检查 Python3
  ```bash
  ssh root@8.140.221.27 "python3 --version"
  ```

- [ ] 安装 COS SDK
  ```bash
  ssh root@8.140.221.27 "pip3 install cos-python-sdk-v5"
  ```

- [ ] 验证安装
  ```bash
  ssh root@8.140.221.27 "python3 -c 'import qcloud_cos; print(\"OK\")'"
  ```

### 步骤 3: 配置环境变量

- [ ] 检查服务器 .env 文件
  ```bash
  ssh root@8.140.221.27 "cat /root/.env | grep TENCENTCLOUD"
  ```

- [ ] 确认所有必要变量存在
  - POSTGRES_PASSWORD
  - TENCENTCLOUD_SECRET_ID
  - TENCENTCLOUD_SECRET_KEY
  - TENCENTCLOUD_COS_BUCKET
  - TENCENTCLOUD_COS_REGION

### 步骤 4: 测试备份

- [ ] 执行测试备份
  ```bash
  ssh root@8.140.221.27 "cd /root && ./scripts/backup-to-cos.sh"
  ```

- [ ] 检查备份文件
  ```bash
  ssh root@8.140.221.27 "ls -lh /root/backups/postgres/"
  ssh root@8.140.221.27 "ls -lh /root/backups/minio/"
  ssh root@8.140.221.27 "ls -lh /root/backups/qdrant/"
  ```

- [ ] 验证 COS 上传
  - 登录腾讯云控制台
  - 检查 bucket: school-1253674045
  - 查看路径: panda-wiki-backups/

### 步骤 5: 配置定时任务

- [ ] 编辑 crontab
  ```bash
  ssh root@8.140.221.27
  crontab -e
  ```

- [ ] 添加定时任务
  ```bash
  # 每天凌晨3点执行完整备份
  0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1
  ```

- [ ] 验证 crontab
  ```bash
  crontab -l
  ```

---

## ✅ 部署后验证

### 1. 功能验证

- [ ] 手动执行备份成功
- [ ] PostgreSQL 备份文件生成
- [ ] MinIO 备份文件生成
- [ ] Qdrant 备份文件生成
- [ ] 文件成功上传到 COS
- [ ] 备份日志正常

### 2. 日志检查

- [ ] 查看备份日志
  ```bash
  ssh root@8.140.221.27 "tail -50 /root/logs/backup.log"
  ```

- [ ] 确认无错误信息

### 3. 存储检查

- [ ] 本地备份目录存在
  ```bash
  ssh root@8.140.221.27 "du -sh /root/backups/*"
  ```

- [ ] COS 存储正常
  - 登录腾讯云控制台验证

### 4. 定时任务验证

- [ ] 等待定时任务执行（第二天检查）
- [ ] 检查日志文件更新时间
- [ ] 验证新的备份文件生成

---

## 📊 监控设置

### 1. 日志监控

- [ ] 配置日志轮转
  ```bash
  # 创建 logrotate 配置
  sudo vim /etc/logrotate.d/panda-wiki-backup
  ```

- [ ] 添加配置
  ```
  /root/logs/backup.log {
      daily
      rotate 7
      compress
      missingok
      notifempty
  }
  ```

### 2. 告警配置（可选）

- [ ] 配置备份失败告警
  ```bash
  # 修改 crontab，添加邮件通知
  0 3 * * * cd /root && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1 || echo "Backup failed" | mail -s "PandaWiki Backup Failed" admin@example.com
  ```

### 3. 定期检查

- [ ] 每周检查备份状态
- [ ] 每月测试恢复流程
- [ ] 每季度审查备份策略

---

## 🔍 故障排查

### 常见问题

#### 问题 1: pip3 安装失败

```bash
# 解决方案
ssh root@8.140.221.27 "pip3 install --break-system-packages cos-python-sdk-v5"
```

#### 问题 2: 权限错误

```bash
# 解决方案
ssh root@8.140.221.27 "chmod +x /root/scripts/*.sh /root/scripts/*.py"
```

#### 问题 3: 磁盘空间不足

```bash
# 检查磁盘空间
ssh root@8.140.221.27 "df -h"

# 清理旧备份
ssh root@8.140.221.27 "find /root/backups -type f -mtime +7 -delete"
```

#### 问题 4: COS 上传失败

```bash
# 检查网络
ssh root@8.140.221.27 "ping -c 3 cos.ap-beijing.myqcloud.com"

# 检查凭证
ssh root@8.140.221.27 "cat /root/.env | grep TENCENTCLOUD"

# 测试上传
ssh root@8.140.221.27 "python3 /root/scripts/upload_backup_to_cos.py --help"
```

---

## 📝 部署记录

### 部署信息

- **部署日期**: _______________
- **部署人员**: _______________
- **服务器IP**: 8.140.221.27
- **备份路径**: /root/backups/
- **COS Bucket**: school-1253674045
- **COS Region**: ap-beijing

### 验证签名

- [ ] 所有检查项已完成
- [ ] 测试备份成功
- [ ] 定时任务已配置
- [ ] 文档已更新

**签名**: _______________  
**日期**: _______________

---

## 📚 相关文档

- [备份指南](BACKUP_GUIDE.md)
- [快速参考](BACKUP_QUICK_REF.md)
- [测试报告](TEST_UPLOAD_REPORT.md)
- [脚本说明](scripts/README.md)

---

## 🎯 下一步

部署完成后:

1. ✅ 等待第一次定时备份执行
2. ✅ 验证备份文件生成
3. ✅ 测试数据恢复流程
4. ✅ 更新运维文档
5. ✅ 培训团队成员

---

**最后更新**: 2025-12-26  
**版本**: 1.0
