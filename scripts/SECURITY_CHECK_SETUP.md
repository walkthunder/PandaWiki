# 文档安全检查工具安装配置指南

## 安装步骤

### 1. 确认文件权限

```bash
chmod +x scripts/security-check.sh
chmod +x scripts/security_check.py
chmod +x scripts/scheduled-security-check.sh
```

### 2. 配置远程服务器信息

编辑 `scripts/.remote-config` 文件：

```bash
# 远程服务器配置
export REMOTE_HOST="8.140.221.27"
export REMOTE_USER="root"
export REMOTE_PORT="22"
```

### 3. 测试SSH连接

```bash
# 测试连接
ssh root@8.140.221.27 "echo 'Connection OK'"

# 测试Docker访问
ssh root@8.140.221.27 "docker ps | grep panda-wiki"
```

### 4. 运行首次检查

```bash
# 使用Bash版本
./scripts/security-check.sh --all

# 或使用Python版本
python3 scripts/security_check.py --all
```

### 5. 查看报告

```bash
# 查看最新报告
ls -lt security-reports/

# 阅读报告
cat security-reports/security_check_*.md
```

## 配置定期检查

### 方法1：使用crontab（推荐）

```bash
# 编辑crontab
crontab -e

# 添加以下行（每周一凌晨2点执行）
0 2 * * 1 cd /path/to/PandaWiki && ./scripts/scheduled-security-check.sh

# 或每天凌晨3点执行
0 3 * * * cd /path/to/PandaWiki && ./scripts/scheduled-security-check.sh
```

### 方法2：使用systemd timer

创建服务文件 `/etc/systemd/system/pandawiki-security-check.service`：

```ini
[Unit]
Description=PandaWiki Security Check
After=network.target

[Service]
Type=oneshot
User=your-username
WorkingDirectory=/path/to/PandaWiki
ExecStart=/path/to/PandaWiki/scripts/scheduled-security-check.sh
StandardOutput=journal
StandardError=journal
```

创建定时器文件 `/etc/systemd/system/pandawiki-security-check.timer`：

```ini
[Unit]
Description=PandaWiki Security Check Timer
Requires=pandawiki-security-check.service

[Timer]
OnCalendar=Mon *-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

启用定时器：

```bash
sudo systemctl daemon-reload
sudo systemctl enable pandawiki-security-check.timer
sudo systemctl start pandawiki-security-check.timer

# 查看状态
sudo systemctl status pandawiki-security-check.timer
```

## 配置告警通知

### 邮件告警

编辑 `scripts/scheduled-security-check.sh`，设置邮箱地址：

```bash
ALERT_EMAIL="admin@example.com"
```

确保系统已安装并配置mail命令：

```bash
# Ubuntu/Debian
sudo apt-get install mailutils

# CentOS/RHEL
sudo yum install mailx
```

### Webhook告警（可选）

可以修改 `scripts/scheduled-security-check.sh`，添加webhook通知：

```bash
# 在脚本中添加
if [ $HIGH_RISK_COUNT -gt 0 ]; then
    # 发送到企业微信/钉钉/Slack等
    curl -X POST "YOUR_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{\"text\":\"发现 $HIGH_RISK_COUNT 个高风险问题\"}"
fi
```

## 自定义检查规则

### 添加新的关键词检查

编辑 `scripts/security_check.py`，在 `PATTERNS` 字典中添加：

```python
PATTERNS = {
    # ... 现有规则 ...
    
    'custom_rule': {
        'keywords': ['自定义关键词1', '自定义关键词2'],
        'severity': 'high',  # high, medium, low
        'description': '自定义检查项描述'
    }
}
```

### 添加正则表达式检查

```python
PATTERNS = {
    # ... 现有规则 ...
    
    'custom_regex': {
        'regex': r'your_regex_pattern',
        'severity': 'medium',
        'description': '正则匹配描述'
    }
}
```

## 日志管理

### 查看检查日志

```bash
# 查看最近的日志
tail -f logs/security-check.log

# 查看所有日志
cat logs/security-check.log
```

### 日志轮转

创建 `/etc/logrotate.d/pandawiki-security-check`：

```
/path/to/PandaWiki/logs/security-check.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0644 your-username your-username
}
```

## 报告管理

### 自动清理旧报告

`scheduled-security-check.sh` 会自动清理30天前的报告。

如需修改保留时间，编辑脚本中的这一行：

```bash
find "${REPORT_DIR}" -name "security_check_*.md" -mtime +30 -delete
```

将 `+30` 改为你需要的天数。

### 报告归档

```bash
# 创建归档目录
mkdir -p security-reports/archive

# 归档旧报告
mv security-reports/security_check_2025*.md security-reports/archive/
```

## 集成到CI/CD

### GitHub Actions示例

创建 `.github/workflows/security-check.yml`：

```yaml
name: Security Check

on:
  schedule:
    - cron: '0 2 * * 1'  # 每周一凌晨2点
  workflow_dispatch:  # 允许手动触发

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup SSH
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.SSH_PRIVATE_KEY }}" > ~/.ssh/id_rsa
          chmod 600 ~/.ssh/id_rsa
          ssh-keyscan -H ${{ secrets.REMOTE_HOST }} >> ~/.ssh/known_hosts
      
      - name: Run Security Check
        run: |
          ./scripts/security-check.sh --all
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-reports/
```

## 故障排除

### 问题1：SSH连接失败

```bash
# 检查SSH配置
ssh -v root@8.140.221.27

# 检查防火墙
telnet 8.140.221.27 22
```

### 问题2：Docker命令失败

```bash
# 检查Docker容器状态
ssh root@8.140.221.27 "docker ps -a | grep panda-wiki"

# 检查容器日志
ssh root@8.140.221.27 "docker logs panda-wiki-postgres"
```

### 问题3：数据库连接失败

```bash
# 测试数据库连接
ssh root@8.140.221.27 "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c 'SELECT 1;'"
```

### 问题4：Python脚本执行慢

- 不使用 `--check-content` 选项可以大幅提升速度
- 或者只检查特定知识库：`--kb KB_ID`

## 安全最佳实践

1. **定期检查**：建议每周至少运行一次
2. **及时处理**：发现高风险问题立即处理
3. **权限控制**：限制报告文件的访问权限
4. **审计日志**：保留检查日志用于审计
5. **培训教育**：对文档上传者进行安全培训

## 更新和维护

### 更新脚本

```bash
# 拉取最新代码
git pull origin main

# 重新设置权限
chmod +x scripts/*.sh scripts/*.py
```

### 备份配置

```bash
# 备份配置文件
cp scripts/.remote-config scripts/.remote-config.backup
```

## 支持和反馈

如有问题或建议，请：
1. 查看详细文档：`scripts/SECURITY_CHECK_README.md`
2. 查看快速参考：`SECURITY_CHECK_QUICK_REF.md`
3. 联系系统管理员
