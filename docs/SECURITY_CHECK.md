# 文档安全检查工具

## 快速开始

### 检查所有文档
```bash
./scripts/security-check.sh --all
```

### 查看报告
```bash
cat security-reports/security_check_*.md
```

### 列出知识库
```bash
python3 scripts/security_check.py --list
```

## 工具说明

### 脚本文件
- `scripts/security-check.sh` - Bash版本，快速检查
- `scripts/security_check.py` - Python版本，深度分析
- `scripts/scheduled-security-check.sh` - 定期自动检查

### 检查项目

| 检查项 | 风险等级 | 说明 |
|--------|---------|------|
| 保密关键词 | 中 | 密、保密、机密、秘密、绝密 |
| 个人信息 | 高 | 通讯录、花名册、员工名单 |
| 财务信息 | 高 | 工资表、报价单、预算表 |
| 内部标识 | 中 | 内部使用、仅限内部 |
| 联系方式 | 低-中 | 电话、手机号 |
| 身份证号 | 高 | 18位身份证格式 |
| Excel文件 | 中 | 需人工审查 |

## 常用命令

```bash
# 检查所有文档
./scripts/security-check.sh --all

# 检查指定知识库
./scripts/security-check.sh --kb <KB_ID>

# Python版本深度检查
python3 scripts/security_check.py --all --check-content

# 测试工具
./scripts/test-security-check.sh
```

## 配置定期检查

```bash
# 编辑crontab
crontab -e

# 添加（每周一凌晨2点）
0 2 * * 1 cd /path/to/PandaWiki && ./scripts/scheduled-security-check.sh
```

## 配置文件

编辑 `scripts/.remote-config`：

```bash
export REMOTE_HOST="8.140.221.27"
export REMOTE_USER="root"
export REMOTE_PORT="22"
```

## 处理流程

### 1. 高风险（立即处理）
- 包含真实个人信息 → 立即删除
- 包含财务数据 → 立即删除
- 包含身份证号 → 立即删除

### 2. 中风险（24小时内）
- Excel文件 → 下载审查
- 保密关键词 → 确认是否为公开法规
- 内部标识 → 评估是否适合公开

### 3. 低风险（一周内）
- 联系方式 → 确认是否为公开信息
- 邮箱地址 → 确认是否为公开邮箱

## 详细文档

- [完整使用说明](../scripts/SECURITY_CHECK_README.md)
- [安装配置指南](../scripts/SECURITY_CHECK_SETUP.md)
- [问题处理清单](../scripts/SECURITY_ACTION_CHECKLIST.md)
- [报告示例](../scripts/REPORT_EXAMPLE.md)

## 故障排除

### SSH连接失败
```bash
ssh root@8.140.221.27 "echo 'OK'"
```

### 权限问题
```bash
chmod +x scripts/security-check.sh
chmod +x scripts/security_check.py
```

## 安全建议

1. 每周至少运行一次检查
2. 高风险问题立即处理
3. 建立文档上传审核流程
4. 定期培训文档上传者
5. 报告文件妥善保管，不要提交到Git
