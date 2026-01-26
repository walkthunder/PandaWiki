# 文档安全检查工具使用说明

本工具用于检查生产环境中上传到PandaWiki的文档是否包含敏感信息，防止数据泄露。

## 工具说明

提供两个版本的检查工具：

1. **security-check.sh** - Bash脚本版本，轻量级，适合快速检查
2. **security_check.py** - Python脚本版本，功能更强大，支持内容分析和正则匹配

## 检查项目

### 1. 保密相关关键词
- 关键词：密、保密、机密、秘密、绝密、涉密
- 风险等级：中
- 说明：需要确认是否为公开的法律法规文件

### 2. 个人信息
- 关键词：通讯录、花名册、员工名单、人员名单
- 风险等级：高
- 说明：可能包含真实个人信息，需立即审核

### 3. 财务信息
- 关键词：工资表、薪资、报价单、预算表、财务报表、银行账号
- 风险等级：高
- 说明：可能包含财务敏感数据，需立即审核

### 4. 内部标识
- 关键词：内部使用、仅限内部、草稿、未定稿、内部资料
- 风险等级：中
- 说明：标记为内部的文档可能不适合对外公开

### 5. 联系方式
- 关键词：联系方式、联系电话、手机号
- 模式：手机号码格式（1[3-9]xxxxxxxxx）
- 风险等级：低-中
- 说明：需确认是否为公开信息

### 6. 身份证号
- 模式：18位身份证号格式
- 风险等级：高
- 说明：包含真实身份证号需立即删除

### 7. Excel文件
- 文件类型：.xls, .xlsx
- 风险等级：中
- 说明：Excel文件可能包含结构化敏感数据，需人工审查

## 使用方法

### Bash版本 (security-check.sh)

#### 1. 列出所有文档
```bash
./scripts/security-check.sh --list
```

#### 2. 检查所有文档
```bash
./scripts/security-check.sh --all
```

#### 3. 检查指定知识库
```bash
./scripts/security-check.sh --kb 860d7e13-a4f1-4103-ba86-59ff8c11b790
```

#### 4. 指定输出目录
```bash
./scripts/security-check.sh --all --output ./my-reports
```

#### 5. 指定远程服务器
```bash
./scripts/security-check.sh --all --host 8.140.221.27 --user root
```

### Python版本 (security_check.py)

#### 1. 列出所有知识库
```bash
python3 scripts/security_check.py --list
```

#### 2. 检查所有文档（仅检查文档名）
```bash
python3 scripts/security_check.py --all
```

#### 3. 检查所有文档（包括内容分析）
```bash
python3 scripts/security_check.py --all --check-content
```

#### 4. 检查指定知识库
```bash
python3 scripts/security_check.py --kb 860d7e13-a4f1-4103-ba86-59ff8c11b790
```

#### 5. 完整示例
```bash
python3 scripts/security_check.py \
  --all \
  --check-content \
  --host 8.140.221.27 \
  --user root \
  --output ./security-reports
```

## 配置文件

脚本会自动读取 `scripts/.remote-config` 文件中的配置：

```bash
# 远程服务器配置
export REMOTE_HOST="8.140.221.27"
export REMOTE_USER="root"
export REMOTE_PORT="22"
```

## 输出报告

### 报告格式

两个版本都会生成Markdown格式的检查报告，Python版本还会额外生成JSON格式数据。

报告包含以下内容：
- 执行摘要（问题统计）
- 高风险问题列表（需立即处理）
- 中风险问题列表（需要审核）
- 低风险问题列表（建议关注）
- 安全建议和后续行动

### 报告位置

默认保存在 `./security-reports/` 目录下：
- Markdown报告：`security_check_YYYYMMDD_HHMMSS.md`
- JSON数据（仅Python版本）：`security_check_YYYYMMDD_HHMMSS.json`

## 使用建议

### 首次使用
1. 先使用 `--list` 查看所有知识库
2. 使用 Bash 版本快速检查所有文档名称
3. 如发现可疑文档，使用 Python 版本的 `--check-content` 进行深度分析

### 定期检查
建议每周运行一次安全检查：

```bash
# 添加到 crontab
0 2 * * 1 cd /path/to/project && ./scripts/security-check.sh --all
```

### 性能考虑
- Bash版本：快速，只检查文档名称和数据库元数据
- Python版本（不含--check-content）：较快，检查文档名称
- Python版本（含--check-content）：较慢，会读取文档内容进行深度分析

## 处理发现的问题

### 高风险问题
1. 立即审核文档内容
2. 如确认包含敏感信息，立即删除或设置访问权限
3. 通知相关人员，避免再次上传

### 中风险问题
1. 人工审核文档内容
2. 确认是否适合对外公开
3. 如不适合，删除或限制访问

### 低风险问题
1. 定期审核
2. 确认是否为公开信息
3. 建立白名单机制

## 故障排除

### 连接失败
```bash
# 测试SSH连接
ssh root@8.140.221.27 "echo 'Connection OK'"

# 检查Docker容器状态
ssh root@8.140.221.27 "docker ps | grep panda-wiki"
```

### 权限问题
```bash
# 给脚本添加执行权限
chmod +x scripts/security-check.sh
chmod +x scripts/security_check.py
```

### Python依赖
Python脚本使用标准库，无需额外安装依赖。

## 安全注意事项

1. ⚠️ 脚本以只读方式访问数据库，不会修改任何数据
2. ⚠️ 报告中的敏感数据会自动脱敏处理
3. ⚠️ 报告文件可能包含敏感信息，请妥善保管
4. ⚠️ 不要将报告提交到版本控制系统

## 扩展功能

### 自定义检查规则

编辑 `security_check.py` 中的 `PATTERNS` 字典添加自定义规则：

```python
PATTERNS = {
    'custom_pattern': {
        'keywords': ['自定义关键词1', '自定义关键词2'],
        'severity': 'high',
        'description': '自定义检查项描述'
    }
}
```

### 集成到CI/CD

可以将检查脚本集成到部署流程中：

```bash
# 在部署后自动运行检查
./scripts/security-check.sh --all
if [ $? -ne 0 ]; then
    echo "安全检查发现问题，请查看报告"
fi
```

## 联系支持

如有问题或建议，请联系系统管理员。
