#!/bin/bash

# 安全检查工具测试脚本
# 用途：验证安全检查工具是否正常工作

set -e

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}安全检查工具测试${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 测试1: 检查脚本文件是否存在
echo -e "${YELLOW}测试1: 检查脚本文件...${NC}"
files=(
    "scripts/security-check.sh"
    "scripts/security_check.py"
    "scripts/scheduled-security-check.sh"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ✅ $file 存在"
    else
        echo -e "  ${RED}❌ $file 不存在${NC}"
        exit 1
    fi
done
echo ""

# 测试2: 检查脚本执行权限
echo -e "${YELLOW}测试2: 检查执行权限...${NC}"
for file in "${files[@]}"; do
    if [ -x "$file" ]; then
        echo -e "  ✅ $file 可执行"
    else
        echo -e "  ${RED}❌ $file 不可执行${NC}"
        echo -e "  ${YELLOW}提示: 运行 chmod +x $file${NC}"
        exit 1
    fi
done
echo ""

# 测试3: 检查文档文件
echo -e "${YELLOW}测试3: 检查文档文件...${NC}"
docs=(
    "scripts/SECURITY_CHECK_README.md"
    "scripts/SECURITY_CHECK_SETUP.md"
    "scripts/SECURITY_ACTION_CHECKLIST.md"
    "scripts/REPORT_EXAMPLE.md"
    "docs/SECURITY_CHECK.md"
)

for doc in "${docs[@]}"; do
    if [ -f "$doc" ]; then
        echo -e "  ✅ $doc 存在"
    else
        echo -e "  ${RED}❌ $doc 不存在${NC}"
        exit 1
    fi
done
echo ""

# 测试4: 检查SSH连接
echo -e "${YELLOW}测试4: 检查SSH连接...${NC}"
if [ -f "scripts/.remote-config" ]; then
    source scripts/.remote-config
    echo -e "  ℹ️  远程服务器: ${REMOTE_HOST}"
    
    if ssh -o ConnectTimeout=5 ${REMOTE_USER}@${REMOTE_HOST} "echo 'OK'" > /dev/null 2>&1; then
        echo -e "  ✅ SSH连接成功"
    else
        echo -e "  ${YELLOW}⚠️  SSH连接失败（可能需要配置密钥）${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠️  未找到 scripts/.remote-config 文件${NC}"
fi
echo ""

# 测试5: 测试Bash脚本帮助信息
echo -e "${YELLOW}测试5: 测试Bash脚本帮助...${NC}"
if ./scripts/security-check.sh --help > /dev/null 2>&1; then
    echo -e "  ✅ Bash脚本帮助信息正常"
else
    echo -e "  ${RED}❌ Bash脚本帮助信息失败${NC}"
    exit 1
fi
echo ""

# 测试6: 测试Python脚本帮助信息
echo -e "${YELLOW}测试6: 测试Python脚本帮助...${NC}"
if python3 scripts/security_check.py --help > /dev/null 2>&1; then
    echo -e "  ✅ Python脚本帮助信息正常"
else
    echo -e "  ${RED}❌ Python脚本帮助信息失败${NC}"
    exit 1
fi
echo ""

# 测试7: 检查报告目录
echo -e "${YELLOW}测试7: 检查报告目录...${NC}"
if [ -d "security-reports" ]; then
    report_count=$(ls -1 security-reports/security_check_*.md 2>/dev/null | wc -l)
    echo -e "  ✅ 报告目录存在"
    echo -e "  ℹ️  已有报告数: ${report_count}"
else
    echo -e "  ℹ️  报告目录不存在（首次运行时会自动创建）"
fi
echo ""

# 测试8: 检查.gitignore配置
echo -e "${YELLOW}测试8: 检查.gitignore配置...${NC}"
if grep -q "security-reports/" .gitignore; then
    echo -e "  ✅ security-reports/ 已添加到.gitignore"
else
    echo -e "  ${YELLOW}⚠️  security-reports/ 未添加到.gitignore${NC}"
fi
echo ""

# 测试总结
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✅ 所有基础测试通过！${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${YELLOW}下一步操作：${NC}"
echo -e "1. 运行实际检查："
echo -e "   ${BLUE}./scripts/security-check.sh --all${NC}"
echo ""
echo -e "2. 查看报告："
echo -e "   ${BLUE}cat security-reports/security_check_*.md${NC}"
echo ""
echo -e "3. 使用Python版本："
echo -e "   ${BLUE}python3 scripts/security_check.py --list${NC}"
echo -e "   ${BLUE}python3 scripts/security_check.py --all${NC}"
echo ""
echo -e "4. 配置定期检查："
echo -e "   ${BLUE}crontab -e${NC}"
echo -e "   添加: ${BLUE}0 2 * * 1 cd $(pwd) && ./scripts/scheduled-security-check.sh${NC}"
echo ""
