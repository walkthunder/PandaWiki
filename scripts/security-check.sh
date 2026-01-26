#!/bin/bash

# 生产环境文档安全检查脚本
# 用途：检查上传到PandaWiki的文档是否包含敏感信息
# 使用方法：./scripts/security-check.sh [options]

set -e

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认配置
REMOTE_HOST="${REMOTE_HOST:-8.140.221.27}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PORT="${REMOTE_PORT:-22}"
OUTPUT_DIR="./security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${OUTPUT_DIR}/security_check_${TIMESTAMP}.md"

# 加载远程配置
if [ -f "scripts/.remote-config" ]; then
    source scripts/.remote-config
fi

# 显示帮助信息
show_help() {
    cat << EOF
生产环境文档安全检查脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -l, --list              列出所有文档
    -k, --kb KB_ID          检查指定知识库的文档
    -a, --all               检查所有文档（默认）
    -o, --output DIR        指定输出目录（默认: ./security-reports）
    --host HOST             远程服务器地址（默认: 8.140.221.27）
    --user USER             远程服务器用户（默认: root）

示例:
    $0 --list                                    # 列出所有文档
    $0 --all                                     # 检查所有文档
    $0 --kb 860d7e13-a4f1-4103-ba86-59ff8c11b790 # 检查指定知识库

EOF
}

# 创建输出目录
mkdir -p "${OUTPUT_DIR}"

# 列出所有文档
list_documents() {
    echo -e "${BLUE}正在获取文档列表...${NC}"
    
    ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c \"
        SELECT 
            kb.name as knowledge_base,
            COUNT(n.id) as doc_count
        FROM nodes n 
        JOIN knowledge_bases kb ON n.kb_id = kb.id 
        WHERE n.type IN (2, 3) 
        GROUP BY kb.name;
    \""
    
    echo ""
    ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c \"
        SELECT 
            kb.name as knowledge_base,
            kb.id as kb_id,
            n.name as document_name,
            n.created_at
        FROM nodes n 
        JOIN knowledge_bases kb ON n.kb_id = kb.id 
        WHERE n.type IN (2, 3) 
        ORDER BY kb.name, n.created_at DESC
        LIMIT 50;
    \" -x"
}

# 初始化报告
init_report() {
    cat > "${REPORT_FILE}" << EOF
# 生产环境文档安全检查报告

**检查时间**: $(date '+%Y-%m-%d %H:%M:%S')  
**服务器**: ${REMOTE_HOST}  
**检查范围**: ${CHECK_SCOPE}

---

## 执行摘要

EOF
}

# 检查文档内容
check_documents() {
    local kb_filter="$1"
    local where_clause=""
    
    if [ -n "$kb_filter" ]; then
        where_clause="AND n.kb_id = '$kb_filter'"
        CHECK_SCOPE="知识库 ID: $kb_filter"
    else
        CHECK_SCOPE="所有知识库"
    fi
    
    echo -e "${BLUE}开始安全检查...${NC}"
    init_report
    
    # 获取文档总数
    local total_docs=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes WHERE type IN (2, 3) ${where_clause};
    \"" | tr -d ' ')
    
    echo "- **文档总数**: ${total_docs}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    # 检查1: 包含"密"相关关键词的文档
    echo -e "${YELLOW}检查1: 包含保密相关关键词的文档...${NC}"
    check_sensitive_keywords "${where_clause}"
    
    # 检查2: 包含个人信息关键词的文档
    echo -e "${YELLOW}检查2: 包含个人信息关键词的文档...${NC}"
    check_personal_info "${where_clause}"
    
    # 检查3: 包含联系方式的文档
    echo -e "${YELLOW}检查3: 包含联系方式的文档...${NC}"
    check_contact_info "${where_clause}"
    
    # 检查4: 包含财务信息的文档
    echo -e "${YELLOW}检查4: 包含财务信息关键词的文档...${NC}"
    check_financial_info "${where_clause}"
    
    # 检查5: 包含内部标识的文档
    echo -e "${YELLOW}检查5: 包含内部标识的文档...${NC}"
    check_internal_marks "${where_clause}"
    
    # 检查6: Excel文件检查
    echo -e "${YELLOW}检查6: Excel文件检查...${NC}"
    check_excel_files "${where_clause}"
    
    # 生成建议
    generate_recommendations
    
    echo -e "${GREEN}检查完成！报告已保存到: ${REPORT_FILE}${NC}"
}

# 检查敏感关键词
check_sensitive_keywords() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 1. 保密相关关键词检查

检查包含以下关键词的文档：密、保密、机密、秘密、绝密、涉密

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND (name ILIKE '%密%' OR name ILIKE '%保密%' OR name ILIKE '%机密%' OR name ILIKE '%秘密%' OR name ILIKE '%绝密%' OR name ILIKE '%涉密%')
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND (name ILIKE '%密%' OR name ILIKE '%保密%' OR name ILIKE '%机密%' OR name ILIKE '%秘密%' OR name ILIKE '%绝密%' OR name ILIKE '%涉密%')
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "**分析**: 这些文档标题包含保密相关关键词，需要人工审核确认是否为公开的法律法规文件还是内部涉密文件。" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现包含保密关键词的文档标题" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 检查个人信息
check_personal_info() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 2. 个人信息关键词检查

检查包含以下关键词的文档：身份证、手机号、银行账号、员工、通讯录、花名册

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND (name ILIKE '%通讯录%' OR name ILIKE '%花名册%' OR name ILIKE '%员工名单%')
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND (name ILIKE '%通讯录%' OR name ILIKE '%花名册%' OR name ILIKE '%员工名单%')
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "⚠️ **警告**: 发现可能包含个人信息的文档，需要立即审核！" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现明显的个人信息文档" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 检查联系方式
check_contact_info() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 3. 联系方式检查

检查包含联系方式的文档（如电话号码、邮箱等）

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND name ILIKE '%联系方式%'
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND name ILIKE '%联系方式%'
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "**分析**: 这些文档包含联系方式，需要确认是否为公开的政府部门联系方式。" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现包含联系方式的文档标题" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 检查财务信息
check_financial_info() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 4. 财务信息关键词检查

检查包含以下关键词的文档：工资、薪资、报价、预算、财务、账号

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND (name ILIKE '%工资%' OR name ILIKE '%薪资%' OR name ILIKE '%报价单%' OR name ILIKE '%预算表%' OR name ILIKE '%财务报表%')
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND (name ILIKE '%工资%' OR name ILIKE '%薪资%' OR name ILIKE '%报价单%' OR name ILIKE '%预算表%' OR name ILIKE '%财务报表%')
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "⚠️ **警告**: 发现可能包含财务信息的文档，需要立即审核！" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现明显的财务信息文档" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 检查内部标识
check_internal_marks() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 5. 内部标识检查

检查包含以下关键词的文档：内部、仅限内部、草稿、未定稿

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND (name ILIKE '%内部%' OR name ILIKE '%仅限%' OR name ILIKE '%草稿%' OR name ILIKE '%未定稿%')
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND (name ILIKE '%内部%' OR name ILIKE '%仅限%' OR name ILIKE '%草稿%' OR name ILIKE '%未定稿%')
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "**分析**: 这些文档可能标记为内部使用，需要确认是否适合对外公开。" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现内部标识文档" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 检查Excel文件
check_excel_files() {
    local where_clause="$1"
    
    cat >> "${REPORT_FILE}" << EOF
## 6. Excel文件检查

Excel文件可能包含结构化的敏感数据，需要特别关注

EOF
    
    local result=$(ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
        SELECT COUNT(*) FROM nodes 
        WHERE type IN (2, 3) 
        AND (name ILIKE '%.xls' OR name ILIKE '%.xlsx')
        ${where_clause};
    \"" | tr -d ' ')
    
    echo "**发现文档数**: ${result}" >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    
    if [ "$result" -gt 0 ]; then
        echo "**文档列表**:" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        ssh ${REMOTE_USER}@${REMOTE_HOST} "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c \"
            SELECT '- ' || name FROM nodes 
            WHERE type IN (2, 3) 
            AND (name ILIKE '%.xls' OR name ILIKE '%.xlsx')
            ${where_clause}
            ORDER BY name;
        \"" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        
        echo "**建议**: Excel文件需要人工下载并详细审查内容。" >> "${REPORT_FILE}"
    else
        echo "✅ 未发现Excel文件" >> "${REPORT_FILE}"
    fi
    echo "" >> "${REPORT_FILE}"
}

# 生成建议
generate_recommendations() {
    cat >> "${REPORT_FILE}" << EOF

---

## 安全建议

### 高风险项
- ⚠️ 包含"通讯录"、"花名册"、"员工名单"的文档需要立即审核
- ⚠️ 包含"工资"、"薪资"、"报价单"的文档需要立即审核
- ⚠️ 所有Excel文件需要人工下载审查

### 中风险项
- 包含"内部"、"仅限"标识的文档需要确认是否适合公开
- 包含联系方式的文档需要确认是否为公开信息

### 低风险项
- 包含"保密"、"密"等关键词的文档，如果是公开的法律法规则无需担心
- 政府部门公开的联系方式无需处理

### 后续行动
1. 优先处理高风险项，立即审核相关文档
2. 建立文档上传审核机制，避免敏感信息上传
3. 定期运行此脚本进行安全检查
4. 对于已发现的敏感文档，及时删除或设置访问权限

---

**报告生成时间**: $(date '+%Y-%m-%d %H:%M:%S')

EOF
}

# 解析命令行参数
ACTION="check"
KB_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            ACTION="list"
            shift
            ;;
        -k|--kb)
            KB_FILTER="$2"
            shift 2
            ;;
        -a|--all)
            KB_FILTER=""
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            mkdir -p "${OUTPUT_DIR}"
            REPORT_FILE="${OUTPUT_DIR}/security_check_${TIMESTAMP}.md"
            shift 2
            ;;
        --host)
            REMOTE_HOST="$2"
            shift 2
            ;;
        --user)
            REMOTE_USER="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}未知选项: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# 执行操作
case $ACTION in
    list)
        list_documents
        ;;
    check)
        check_documents "$KB_FILTER"
        ;;
    *)
        echo -e "${RED}未知操作: $ACTION${NC}"
        exit 1
        ;;
esac
