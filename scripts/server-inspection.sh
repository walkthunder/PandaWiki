#!/bin/bash

# PandaWiki 服务器自动巡检脚本
# 用途: 自动检测线上服务器状态并生成巡检报告
# 使用: ./scripts/server-inspection.sh

set -e

# ==================== 配置区 ====================
SERVER_IP="${SERVER_IP:-8.140.221.27}"
SERVER_USER="${SERVER_USER:-root}"
PROJECT_PATH="${PROJECT_PATH:-/root}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"
REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/server_inspection_${TIMESTAMP}.md"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==================== 函数定义 ====================

# SSH 执行命令
ssh_exec() {
    if [ -z "$SSH_KEY_PATH" ]; then
        ssh -o ConnectTimeout=10 "$SERVER_USER@$SERVER_IP" "$1" 2>/dev/null
    else
        ssh -i "$SSH_KEY_PATH" -o ConnectTimeout=10 "$SERVER_USER@$SERVER_IP" "$1" 2>/dev/null
    fi
}

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 SSH 连接
check_ssh_connection() {
    print_info "检查 SSH 连接到 $SERVER_USER@$SERVER_IP ..."
    if ssh_exec "echo 'SSH connection OK'" > /dev/null 2>&1; then
        print_success "SSH 连接正常"
        return 0
    else
        print_error "无法连接到服务器，请检查网络和 SSH 配置"
        exit 1
    fi
}

# 收集系统信息
collect_system_info() {
    print_info "收集系统资源信息..."
    
    # 磁盘使用
    DISK_INFO=$(ssh_exec "df -h / | tail -1")
    DISK_TOTAL=$(echo "$DISK_INFO" | awk '{print $2}')
    DISK_USED=$(echo "$DISK_INFO" | awk '{print $3}')
    DISK_AVAIL=$(echo "$DISK_INFO" | awk '{print $4}')
    DISK_PERCENT=$(echo "$DISK_INFO" | awk '{print $5}' | tr -d '%')
    
    # 内存使用
    MEM_INFO=$(ssh_exec "free -h | grep Mem")
    MEM_TOTAL=$(echo "$MEM_INFO" | awk '{print $2}')
    MEM_USED=$(echo "$MEM_INFO" | awk '{print $3}')
    MEM_AVAIL=$(echo "$MEM_INFO" | awk '{print $7}')
    MEM_PERCENT=$(ssh_exec "free | grep Mem | awk '{printf \"%.0f\", \$3/\$2 * 100}'")
    
    # 数据目录大小
    DATA_SIZES=$(ssh_exec "du -sh ${PROJECT_PATH}/data/* 2>/dev/null | sort -h")
    
    print_success "系统信息收集完成"
}

# 收集容器信息
collect_container_info() {
    print_info "收集 Docker 容器信息..."
    
    # 容器状态
    CONTAINER_STATUS=$(ssh_exec "docker ps -a --format 'table {{.Names}}|{{.Status}}|{{.Ports}}' | tail -n +2")
    
    # 容器资源使用
    CONTAINER_STATS=$(ssh_exec "docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}'")
    
    # 运行中的容器数量
    RUNNING_COUNT=$(ssh_exec "docker ps -q | wc -l")
    TOTAL_COUNT=$(ssh_exec "docker ps -aq | wc -l")
    
    print_success "容器信息收集完成 (运行中: $RUNNING_COUNT/$TOTAL_COUNT)"
}

# 收集网络信息
collect_network_info() {
    print_info "收集网络配置信息..."
    
    # Docker 网络
    NETWORK_INFO=$(ssh_exec "docker network ls | grep panda-wiki")
    
    # 端口监听
    PORT_INFO=$(ssh_exec "ss -tlnp | grep -E ':(80|443|2443|8000|5432|6379|9000)' || echo 'No ports found'")
    
    print_success "网络信息收集完成"
}

# 收集日志信息
collect_log_info() {
    print_info "收集服务日志信息..."
    
    # API 日志 (最近30行)
    API_LOGS=$(ssh_exec "docker logs panda-wiki-api --tail 30 2>&1 | grep -E '(ERROR|WARN|level=)' | tail -20 || echo 'No logs'")
    
    # 检查错误日志
    ERROR_COUNT=$(ssh_exec "docker logs panda-wiki-api --tail 100 2>&1 | grep -c 'ERROR' || echo 0")
    
    print_success "日志信息收集完成 (发现 $ERROR_COUNT 个错误)"
}

# 收集备份信息
collect_backup_info() {
    print_info "收集备份信息..."
    
    # 备份文件列表
    BACKUP_LIST=$(ssh_exec "ls -lh ${PROJECT_PATH}/backups/postgres/*.gz 2>/dev/null | tail -5 || echo 'No backups found'")
    BACKUP_COUNT=$(ssh_exec "ls ${PROJECT_PATH}/backups/postgres/*.gz 2>/dev/null | wc -l || echo 0")
    BACKUP_TOTAL_SIZE=$(ssh_exec "du -sh ${PROJECT_PATH}/backups/postgres 2>/dev/null | cut -f1 || echo '0'")
    
    # 最新备份时间
    LATEST_BACKUP=$(ssh_exec "ls -t ${PROJECT_PATH}/backups/postgres/*.gz 2>/dev/null | head -1 | xargs basename || echo 'None'")
    
    print_success "备份信息收集完成 (共 $BACKUP_COUNT 个备份文件)"
}

# 收集配置信息
collect_config_info() {
    print_info "收集配置信息..."
    
    # 环境变量 (隐藏敏感信息)
    ENV_INFO=$(ssh_exec "cat ${PROJECT_PATH}/.env 2>/dev/null | grep -v '^#' | grep -v '^$' | sed 's/=.*/=***/' || echo 'No .env file'")
    
    # 检查默认密码
    DEFAULT_PASSWORD_CHECK=$(ssh_exec "cat ${PROJECT_PATH}/.env 2>/dev/null | grep -c 'admin123' || echo 0")
    
    print_success "配置信息收集完成"
}

# 健康检查
health_check() {
    print_info "执行健康检查..."
    
    # 检查关键容器
    POSTGRES_HEALTH=$(ssh_exec "docker inspect panda-wiki-postgres --format='{{.State.Health.Status}}' 2>/dev/null || echo 'unknown'")
    API_STATUS=$(ssh_exec "docker inspect panda-wiki-api --format='{{.State.Status}}' 2>/dev/null || echo 'unknown'")
    APP_STATUS=$(ssh_exec "docker inspect panda-wiki-app --format='{{.State.Status}}' 2>/dev/null || echo 'unknown'")
    
    # 磁盘空间检查
    if [ "$DISK_PERCENT" -gt 80 ]; then
        DISK_STATUS="⚠️ 警告"
    elif [ "$DISK_PERCENT" -gt 70 ]; then
        DISK_STATUS="⚠️ 注意"
    else
        DISK_STATUS="✅ 正常"
    fi
    
    # 内存检查
    if [ "$MEM_PERCENT" -gt 85 ]; then
        MEM_STATUS="⚠️ 警告"
    elif [ "$MEM_PERCENT" -gt 70 ]; then
        MEM_STATUS="⚠️ 注意"
    else
        MEM_STATUS="✅ 正常"
    fi
    
    # 备份检查
    if [ "$BACKUP_COUNT" -eq 0 ]; then
        BACKUP_STATUS="❌ 无备份"
    elif [ "$BACKUP_COUNT" -lt 3 ]; then
        BACKUP_STATUS="⚠️ 备份较少"
    else
        BACKUP_STATUS="✅ 正常"
    fi
    
    # 安全检查
    if [ "$DEFAULT_PASSWORD_CHECK" -gt 0 ]; then
        SECURITY_STATUS="⚠️ 使用默认密码"
    else
        SECURITY_STATUS="✅ 密码已修改"
    fi
    
    print_success "健康检查完成"
}

# 生成 Markdown 报告
generate_report() {
    print_info "生成巡检报告..."
    
    mkdir -p "$REPORT_DIR"
    
    cat > "$REPORT_FILE" << EOF
# PandaWiki 服务器巡检报告

**生成时间**: $(date +"%Y年%m月%d日 %H:%M:%S")  
**服务器地址**: $SERVER_IP  
**巡检工具**: 自动化巡检脚本 v1.0

---

## 📊 执行摘要

### 系统健康度评分

| 检查项 | 状态 | 详情 |
|--------|------|------|
| 磁盘空间 | $DISK_STATUS | 使用率 ${DISK_PERCENT}% |
| 内存使用 | $MEM_STATUS | 使用率 ${MEM_PERCENT}% |
| 容器状态 | $([ "$RUNNING_COUNT" -eq "$TOTAL_COUNT" ] && echo "✅ 正常" || echo "⚠️ 异常") | $RUNNING_COUNT/$TOTAL_COUNT 运行中 |
| 数据备份 | $BACKUP_STATUS | 共 $BACKUP_COUNT 个备份 |
| 安全配置 | $SECURITY_STATUS | 密码安全检查 |
| PostgreSQL | $([ "$POSTGRES_HEALTH" = "healthy" ] && echo "✅ 健康" || echo "⚠️ $POSTGRES_HEALTH") | 数据库状态 |
| API 服务 | $([ "$API_STATUS" = "running" ] && echo "✅ 运行中" || echo "⚠️ $API_STATUS") | 后端服务 |
| App 服务 | $([ "$APP_STATUS" = "running" ] && echo "✅ 运行中" || echo "⚠️ $APP_STATUS") | 前端服务 |

### 关键指标

- **容器运行**: $RUNNING_COUNT/$TOTAL_COUNT 个容器正常运行
- **磁盘使用**: $DISK_USED / $DISK_TOTAL (${DISK_PERCENT}%)
- **内存使用**: $MEM_USED / $MEM_TOTAL (${MEM_PERCENT}%)
- **最新备份**: $LATEST_BACKUP
- **错误日志**: 最近100条日志中发现 $ERROR_COUNT 个错误

---

## 🖥️ 系统资源状态

### 磁盘使用情况

\`\`\`
文件系统: /dev/vda3
总容量: $DISK_TOTAL
已使用: $DISK_USED (${DISK_PERCENT}%)
可用空间: $DISK_AVAIL
状态: $DISK_STATUS
\`\`\`

### 内存使用情况

\`\`\`
总内存: $MEM_TOTAL
已使用: $MEM_USED (${MEM_PERCENT}%)
可用内存: $MEM_AVAIL
状态: $MEM_STATUS
\`\`\`

### 数据存储分布

\`\`\`
$DATA_SIZES
\`\`\`

---

## 🐳 Docker 容器状态

### 容器运行状态

\`\`\`
容器名称 | 状态 | 端口映射
$(echo "$CONTAINER_STATUS" | sed 's/|/ | /g')
\`\`\`

### 容器资源使用

| 容器名称 | CPU使用 | 内存使用 | 内存占比 |
|---------|---------|----------|----------|
$(echo "$CONTAINER_STATS" | while IFS='|' read name cpu mem percent; do
    echo "| $name | $cpu | $mem | $percent |"
done)

---

## 🔐 安全性检查

### 密码安全

$(if [ "$DEFAULT_PASSWORD_CHECK" -gt 0 ]; then
    echo "⚠️ **警告**: 检测到 $DEFAULT_PASSWORD_CHECK 个配置项使用默认密码 \`admin123\`"
    echo ""
    echo "**建议措施**:"
    echo "1. 立即修改 \`${PROJECT_PATH}/.env\` 中的所有密码"
    echo "2. 使用强密码 (至少16位，包含大小写字母、数字、特殊字符)"
    echo "3. 重启所有服务使新密码生效"
else
    echo "✅ **良好**: 未检测到默认密码"
fi)

### 环境变量配置

\`\`\`bash
$ENV_INFO
\`\`\`

---

## 💾 数据备份状态

### 备份概览

- **备份数量**: $BACKUP_COUNT 个
- **备份总大小**: $BACKUP_TOTAL_SIZE
- **最新备份**: $LATEST_BACKUP
- **备份状态**: $BACKUP_STATUS

### 最近备份记录

\`\`\`
$BACKUP_LIST
\`\`\`

### 备份建议

$(if [ "$BACKUP_COUNT" -eq 0 ]; then
    echo "❌ **紧急**: 未发现任何备份文件，建议立即配置自动备份"
elif [ "$BACKUP_COUNT" -lt 3 ]; then
    echo "⚠️ **注意**: 备份文件较少，建议增加备份频率"
else
    echo "✅ **正常**: 备份文件充足"
fi)

**未备份的数据**:
- MinIO 对象存储 (文档文件)
- Qdrant 向量数据库 (向量数据)
- Redis 缓存数据 (可重建)

---

## 📈 服务日志分析

### API 服务日志 (最近20条关键日志)

\`\`\`
$API_LOGS
\`\`\`

### 错误统计

- **错误数量**: $ERROR_COUNT 个 (最近100条日志)
- **状态**: $([ "$ERROR_COUNT" -gt 10 ] && echo "⚠️ 错误较多，需要关注" || echo "✅ 正常范围")

---

## 🔧 网络配置

### Docker 网络

\`\`\`
$NETWORK_INFO
\`\`\`

### 端口监听

\`\`\`
$PORT_INFO
\`\`\`

---

## 📋 运维建议

### 立即处理 (P0)

$(if [ "$DEFAULT_PASSWORD_CHECK" -gt 0 ]; then
    echo "- ⚠️ **修改默认密码**: 生产环境使用默认密码存在严重安全风险"
fi)
$(if [ "$DISK_PERCENT" -gt 80 ]; then
    echo "- ⚠️ **清理磁盘空间**: 磁盘使用率已超过80%"
fi)
$(if [ "$MEM_PERCENT" -gt 85 ]; then
    echo "- ⚠️ **优化内存使用**: 内存使用率已超过85%"
fi)
$(if [ "$BACKUP_COUNT" -eq 0 ]; then
    echo "- ❌ **配置数据备份**: 未发现任何备份文件"
fi)
$(if [ "$RUNNING_COUNT" -ne "$TOTAL_COUNT" ]; then
    echo "- ⚠️ **检查容器状态**: 有容器未正常运行"
fi)

### 短期优化 (P1)

- 配置定期自动备份 (每日/每周)
- 增加 MinIO 和 Qdrant 数据备份
- 配置监控告警系统
- 优化日志管理和轮转

### 长期规划 (P2)

- 评估资源扩容需求
- 规划高可用架构
- 定期安全审计
- 性能优化和调优

---

## 🎯 巡检结论

**系统状态**: $(
    if [ "$DISK_PERCENT" -lt 70 ] && [ "$MEM_PERCENT" -lt 70 ] && [ "$RUNNING_COUNT" -eq "$TOTAL_COUNT" ] && [ "$BACKUP_COUNT" -gt 0 ]; then
        echo "✅ 良好"
    elif [ "$DISK_PERCENT" -gt 80 ] || [ "$MEM_PERCENT" -gt 85 ] || [ "$RUNNING_COUNT" -ne "$TOTAL_COUNT" ]; then
        echo "⚠️ 需要关注"
    else
        echo "⚠️ 一般"
    fi
)

**关键问题数**: $(
    issues=0
    [ "$DEFAULT_PASSWORD_CHECK" -gt 0 ] && issues=$((issues+1))
    [ "$DISK_PERCENT" -gt 80 ] && issues=$((issues+1))
    [ "$MEM_PERCENT" -gt 85 ] && issues=$((issues+1))
    [ "$BACKUP_COUNT" -eq 0 ] && issues=$((issues+1))
    [ "$RUNNING_COUNT" -ne "$TOTAL_COUNT" ] && issues=$((issues+1))
    echo $issues
)

**下次巡检建议**: $(date -d "+7 days" +"%Y年%m月%d日" 2>/dev/null || date -v+7d +"%Y年%m月%d日" 2>/dev/null || echo "7天后")

---

**报告生成工具**: PandaWiki 自动化巡检脚本  
**脚本版本**: v1.0  
**联系方式**: 运维团队
EOF

    print_success "报告已生成: $REPORT_FILE"
}

# 显示报告摘要
show_summary() {
    echo ""
    echo "=========================================="
    echo "           巡检完成摘要"
    echo "=========================================="
    echo ""
    echo "服务器: $SERVER_USER@$SERVER_IP"
    echo "容器状态: $RUNNING_COUNT/$TOTAL_COUNT 运行中"
    echo "磁盘使用: ${DISK_PERCENT}% ($DISK_STATUS)"
    echo "内存使用: ${MEM_PERCENT}% ($MEM_STATUS)"
    echo "数据备份: $BACKUP_COUNT 个 ($BACKUP_STATUS)"
    echo "安全状态: $SECURITY_STATUS"
    echo ""
    echo "完整报告: $REPORT_FILE"
    echo ""
    
    # 显示警告
    if [ "$DEFAULT_PASSWORD_CHECK" -gt 0 ] || [ "$DISK_PERCENT" -gt 80 ] || [ "$MEM_PERCENT" -gt 85 ] || [ "$BACKUP_COUNT" -eq 0 ]; then
        print_warning "发现需要关注的问题，请查看完整报告"
    else
        print_success "系统运行正常"
    fi
    
    echo "=========================================="
}

# ==================== 主流程 ====================

main() {
    echo ""
    echo "=========================================="
    echo "    PandaWiki 服务器自动巡检工具"
    echo "=========================================="
    echo ""
    
    # 检查连接
    check_ssh_connection
    
    # 收集信息
    collect_system_info
    collect_container_info
    collect_network_info
    collect_log_info
    collect_backup_info
    collect_config_info
    
    # 健康检查
    health_check
    
    # 生成报告
    generate_report
    
    # 显示摘要
    show_summary
    
    # 询问是否打开报告
    echo ""
    read -p "是否打开报告文件? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v open &> /dev/null; then
            open "$REPORT_FILE"
        elif command -v xdg-open &> /dev/null; then
            xdg-open "$REPORT_FILE"
        else
            print_info "请手动打开: $REPORT_FILE"
        fi
    fi
}

# 执行主流程
main
