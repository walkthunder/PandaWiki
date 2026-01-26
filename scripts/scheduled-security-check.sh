#!/bin/bash

# 定期安全检查脚本
# 用途：自动运行安全检查并发送通知
# 使用方法：添加到crontab定期执行

set -e

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="${PROJECT_DIR}/security-reports"
LOG_FILE="${PROJECT_DIR}/logs/security-check.log"
ALERT_EMAIL="${ALERT_EMAIL:-}"  # 可选：设置告警邮箱

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# 创建日志目录
mkdir -p "$(dirname "$LOG_FILE")"

# 记录日志
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=========================================="
log "开始定期安全检查"
log "=========================================="

# 切换到项目目录
cd "$PROJECT_DIR"

# 运行安全检查
log "运行安全检查脚本..."
if ./scripts/security-check.sh --all >> "$LOG_FILE" 2>&1; then
    log "✅ 安全检查完成"
else
    log "❌ 安全检查失败"
    exit 1
fi

# 获取最新的报告文件
LATEST_REPORT=$(ls -t "${REPORT_DIR}"/security_check_*.md 2>/dev/null | head -1)

if [ -z "$LATEST_REPORT" ]; then
    log "❌ 未找到检查报告"
    exit 1
fi

log "报告文件: $LATEST_REPORT"

# 分析报告，检查是否有高风险问题
HIGH_RISK_COUNT=0
MEDIUM_RISK_COUNT=0

# 检查高风险关键词
if grep -q "通讯录\|花名册\|员工名单\|工资表\|薪资\|报价单" "$LATEST_REPORT"; then
    HIGH_RISK_COUNT=$((HIGH_RISK_COUNT + 1))
fi

# 检查中风险关键词
if grep -q "Excel文件\|内部使用\|保密" "$LATEST_REPORT"; then
    MEDIUM_RISK_COUNT=$((MEDIUM_RISK_COUNT + 1))
fi

# 生成摘要
log "=========================================="
log "检查结果摘要"
log "=========================================="
log "高风险问题: $HIGH_RISK_COUNT"
log "中风险问题: $MEDIUM_RISK_COUNT"

# 如果有高风险问题，发送告警
if [ $HIGH_RISK_COUNT -gt 0 ]; then
    log "⚠️  发现高风险问题，需要立即处理！"
    
    # 如果配置了邮箱，发送告警邮件
    if [ -n "$ALERT_EMAIL" ]; then
        SUBJECT="[紧急] PandaWiki文档安全检查发现高风险问题"
        BODY="发现 $HIGH_RISK_COUNT 个高风险问题，请立即查看报告：$LATEST_REPORT"
        
        # 使用mail命令发送邮件（需要系统配置mail）
        if command -v mail &> /dev/null; then
            echo "$BODY" | mail -s "$SUBJECT" "$ALERT_EMAIL"
            log "已发送告警邮件到: $ALERT_EMAIL"
        else
            log "⚠️  未安装mail命令，无法发送邮件"
        fi
    fi
elif [ $MEDIUM_RISK_COUNT -gt 0 ]; then
    log "ℹ️  发现中风险问题，建议审核"
else
    log "✅ 未发现明显的安全问题"
fi

# 清理旧报告（保留最近30天）
log "清理旧报告..."
find "${REPORT_DIR}" -name "security_check_*.md" -mtime +30 -delete 2>/dev/null || true
find "${REPORT_DIR}" -name "security_check_*.json" -mtime +30 -delete 2>/dev/null || true

log "=========================================="
log "定期安全检查完成"
log "=========================================="

# 返回状态码
if [ $HIGH_RISK_COUNT -gt 0 ]; then
    exit 2  # 有高风险问题
elif [ $MEDIUM_RISK_COUNT -gt 0 ]; then
    exit 1  # 有中风险问题
else
    exit 0  # 无问题
fi
