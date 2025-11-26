#!/bin/bash

# 安全部署脚本 - 在部署前自动备份数据库

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置
REMOTE_HOST="${REMOTE_HOST:-8.140.221.27}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PATH="${REMOTE_PATH:-/root}"
BACKUP_BEFORE_DEPLOY="${BACKUP_BEFORE_DEPLOY:-yes}"
SKIP_BACKUP="${SKIP_BACKUP:-no}"

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 显示帮助
show_help() {
    echo "安全部署脚本"
    echo ""
    echo "用法:"
    echo "  $0 [选项] [部署类型]"
    echo ""
    echo "部署类型:"
    echo "  local          本地部署（默认）"
    echo "  remote         远程部署"
    echo ""
    echo "选项:"
    echo "  -h, --host HOST        远程服务器地址"
    echo "  -u, --user USER        远程服务器用户名"
    echo "  -p, --path PATH        远程项目路径"
    echo "  --skip-backup          跳过备份（不推荐）"
    echo "  --help                 显示帮助"
    echo ""
    echo "环境变量:"
    echo "  REMOTE_HOST            远程服务器地址"
    echo "  REMOTE_USER            远程服务器用户名"
    echo "  REMOTE_PATH            远程项目路径"
    echo "  SKIP_BACKUP            跳过备份 (yes/no)"
    echo ""
    echo "示例:"
    echo "  $0 local                                    # 本地部署"
    echo "  $0 remote -h 8.140.221.27                  # 远程部署"
    echo "  $0 remote --skip-backup                    # 远程部署（跳过备份）"
}

# 确认操作
confirm() {
    local message=$1
    echo -e "${YELLOW}$message${NC}"
    read -p "继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "操作已取消"
        exit 1
    fi
}

# 备份数据库
backup_database() {
    local mode=$1
    
    if [ "$SKIP_BACKUP" = "yes" ]; then
        log_warning "跳过数据库备份（--skip-backup）"
        return 0
    fi
    
    log_info "开始备份数据库..."
    
    if [ "$mode" = "local" ]; then
        ./scripts/backup-database-full.sh --local
    else
        ./scripts/backup-database-full.sh --remote "$REMOTE_HOST" --user "$REMOTE_USER" --path "$REMOTE_PATH"
    fi
    
    if [ $? -eq 0 ]; then
        log_success "数据库备份完成"
    else
        log_error "数据库备份失败"
        confirm "备份失败，是否继续部署？"
    fi
}

# 本地部署
deploy_local() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║         本地部署流程                   ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    # 1. 备份数据库
    log_info "步骤 1/3: 备份数据库"
    backup_database "local"
    echo ""
    
    # 2. 确认部署
    log_info "步骤 2/3: 确认部署"
    confirm "即将开始本地部署，这将重启服务。"
    echo ""
    
    # 3. 执行部署
    log_info "步骤 3/3: 执行部署"
    if [ -f "deploy/local-deploy.sh" ]; then
        bash deploy/local-deploy.sh
    else
        log_error "找不到 deploy/local-deploy.sh"
        exit 1
    fi
    
    log_success "本地部署完成！"
}

# 远程部署
deploy_remote() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║         远程部署流程                   ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    log_info "目标服务器: $REMOTE_USER@$REMOTE_HOST"
    log_info "项目路径: $REMOTE_PATH"
    echo ""
    
    # 1. 检查连接
    log_info "步骤 1/4: 检查服务器连接"
    if ! ssh -o ConnectTimeout=5 $REMOTE_USER@$REMOTE_HOST "echo 'Connection OK'" > /dev/null 2>&1; then
        log_error "无法连接到服务器 $REMOTE_HOST"
        exit 1
    fi
    log_success "服务器连接正常"
    echo ""
    
    # 2. 备份远程数据库
    log_info "步骤 2/4: 备份远程数据库"
    backup_database "remote"
    echo ""
    
    # 3. 确认部署
    log_info "步骤 3/4: 确认部署"
    confirm "即将开始远程部署到 $REMOTE_HOST，这将重启服务。"
    echo ""
    
    # 4. 执行部署
    log_info "步骤 4/4: 执行部署"
    if [ -f "deploy/remote-deploy.sh" ]; then
        # 设置环境变量并执行
        REMOTE_HOST=$REMOTE_HOST REMOTE_USER=$REMOTE_USER REMOTE_PATH=$REMOTE_PATH \
            bash deploy/remote-deploy.sh
    else
        log_error "找不到 deploy/remote-deploy.sh"
        exit 1
    fi
    
    log_success "远程部署完成！"
}

# 部署前检查
pre_deploy_check() {
    log_info "执行部署前检查..."
    
    # 检查必要的脚本
    if [ ! -f "scripts/backup-database-full.sh" ]; then
        log_error "找不到备份脚本: scripts/backup-database-full.sh"
        exit 1
    fi
    
    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker 未安装"
        exit 1
    fi
    
    log_success "部署前检查通过"
}

# 主函数
main() {
    local deploy_type="local"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            local|remote)
                deploy_type=$1
                shift
                ;;
            -h|--host)
                REMOTE_HOST="$2"
                shift 2
                ;;
            -u|--user)
                REMOTE_USER="$2"
                shift 2
                ;;
            -p|--path)
                REMOTE_PATH="$2"
                shift 2
                ;;
            --skip-backup)
                SKIP_BACKUP="yes"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 执行部署前检查
    pre_deploy_check
    echo ""
    
    # 执行部署
    if [ "$deploy_type" = "local" ]; then
        deploy_local
    else
        deploy_remote
    fi
    
    echo ""
    log_success "部署流程完成！"
    echo ""
    echo "备份文件位置:"
    if [ "$deploy_type" = "local" ]; then
        echo "  backups/database/"
    else
        echo "  backups/remote/"
    fi
    echo ""
    echo "如需回滚，请使用备份文件恢复数据库。"
    echo ""
}

main "$@"
