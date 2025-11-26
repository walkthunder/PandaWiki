#!/bin/bash

# 数据库恢复脚本

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

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
    echo "数据库恢复工具"
    echo ""
    echo "用法:"
    echo "  $0 [选项] <备份文件>"
    echo ""
    echo "选项:"
    echo "  -l, --local          恢复到本地数据库（默认）"
    echo "  -r, --remote HOST    恢复到远程数据库"
    echo "  -u, --user USER      远程服务器用户名（默认: root）"
    echo "  -p, --path PATH      远程项目路径（默认: /root）"
    echo "  --force              强制恢复，不提示确认"
    echo "  -h, --help           显示帮助"
    echo ""
    echo "示例:"
    echo "  $0 backups/database/202511/panda-wiki_local_20251126_120000.sql.gz"
    echo "  $0 -r 8.140.221.27 backups/remote/panda-wiki_remote_20251126_120000.sql.gz"
    echo ""
    echo "注意:"
    echo "  - 恢复操作会覆盖现有数据库"
    echo "  - 建议在恢复前先备份当前数据库"
    echo "  - 支持 .sql 和 .sql.gz 格式"
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

# 列出可用备份
list_backups() {
    echo ""
    echo "=== 可用的备份文件 ==="
    echo ""
    
    echo "本地备份:"
    if [ -d "backups/database" ]; then
        find backups/database -name "panda-wiki_*.sql.gz" -type f -printf '%T@ %p %s\n' | \
            sort -rn | \
            head -10 | \
            awk '{
                cmd="date -d @"$1" +\"%Y-%m-%d %H:%M:%S\"";
                cmd | getline date;
                close(cmd);
                size=$3/1024/1024;
                printf "  [%s] %s (%.2f MB)\n", date, $2, size
            }'
    else
        echo "  无备份"
    fi
    
    echo ""
    echo "远程备份:"
    if [ -d "backups/remote" ]; then
        find backups/remote -name "panda-wiki_*.sql.gz" -type f -printf '%T@ %p %s\n' | \
            sort -rn | \
            head -10 | \
            awk '{
                cmd="date -d @"$1" +\"%Y-%m-%d %H:%M:%S\"";
                cmd | getline date;
                close(cmd);
                size=$3/1024/1024;
                printf "  [%s] %s (%.2f MB)\n", date, $2, size
            }'
    else
        echo "  无备份"
    fi
    echo ""
}

# 本地恢复
restore_local() {
    local backup_file=$1
    local force=$2
    
    log_info "准备恢复本地数据库..."
    
    # 检查容器
    if ! docker ps | grep -q panda-wiki-postgres; then
        log_error "PostgreSQL 容器未运行"
        exit 1
    fi
    
    # 检查备份文件
    if [ ! -f "$backup_file" ]; then
        log_error "备份文件不存在: $backup_file"
        exit 1
    fi
    
    # 显示备份信息
    local file_size=$(ls -lh "$backup_file" | awk '{print $5}')
    local file_date=$(ls -l --time-style=long-iso "$backup_file" | awk '{print $6, $7}')
    
    echo ""
    echo "备份文件信息:"
    echo "  文件: $backup_file"
    echo "  大小: $file_size"
    echo "  日期: $file_date"
    echo ""
    
    # 确认操作
    if [ "$force" != "yes" ]; then
        log_warning "警告: 此操作将覆盖当前数据库的所有数据！"
        confirm "确定要恢复数据库吗？"
        
        # 建议先备份
        echo ""
        log_warning "建议先备份当前数据库"
        read -p "是否先备份当前数据库? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            log_info "正在备份当前数据库..."
            ./scripts/backup-database-full.sh --local
            echo ""
        fi
    fi
    
    # 执行恢复
    log_info "开始恢复数据库..."
    
    if [[ "$backup_file" == *.gz ]]; then
        # 压缩文件
        gunzip -c "$backup_file" | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki
    else
        # 未压缩文件
        cat "$backup_file" | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki
    fi
    
    if [ $? -eq 0 ]; then
        log_success "数据库恢复完成！"
    else
        log_error "数据库恢复失败"
        exit 1
    fi
}

# 远程恢复
restore_remote() {
    local backup_file=$1
    local remote_host=$2
    local remote_user=$3
    local remote_path=$4
    local force=$5
    
    log_info "准备恢复远程数据库..."
    log_info "目标服务器: $remote_user@$remote_host"
    
    # 检查备份文件
    if [ ! -f "$backup_file" ]; then
        log_error "备份文件不存在: $backup_file"
        exit 1
    fi
    
    # 检查连接
    log_info "检查服务器连接..."
    if ! ssh -o ConnectTimeout=5 $remote_user@$remote_host "echo 'OK'" > /dev/null 2>&1; then
        log_error "无法连接到服务器 $remote_host"
        exit 1
    fi
    log_success "服务器连接正常"
    
    # 显示备份信息
    local file_size=$(ls -lh "$backup_file" | awk '{print $5}')
    local file_date=$(ls -l --time-style=long-iso "$backup_file" | awk '{print $6, $7}')
    
    echo ""
    echo "备份文件信息:"
    echo "  文件: $backup_file"
    echo "  大小: $file_size"
    echo "  日期: $file_date"
    echo "  目标: $remote_user@$remote_host"
    echo ""
    
    # 确认操作
    if [ "$force" != "yes" ]; then
        log_warning "警告: 此操作将覆盖远程服务器数据库的所有数据！"
        confirm "确定要恢复远程数据库吗？"
        
        # 建议先备份
        echo ""
        log_warning "建议先备份远程数据库"
        read -p "是否先备份远程数据库? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            log_info "正在备份远程数据库..."
            ./scripts/backup-database-full.sh --remote "$remote_host" --user "$remote_user" --path "$remote_path"
            echo ""
        fi
    fi
    
    # 执行恢复
    log_info "开始恢复远程数据库..."
    
    if [[ "$backup_file" == *.gz ]]; then
        # 压缩文件
        gunzip -c "$backup_file" | ssh $remote_user@$remote_host "cd $remote_path && docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki"
    else
        # 未压缩文件
        cat "$backup_file" | ssh $remote_user@$remote_host "cd $remote_path && docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki"
    fi
    
    if [ $? -eq 0 ]; then
        log_success "远程数据库恢复完成！"
    else
        log_error "远程数据库恢复失败"
        exit 1
    fi
}

# 主函数
main() {
    local mode="local"
    local backup_file=""
    local remote_host=""
    local remote_user="root"
    local remote_path="/root"
    local force="no"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--local)
                mode="local"
                shift
                ;;
            -r|--remote)
                mode="remote"
                remote_host="$2"
                shift 2
                ;;
            -u|--user)
                remote_user="$2"
                shift 2
                ;;
            -p|--path)
                remote_path="$2"
                shift 2
                ;;
            --force)
                force="yes"
                shift
                ;;
            --list)
                list_backups
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
            *)
                backup_file="$1"
                shift
                ;;
        esac
    done
    
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║     PandaWiki 数据库恢复工具          ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    # 如果没有指定备份文件，列出可用备份
    if [ -z "$backup_file" ]; then
        list_backups
        echo ""
        log_error "请指定要恢复的备份文件"
        echo ""
        echo "用法: $0 <备份文件>"
        exit 1
    fi
    
    # 执行恢复
    if [ "$mode" = "local" ]; then
        restore_local "$backup_file" "$force"
    else
        if [ -z "$remote_host" ]; then
            log_error "远程模式需要指定主机地址"
            show_help
            exit 1
        fi
        restore_remote "$backup_file" "$remote_host" "$remote_user" "$remote_path" "$force"
    fi
    
    echo ""
    log_success "恢复操作完成！"
    echo ""
}

main "$@"
