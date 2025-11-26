#!/bin/bash

# 完整数据库备份脚本 - 支持本地和远程备份

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置
BACKUP_DIR="backups/database"
REMOTE_BACKUP_DIR="backups/remote"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE_DIR=$(date +%Y%m)

# 创建备份目录
mkdir -p "$BACKUP_DIR/$DATE_DIR"
mkdir -p "$REMOTE_BACKUP_DIR"

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
    echo "数据库备份工具"
    echo ""
    echo "用法:"
    echo "  $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -l, --local          本地备份（默认）"
    echo "  -r, --remote HOST    远程服务器备份"
    echo "  -u, --user USER      远程服务器用户名（默认: root）"
    echo "  -p, --path PATH      远程项目路径（默认: /root）"
    echo "  -k, --keep N         保留最近 N 个备份（默认: 30）"
    echo "  -h, --help           显示帮助"
    echo ""
    echo "示例:"
    echo "  $0                                    # 本地备份"
    echo "  $0 -r 8.140.221.27                   # 远程备份"
    echo "  $0 -r 8.140.221.27 -u root -k 60     # 远程备份，保留60个"
}

# 本地备份
backup_local() {
    log_info "开始本地数据库备份..."
    
    # 检查容器
    if ! docker ps | grep -q panda-wiki-postgres; then
        log_error "PostgreSQL 容器未运行"
        exit 1
    fi
    
    BACKUP_FILE="$BACKUP_DIR/$DATE_DIR/panda-wiki_local_$TIMESTAMP.sql"
    
    log_info "备份数据库到: $BACKUP_FILE"
    
    # 执行备份
    docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > "$BACKUP_FILE"
    
    if [ ! -s "$BACKUP_FILE" ]; then
        log_error "备份失败：文件为空"
        rm -f "$BACKUP_FILE"
        exit 1
    fi
    
    # 获取备份大小
    BACKUP_SIZE=$(ls -lh "$BACKUP_FILE" | awk '{print $5}')
    log_success "数据库备份完成 (大小: $BACKUP_SIZE)"
    
    # 压缩备份
    log_info "压缩备份文件..."
    gzip -f "$BACKUP_FILE"
    COMPRESSED_FILE="${BACKUP_FILE}.gz"
    COMPRESSED_SIZE=$(ls -lh "$COMPRESSED_FILE" | awk '{print $5}')
    log_success "压缩完成 (压缩后: $COMPRESSED_SIZE)"
    
    # 创建元数据
    create_metadata "$COMPRESSED_FILE" "local"
    
    # 清理旧备份
    cleanup_old_backups "$BACKUP_DIR" "$KEEP_BACKUPS"
    
    echo ""
    log_success "备份完成！"
    echo ""
    echo "备份文件: $COMPRESSED_FILE"
    echo "压缩后大小: $COMPRESSED_SIZE"
    echo ""
    echo "恢复命令:"
    echo "  gunzip -c $COMPRESSED_FILE | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki"
    echo ""
}

# 远程备份
backup_remote() {
    local remote_host=$1
    local remote_user=$2
    local remote_path=$3
    
    log_info "开始远程数据库备份..."
    log_info "服务器: $remote_user@$remote_host"
    log_info "路径: $remote_path"
    
    BACKUP_FILE="$REMOTE_BACKUP_DIR/panda-wiki_remote_$TIMESTAMP.sql"
    
    # 通过 SSH 执行远程备份
    log_info "连接到远程服务器..."
    
    ssh $remote_user@$remote_host "cd $remote_path && docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki" > "$BACKUP_FILE"
    
    if [ ! -s "$BACKUP_FILE" ]; then
        log_error "远程备份失败：文件为空"
        rm -f "$BACKUP_FILE"
        exit 1
    fi
    
    # 获取备份大小
    BACKUP_SIZE=$(ls -lh "$BACKUP_FILE" | awk '{print $5}')
    log_success "远程数据库备份完成 (大小: $BACKUP_SIZE)"
    
    # 压缩备份
    log_info "压缩备份文件..."
    gzip -f "$BACKUP_FILE"
    COMPRESSED_FILE="${BACKUP_FILE}.gz"
    COMPRESSED_SIZE=$(ls -lh "$COMPRESSED_FILE" | awk '{print $5}')
    log_success "压缩完成 (压缩后: $COMPRESSED_SIZE)"
    
    # 创建元数据
    create_metadata "$COMPRESSED_FILE" "remote:$remote_host"
    
    # 清理旧备份
    cleanup_old_backups "$REMOTE_BACKUP_DIR" "$KEEP_BACKUPS"
    
    echo ""
    log_success "远程备份完成！"
    echo ""
    echo "备份文件: $COMPRESSED_FILE"
    echo "压缩后大小: $COMPRESSED_SIZE"
    echo "来源: $remote_user@$remote_host:$remote_path"
    echo ""
    echo "恢复到本地:"
    echo "  gunzip -c $COMPRESSED_FILE | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki"
    echo ""
    echo "恢复到远程:"
    echo "  gunzip -c $COMPRESSED_FILE | ssh $remote_user@$remote_host 'docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki'"
    echo ""
}

# 创建元数据文件
create_metadata() {
    local backup_file=$1
    local source=$2
    local metadata_file="${backup_file}.meta"
    
    cat > "$metadata_file" << EOF
{
  "backup_file": "$(basename $backup_file)",
  "timestamp": "$TIMESTAMP",
  "date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "source": "$source",
  "size": "$(ls -lh $backup_file | awk '{print $5}')",
  "md5": "$(md5sum $backup_file | awk '{print $1}')"
}
EOF
}

# 清理旧备份
cleanup_old_backups() {
    local dir=$1
    local keep=$2
    
    log_info "清理旧备份（保留最近 $keep 个）..."
    
    cd "$dir"
    
    # 计算当前备份数量
    local count=$(find . -name "panda-wiki_*.sql.gz" | wc -l)
    
    if [ $count -gt $keep ]; then
        # 删除超出保留数量的旧备份
        find . -name "panda-wiki_*.sql.gz" -type f -printf '%T@ %p\n' | \
            sort -n | \
            head -n -$keep | \
            cut -d' ' -f2- | \
            while read file; do
                log_info "删除旧备份: $file"
                rm -f "$file" "${file}.meta"
            done
    fi
    
    cd - > /dev/null
    
    local remaining=$(find "$dir" -name "panda-wiki_*.sql.gz" | wc -l)
    log_success "当前保留 $remaining 个备份文件"
}

# 列出备份
list_backups() {
    echo ""
    echo "=== 本地备份 ==="
    if [ -d "$BACKUP_DIR" ]; then
        find "$BACKUP_DIR" -name "panda-wiki_*.sql.gz" -type f -printf '%T@ %p %s\n' | \
            sort -rn | \
            awk '{
                cmd="date -d @"$1" +\"%Y-%m-%d %H:%M:%S\"";
                cmd | getline date;
                close(cmd);
                size=$3/1024/1024;
                printf "  %s  %s  %.2f MB\n", date, $2, size
            }' | head -10
    else
        echo "  无备份"
    fi
    
    echo ""
    echo "=== 远程备份 ==="
    if [ -d "$REMOTE_BACKUP_DIR" ]; then
        find "$REMOTE_BACKUP_DIR" -name "panda-wiki_*.sql.gz" -type f -printf '%T@ %p %s\n' | \
            sort -rn | \
            awk '{
                cmd="date -d @"$1" +\"%Y-%m-%d %H:%M:%S\"";
                cmd | getline date;
                close(cmd);
                size=$3/1024/1024;
                printf "  %s  %s  %.2f MB\n", date, $2, size
            }' | head -10
    else
        echo "  无备份"
    fi
    echo ""
}

# 主函数
main() {
    local mode="local"
    local remote_host=""
    local remote_user="root"
    local remote_path="/root"
    KEEP_BACKUPS=30
    
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
            -k|--keep)
                KEEP_BACKUPS="$2"
                shift 2
                ;;
            --list)
                list_backups
                exit 0
                ;;
            -h|--help)
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
    
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║     PandaWiki 数据库备份工具          ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    if [ "$mode" = "local" ]; then
        backup_local
    elif [ "$mode" = "remote" ]; then
        if [ -z "$remote_host" ]; then
            log_error "远程模式需要指定主机地址"
            show_help
            exit 1
        fi
        backup_remote "$remote_host" "$remote_user" "$remote_path"
    fi
}

main "$@"
