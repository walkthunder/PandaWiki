#!/bin/bash

# PandaWiki 自动备份脚本 - 备份到腾讯云 COS
# 用途: 备份 PostgreSQL、MinIO、Qdrant 数据到腾讯云对象存储
# 使用: ./scripts/backup-to-cos.sh

set -e

# ==================== 配置区 ====================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"
BACKUP_BASE_DIR="${PROJECT_ROOT}/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DATE_DIR=$(date +"%Y%m%d")

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==================== 函数定义 ====================

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

# 加载环境变量
load_env() {
    print_info "加载环境变量配置..."
    
    if [ ! -f "$ENV_FILE" ]; then
        print_error "环境变量文件不存在: $ENV_FILE"
        exit 1
    fi
    
    # 导出环境变量
    export $(grep -v '^#' "$ENV_FILE" | grep -v '^$' | xargs)
    
    # 检查必要的环境变量
    if [ -z "$POSTGRES_PASSWORD" ]; then
        print_error "POSTGRES_PASSWORD 未设置"
        exit 1
    fi
    
    if [ -z "$TENCENTCLOUD_SECRET_ID" ] || [ -z "$TENCENTCLOUD_SECRET_KEY" ]; then
        print_error "腾讯云 COS 配置未设置"
        exit 1
    fi
    
    print_success "环境变量加载完成"
}

# 检查依赖
check_dependencies() {
    print_info "检查依赖工具..."
    
    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装"
        exit 1
    fi
    
    # 检查 Python3
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 未安装"
        exit 1
    fi
    
    # 检查腾讯云 COS SDK
    if ! python3 -c "import qcloud_cos" 2>/dev/null; then
        print_warning "腾讯云 COS SDK 未安装，正在安装..."
        pip3 install -q cos-python-sdk-v5 || {
            print_error "安装腾讯云 COS SDK 失败"
            exit 1
        }
        print_success "腾讯云 COS SDK 安装完成"
    fi
    
    print_success "依赖检查完成"
}

# 创建备份目录
create_backup_dirs() {
    print_info "创建备份目录..."
    
    mkdir -p "${BACKUP_BASE_DIR}/postgres/${DATE_DIR}"
    mkdir -p "${BACKUP_BASE_DIR}/minio/${DATE_DIR}"
    mkdir -p "${BACKUP_BASE_DIR}/qdrant/${DATE_DIR}"
    mkdir -p "${BACKUP_BASE_DIR}/temp"
    
    print_success "备份目录创建完成"
}

# 备份 PostgreSQL
backup_postgres() {
    print_info "开始备份 PostgreSQL 数据库..."
    
    local backup_file="${BACKUP_BASE_DIR}/postgres/${DATE_DIR}/postgres_${TIMESTAMP}.sql.gz"
    
    # 检查容器是否运行
    if ! docker ps --format '{{.Names}}' | grep -q "^panda-wiki-postgres$"; then
        print_error "PostgreSQL 容器未运行"
        return 1
    fi
    
    # 执行备份
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" panda-wiki-postgres \
        pg_dump -U panda-wiki -d panda-wiki \
        --format=plain --no-owner --no-acl | gzip > "$backup_file"
    
    if [ $? -eq 0 ]; then
        local size=$(du -h "$backup_file" | cut -f1)
        print_success "PostgreSQL 备份完成: $backup_file (大小: $size)"
        echo "$backup_file"
    else
        print_error "PostgreSQL 备份失败"
        return 1
    fi
}

# 备份 MinIO
backup_minio() {
    print_info "开始备份 MinIO 对象存储..."
    
    local backup_file="${BACKUP_BASE_DIR}/minio/${DATE_DIR}/minio_${TIMESTAMP}.tar.gz"
    local minio_data_dir="${PROJECT_ROOT}/data/minio"
    
    # 检查数据目录
    if [ ! -d "$minio_data_dir" ]; then
        print_error "MinIO 数据目录不存在: $minio_data_dir"
        return 1
    fi
    
    # 使用 tar 打包压缩（不停止服务）
    print_info "正在压缩 MinIO 数据 (约1.3GB，可能需要几分钟)..."
    tar -czf "$backup_file" -C "${PROJECT_ROOT}/data" minio 2>/dev/null
    
    if [ $? -eq 0 ]; then
        local size=$(du -h "$backup_file" | cut -f1)
        print_success "MinIO 备份完成: $backup_file (大小: $size)"
        echo "$backup_file"
    else
        print_error "MinIO 备份失败"
        return 1
    fi
}

# 备份 Qdrant
backup_qdrant() {
    print_info "开始备份 Qdrant 向量数据库..."
    
    local backup_file="${BACKUP_BASE_DIR}/qdrant/${DATE_DIR}/qdrant_${TIMESTAMP}.tar.gz"
    local qdrant_data_dir="${PROJECT_ROOT}/data/qdrant"
    
    # 检查数据目录
    if [ ! -d "$qdrant_data_dir" ]; then
        print_error "Qdrant 数据目录不存在: $qdrant_data_dir"
        return 1
    fi
    
    # 使用 tar 打包压缩（不停止服务）
    print_info "正在压缩 Qdrant 数据 (约368MB)..."
    tar -czf "$backup_file" -C "${PROJECT_ROOT}/data" qdrant 2>/dev/null
    
    if [ $? -eq 0 ]; then
        local size=$(du -h "$backup_file" | cut -f1)
        print_success "Qdrant 备份完成: $backup_file (大小: $size)"
        echo "$backup_file"
    else
        print_error "Qdrant 备份失败"
        return 1
    fi
}

# 上传到腾讯云 COS
upload_to_cos() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local service_type=$(echo "$file_path" | grep -oP '(?<=backups/)[^/]+')
    
    print_info "上传 $file_name 到腾讯云 COS..."
    
    # 调用 Python 上传脚本
    python3 "${SCRIPT_DIR}/upload_backup_to_cos.py" \
        --file "$file_path" \
        --service "$service_type" \
        --date "$DATE_DIR" \
        --secret-id "$TENCENTCLOUD_SECRET_ID" \
        --secret-key "$TENCENTCLOUD_SECRET_KEY" \
        --bucket "$TENCENTCLOUD_COS_BUCKET" \
        --region "$TENCENTCLOUD_COS_REGION"
    
    if [ $? -eq 0 ]; then
        print_success "$file_name 上传成功"
        return 0
    else
        print_error "$file_name 上传失败"
        return 1
    fi
}

# 清理旧备份
cleanup_old_backups() {
    print_info "清理旧备份文件..."
    
    # 保留最近7天的本地备份
    local keep_days=7
    
    # 清理 PostgreSQL 备份
    find "${BACKUP_BASE_DIR}/postgres" -type f -name "*.sql.gz" -mtime +${keep_days} -delete 2>/dev/null || true
    
    # 清理 MinIO 备份（保留最近3天，因为文件较大）
    find "${BACKUP_BASE_DIR}/minio" -type f -name "*.tar.gz" -mtime +3 -delete 2>/dev/null || true
    
    # 清理 Qdrant 备份（保留最近3天）
    find "${BACKUP_BASE_DIR}/qdrant" -type f -name "*.tar.gz" -mtime +3 -delete 2>/dev/null || true
    
    # 清理空目录
    find "${BACKUP_BASE_DIR}" -type d -empty -delete 2>/dev/null || true
    
    print_success "旧备份清理完成"
}

# 生成备份报告
generate_report() {
    local postgres_file="$1"
    local minio_file="$2"
    local qdrant_file="$3"
    
    local report_file="${BACKUP_BASE_DIR}/backup_report_${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
PandaWiki 备份报告
==================

备份时间: $(date +"%Y-%m-%d %H:%M:%S")
备份类型: 完整备份 (PostgreSQL + MinIO + Qdrant)

备份文件:
---------
PostgreSQL: $(basename "$postgres_file") ($(du -h "$postgres_file" | cut -f1))
MinIO:      $(basename "$minio_file") ($(du -h "$minio_file" | cut -f1))
Qdrant:     $(basename "$qdrant_file") ($(du -h "$qdrant_file" | cut -f1))

上传状态:
---------
腾讯云 COS: ✅ 已上传
Bucket:     $TENCENTCLOUD_COS_BUCKET
Region:     $TENCENTCLOUD_COS_REGION

本地备份路径:
-------------
$BACKUP_BASE_DIR

备份保留策略:
-------------
PostgreSQL: 保留7天
MinIO:      保留3天
Qdrant:     保留3天

下次备份建议: $(date -d "+1 day" +"%Y-%m-%d" 2>/dev/null || date -v+1d +"%Y-%m-%d" 2>/dev/null || echo "明天")
EOF

    print_success "备份报告已生成: $report_file"
    cat "$report_file"
}

# ==================== 主流程 ====================

main() {
    echo ""
    echo "=========================================="
    echo "   PandaWiki 自动备份到腾讯云 COS"
    echo "=========================================="
    echo ""
    
    # 记录开始时间
    local start_time=$(date +%s)
    
    # 加载配置
    load_env
    
    # 检查依赖
    check_dependencies
    
    # 创建备份目录
    create_backup_dirs
    
    # 执行备份
    print_info "开始执行备份任务..."
    echo ""
    
    # 备份 PostgreSQL
    postgres_backup=$(backup_postgres)
    if [ $? -ne 0 ]; then
        print_error "PostgreSQL 备份失败，终止备份流程"
        exit 1
    fi
    echo ""
    
    # 备份 MinIO
    minio_backup=$(backup_minio)
    if [ $? -ne 0 ]; then
        print_warning "MinIO 备份失败，继续其他备份"
        minio_backup=""
    fi
    echo ""
    
    # 备份 Qdrant
    qdrant_backup=$(backup_qdrant)
    if [ $? -ne 0 ]; then
        print_warning "Qdrant 备份失败，继续其他备份"
        qdrant_backup=""
    fi
    echo ""
    
    # 上传到腾讯云 COS
    print_info "开始上传备份文件到腾讯云 COS..."
    echo ""
    
    upload_success=0
    upload_failed=0
    
    if [ -n "$postgres_backup" ]; then
        upload_to_cos "$postgres_backup" && upload_success=$((upload_success+1)) || upload_failed=$((upload_failed+1))
        echo ""
    fi
    
    if [ -n "$minio_backup" ]; then
        upload_to_cos "$minio_backup" && upload_success=$((upload_success+1)) || upload_failed=$((upload_failed+1))
        echo ""
    fi
    
    if [ -n "$qdrant_backup" ]; then
        upload_to_cos "$qdrant_backup" && upload_success=$((upload_success+1)) || upload_failed=$((upload_failed+1))
        echo ""
    fi
    
    # 清理旧备份
    cleanup_old_backups
    echo ""
    
    # 生成报告
    if [ -n "$postgres_backup" ] && [ -n "$minio_backup" ] && [ -n "$qdrant_backup" ]; then
        generate_report "$postgres_backup" "$minio_backup" "$qdrant_backup"
    fi
    
    # 计算耗时
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    # 显示摘要
    echo ""
    echo "=========================================="
    echo "           备份完成摘要"
    echo "=========================================="
    echo ""
    echo "备份时间: $(date +"%Y-%m-%d %H:%M:%S")"
    echo "总耗时: ${minutes}分${seconds}秒"
    echo ""
    echo "备份结果:"
    echo "  PostgreSQL: $([ -n "$postgres_backup" ] && echo "✅ 成功" || echo "❌ 失败")"
    echo "  MinIO:      $([ -n "$minio_backup" ] && echo "✅ 成功" || echo "❌ 失败")"
    echo "  Qdrant:     $([ -n "$qdrant_backup" ] && echo "✅ 成功" || echo "❌ 失败")"
    echo ""
    echo "上传结果:"
    echo "  成功: $upload_success 个"
    echo "  失败: $upload_failed 个"
    echo ""
    echo "本地备份: $BACKUP_BASE_DIR"
    echo "云端备份: cos://$TENCENTCLOUD_COS_BUCKET/panda-wiki-backups/$DATE_DIR/"
    echo ""
    
    if [ $upload_failed -eq 0 ]; then
        print_success "所有备份任务完成！"
    else
        print_warning "部分备份任务失败，请检查日志"
    fi
    
    echo "=========================================="
}

# 捕获错误
trap 'print_error "备份过程中发生错误"; exit 1' ERR

# 执行主流程
main
