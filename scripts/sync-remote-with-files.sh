#!/bin/bash

# 远程数据同步到本地脚本（包含文件）
# 用途：同步 PostgreSQL + MinIO 文件

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置变量
BACKUP_DIR="./backups/remote_sync"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOCAL_CONTAINER="panda-wiki-postgres"
LOCAL_DB_NAME="panda-wiki"
LOCAL_DB_USER="panda-wiki"

# 打印标题
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  远程完整同步（包含文件）${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# 打印步骤
print_step() {
    echo ""
    echo -e "${GREEN}>>> $1${NC}"
    echo ""
}

# 打印错误
print_error() {
    echo -e "${RED}错误: $1${NC}"
}

# 打印信息
print_info() {
    echo -e "${YELLOW}$1${NC}"
}

# 读取远程服务器配置
read_remote_config() {
    print_step "配置远程服务器信息..."
    
    if [ -n "$REMOTE_HOST" ] && [ -n "$REMOTE_USER" ] && [ -n "$REMOTE_PATH" ]; then
        echo -e "${GREEN}✓ 从环境变量读取配置${NC}"
        echo "  主机: $REMOTE_USER@$REMOTE_HOST"
        echo "  路径: $REMOTE_PATH"
    else
        if [ -f "scripts/.remote-config" ]; then
            source scripts/.remote-config
            echo -e "${GREEN}✓ 从配置文件读取${NC}"
            echo "  主机: $REMOTE_USER@$REMOTE_HOST"
            echo "  路径: $REMOTE_PATH"
        else
            echo -e "${YELLOW}请输入远程服务器信息:${NC}"
            read -p "远程主机地址: " REMOTE_HOST
            read -p "远程用户名: " REMOTE_USER
            read -p "远程项目路径: " REMOTE_PATH
            read -p "SSH端口 (默认: 22): " REMOTE_PORT
            REMOTE_PORT=${REMOTE_PORT:-22}
        fi
    fi
}

# 在远程服务器上执行备份
backup_remote() {
    print_step "步骤 1/5: 在远程服务器上备份数据..."
    
    local remote_backup_script="
cd $REMOTE_PATH
TIMESTAMP=\$(date +\"%Y%m%d_%H%M%S\")
BACKUP_DIR=\"./backups/full_sync\"
mkdir -p \"\$BACKUP_DIR\"

# 备份 PostgreSQL
echo 'Backing up PostgreSQL...'
if [ -f .env ]; then
    source .env
    docker exec -e PGPASSWORD=\"\$POSTGRES_PASSWORD\" panda-wiki-postgres \
        pg_dump -U panda-wiki -d panda-wiki \
        --format=plain --no-owner --no-acl > \"\$BACKUP_DIR/postgres_\${TIMESTAMP}.sql\"
    gzip \"\$BACKUP_DIR/postgres_\${TIMESTAMP}.sql\"
    echo \"PostgreSQL backup: \$BACKUP_DIR/postgres_\${TIMESTAMP}.sql.gz\"
else
    echo 'ERROR: .env not found'
    exit 1
fi

# 备份 MinIO
echo 'Backing up MinIO...'
tar -czf \"\$BACKUP_DIR/minio_\${TIMESTAMP}.tar.gz\" -C ./data minio
echo \"MinIO backup: \$BACKUP_DIR/minio_\${TIMESTAMP}.tar.gz\"

echo \"SUCCESS:\$BACKUP_DIR/postgres_\${TIMESTAMP}.sql.gz:\$BACKUP_DIR/minio_\${TIMESTAMP}.tar.gz\"
"
    
    print_info "正在远程服务器上执行备份..."
    REMOTE_BACKUP_OUTPUT=$(ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "$remote_backup_script")
    
    if echo "$REMOTE_BACKUP_OUTPUT" | grep -q "SUCCESS:"; then
        BACKUP_INFO=$(echo "$REMOTE_BACKUP_OUTPUT" | grep "SUCCESS:" | cut -d':' -f2-)
        REMOTE_PG_FILE=$(echo "$BACKUP_INFO" | cut -d':' -f1)
        REMOTE_MINIO_FILE=$(echo "$BACKUP_INFO" | cut -d':' -f2)
        echo -e "${GREEN}✓ 远程备份完成${NC}"
        echo "  PostgreSQL: $REMOTE_PG_FILE"
        echo "  MinIO: $REMOTE_MINIO_FILE"
    else
        print_error "远程备份失败"
        echo "$REMOTE_BACKUP_OUTPUT"
        exit 1
    fi
}

# 下载备份文件
download_backups() {
    print_step "步骤 2/5: 下载备份文件到本地..."
    
    mkdir -p "$BACKUP_DIR"
    LOCAL_PG_FILE="$BACKUP_DIR/postgres_${TIMESTAMP}.sql.gz"
    LOCAL_MINIO_FILE="$BACKUP_DIR/minio_${TIMESTAMP}.tar.gz"
    
    # 下载 PostgreSQL 备份
    print_info "下载 PostgreSQL 备份..."
    scp -P "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PG_FILE" "$LOCAL_PG_FILE"
    PG_SIZE=$(du -h "$LOCAL_PG_FILE" | cut -f1)
    echo -e "${GREEN}✓ PostgreSQL 下载完成 (大小: $PG_SIZE)${NC}"
    
    # 下载 MinIO 备份
    print_info "下载 MinIO 备份..."
    scp -P "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_MINIO_FILE" "$LOCAL_MINIO_FILE"
    MINIO_SIZE=$(du -h "$LOCAL_MINIO_FILE" | cut -f1)
    echo -e "${GREEN}✓ MinIO 下载完成 (大小: $MINIO_SIZE)${NC}"
}

# 导入 PostgreSQL
import_postgres() {
    print_step "步骤 3/5: 导入 PostgreSQL 数据库..."
    
    if ! docker ps --format '{{.Names}}' | grep -q "^${LOCAL_CONTAINER}$"; then
        print_error "本地容器 $LOCAL_CONTAINER 未运行"
        exit 1
    fi
    
    if [ -f ".env" ]; then
        source .env
    else
        print_error ".env 文件不存在"
        exit 1
    fi
    
    echo ""
    print_info "⚠️  此操作将覆盖本地数据库!"
    read -p "确认要继续吗? (yes/no): " CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        print_info "操作已取消"
        exit 0
    fi
    
    print_info "停止相关服务..."
    docker compose stop api consumer raglite 2>/dev/null || true
    
    print_info "解压并导入数据库..."
    TEMP_SQL_FILE="/tmp/panda-wiki_import_${TIMESTAMP}.sql"
    gunzip -c "$LOCAL_PG_FILE" > "$TEMP_SQL_FILE"
    
    docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$LOCAL_CONTAINER" \
        psql -U "$LOCAL_DB_USER" -d "$LOCAL_DB_NAME" < "$TEMP_SQL_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ PostgreSQL 导入成功${NC}"
        rm -f "$TEMP_SQL_FILE"
    else
        print_error "PostgreSQL 导入失败"
        rm -f "$TEMP_SQL_FILE"
        exit 1
    fi
}

# 恢复 MinIO 文件
restore_minio() {
    print_step "步骤 4/5: 恢复 MinIO 文件..."
    
    print_info "停止 MinIO 服务..."
    docker compose stop minio
    
    print_info "备份当前 MinIO 数据..."
    if [ -d "./data/minio" ]; then
        mv ./data/minio "./data/minio.backup.${TIMESTAMP}"
        echo -e "${GREEN}✓ 当前数据已备份到: ./data/minio.backup.${TIMESTAMP}${NC}"
    fi
    
    print_info "解压 MinIO 数据..."
    tar -xzf "$LOCAL_MINIO_FILE" -C ./data/
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ MinIO 文件恢复成功${NC}"
    else
        print_error "MinIO 恢复失败"
        # 恢复备份
        if [ -d "./data/minio.backup.${TIMESTAMP}" ]; then
            mv "./data/minio.backup.${TIMESTAMP}" ./data/minio
        fi
        exit 1
    fi
    
    print_info "重启服务..."
    docker compose up -d
    
    echo -e "${GREEN}✓ 所有服务已重启${NC}"
}

# 清理远程备份
cleanup_remote() {
    print_step "步骤 5/5: 清理远程备份文件（可选）..."
    
    read -p "是否删除远程服务器上的备份文件? (yes/no): " CLEANUP
    
    if [ "$CLEANUP" = "yes" ]; then
        ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "rm -f $REMOTE_PG_FILE $REMOTE_MINIO_FILE"
        echo -e "${GREEN}✓ 远程备份文件已删除${NC}"
    else
        print_info "远程备份文件保留"
    fi
}

# 显示总结
show_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  完整同步完成!${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}同步信息:${NC}"
    echo "  远程主机: $REMOTE_USER@$REMOTE_HOST"
    echo "  PostgreSQL: $LOCAL_PG_FILE ($PG_SIZE)"
    echo "  MinIO: $LOCAL_MINIO_FILE ($MINIO_SIZE)"
    echo "  完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo -e "${YELLOW}同步内容:${NC}"
    echo "  ✓ 所有文档内容"
    echo "  ✓ 用户数据"
    echo "  ✓ 图片和附件"
    echo "  ✓ 知识库配置"
    echo ""
    echo -e "${GREEN}数据已完整同步!${NC}"
}

# 主函数
main() {
    print_header
    
    if [ ! -f "docker-compose.yml" ]; then
        print_error "请在项目根目录下运行此脚本"
        exit 1
    fi
    
    read_remote_config
    backup_remote
    download_backups
    import_postgres
    restore_minio
    cleanup_remote
    show_summary
}

# 执行主函数
main
