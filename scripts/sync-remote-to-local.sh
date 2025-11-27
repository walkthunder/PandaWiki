#!/bin/bash

# 远程数据同步到本地脚本
# 用途：一键备份远程数据库，下载到本地，并导入到本地数据库

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
REMOTE_HOST="8.140.221.27"
REMOTE_USER="root"
REMOTE_PATH="/root"

# 打印标题
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  远程数据同步到本地 - 一键脚本${NC}"
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

# 打印警告
print_warning() {
    echo -e "${YELLOW}警告: $1${NC}"
}

# 打印信息
print_info() {
    echo -e "${YELLOW}$1${NC}"
}

# 检查必要的工具
check_requirements() {
    print_step "检查必要的工具..."
    
    local missing_tools=()
    
    if ! command -v ssh &> /dev/null; then
        missing_tools+=("ssh")
    fi
    
    if ! command -v scp &> /dev/null; then
        missing_tools+=("scp")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if ! command -v gunzip &> /dev/null; then
        missing_tools+=("gunzip")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "缺少必要的工具: ${missing_tools[*]}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ 所有必要工具已安装${NC}"
}

# 读取远程服务器配置
read_remote_config() {
    print_step "配置远程服务器信息..."
    
    # 尝试从环境变量读取
    if [ -n "$REMOTE_HOST" ] && [ -n "$REMOTE_USER" ] && [ -n "$REMOTE_PATH" ]; then
        echo -e "${GREEN}✓ 从环境变量读取配置${NC}"
        echo "  主机: $REMOTE_USER@$REMOTE_HOST"
        echo "  路径: $REMOTE_PATH"
    else
        # 交互式输入
        echo -e "${YELLOW}请输入远程服务器信息:${NC}"
        read -p "远程主机地址 (例: 192.168.1.100): " REMOTE_HOST
        read -p "远程用户名 (例: root): " REMOTE_USER
        read -p "远程项目路径 (例: /root/PandaWiki): " REMOTE_PATH
        read -p "SSH端口 (默认: 22): " REMOTE_PORT
        REMOTE_PORT=${REMOTE_PORT:-22}
    fi
    
    # 验证SSH连接
    echo ""
    print_info "测试SSH连接..."
    if ssh -p "${REMOTE_PORT:-22}" -o ConnectTimeout=5 -o BatchMode=yes "$REMOTE_USER@$REMOTE_HOST" "echo 'SSH连接成功'" 2>/dev/null; then
        echo -e "${GREEN}✓ SSH连接测试成功${NC}"
    else
        print_warning "SSH连接测试失败，可能需要输入密码"
        read -p "是否继续? (yes/no): " CONTINUE
        if [ "$CONTINUE" != "yes" ]; then
            exit 0
        fi
    fi
}

# 在远程服务器上执行备份
backup_remote_database() {
    print_step "步骤 1/4: 在远程服务器上备份数据库..."
    
    local remote_backup_script="
cd $REMOTE_PATH
TIMESTAMP=\$(date +\"%Y%m%d_%H%M%S\")
BACKUP_DIR=\"./backups/postgres\"
mkdir -p \"\$BACKUP_DIR\"
BACKUP_FILE=\"\$BACKUP_DIR/panda-wiki_\${TIMESTAMP}.sql\"

# 读取环境变量
if [ -f .env ]; then
    source .env
else
    echo 'ERROR: .env file not found'
    exit 1
fi

# 检查容器是否运行
if ! docker ps --format '{{.Names}}' | grep 'panda-wiki-postgres'; then
    echo 'ERROR: Container panda-wiki-postgres is not running'
    exit 1
fi

# 执行备份
echo 'Starting database backup...'
docker exec -e PGPASSWORD=\"\$POSTGRES_PASSWORD\" panda-wiki-postgres \
    pg_dump -U panda-wiki -d panda-wiki \
    --format=plain --no-owner --no-acl > \"\$BACKUP_FILE\"

if [ \$? -eq 0 ]; then
    # 压缩备份
    gzip \"\$BACKUP_FILE\"
    echo \"SUCCESS:\$BACKUP_FILE.gz\"
else
    echo 'ERROR: Backup failed'
    exit 1
fi
"
    
    print_info "正在远程服务器上执行备份..."
    REMOTE_BACKUP_OUTPUT=$(ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "$remote_backup_script")
    
    if echo "$REMOTE_BACKUP_OUTPUT" | grep -q "SUCCESS:"; then
        REMOTE_BACKUP_FILE=$(echo "$REMOTE_BACKUP_OUTPUT" | grep "SUCCESS:" | cut -d':' -f2)
        echo -e "${GREEN}✓ 远程备份完成: $REMOTE_BACKUP_FILE${NC}"
    else
        print_error "远程备份失败"
        echo "$REMOTE_BACKUP_OUTPUT"
        exit 1
    fi
}

# 下载备份文件到本地
download_backup() {
    print_step "步骤 2/4: 下载备份文件到本地..."
    
    mkdir -p "$BACKUP_DIR"
    LOCAL_BACKUP_FILE="$BACKUP_DIR/remote_sync_${TIMESTAMP}.sql.gz"
    
    print_info "正在下载: $REMOTE_BACKUP_FILE"
    print_info "保存到: $LOCAL_BACKUP_FILE"
    
    scp -P "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BACKUP_FILE" "$LOCAL_BACKUP_FILE"
    
    if [ $? -eq 0 ]; then
        BACKUP_SIZE=$(du -h "$LOCAL_BACKUP_FILE" | cut -f1)
        echo -e "${GREEN}✓ 下载完成 (大小: $BACKUP_SIZE)${NC}"
    else
        print_error "下载失败"
        exit 1
    fi
}

# 导入到本地数据库
import_to_local() {
    print_step "步骤 3/4: 导入到本地数据库..."
    
    # 检查本地容器
    if ! docker ps --format '{{.Names}}' | grep -q "^${LOCAL_CONTAINER}$"; then
        print_error "本地容器 $LOCAL_CONTAINER 未运行"
        print_info "请先启动本地数据库: docker compose up -d postgres"
        exit 1
    fi
    
    # 读取本地数据库密码
    if [ -f ".env" ]; then
        source .env
    else
        print_error ".env 文件不存在"
        exit 1
    fi
    
    if [ -z "$POSTGRES_PASSWORD" ]; then
        print_error "POSTGRES_PASSWORD 未设置"
        exit 1
    fi
    
    # 确认操作
    echo ""
    print_warning "此操作将覆盖本地数据库中的所有数据!"
    read -p "确认要继续吗? (yes/no): " CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        print_info "操作已取消"
        exit 0
    fi
    
    # 停止依赖数据库的服务
    print_info "正在停止相关服务..."
    docker compose stop api consumer raglite 2>/dev/null || true
    
    # 解压备份文件
    print_info "正在解压备份文件..."
    TEMP_SQL_FILE="/tmp/panda-wiki_import_${TIMESTAMP}.sql"
    gunzip -c "$LOCAL_BACKUP_FILE" > "$TEMP_SQL_FILE"
    
    # 执行导入
    print_info "正在导入数据库（这可能需要几分钟）..."
    docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$LOCAL_CONTAINER" \
        psql -U "$LOCAL_DB_USER" -d "$LOCAL_DB_NAME" < "$TEMP_SQL_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ 数据库导入成功${NC}"
    else
        print_error "数据库导入失败"
        rm -f "$TEMP_SQL_FILE"
        exit 1
    fi
    
    # 清理临时文件
    rm -f "$TEMP_SQL_FILE"
    
    # 重启服务
    print_info "正在重启服务..."
    docker compose up -d api consumer raglite
    
    echo -e "${GREEN}✓ 服务已重启${NC}"
}

# 清理远程备份（可选）
cleanup_remote() {
    print_step "步骤 4/4: 清理远程备份文件（可选）..."
    
    read -p "是否删除远程服务器上的备份文件? (yes/no): " CLEANUP
    
    if [ "$CLEANUP" = "yes" ]; then
        ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "rm -f $REMOTE_BACKUP_FILE"
        echo -e "${GREEN}✓ 远程备份文件已删除${NC}"
    else
        print_info "远程备份文件保留: $REMOTE_BACKUP_FILE"
    fi
}

# 显示总结
show_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  同步完成!${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}操作摘要:${NC}"
    echo "  远程主机: $REMOTE_USER@$REMOTE_HOST"
    echo "  本地备份: $LOCAL_BACKUP_FILE"
    echo "  备份大小: $(du -h "$LOCAL_BACKUP_FILE" | cut -f1)"
    echo "  完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo -e "${YELLOW}下一步操作:${NC}"
    echo "  1. 验证数据: 访问 http://localhost:3000"
    echo "  2. 检查日志: docker compose logs -f api"
    echo "  3. 查看备份: ls -lh $BACKUP_DIR"
    echo ""
}

# 主函数
main() {
    print_header
    
    # 检查是否在项目根目录
    if [ ! -f "docker-compose.yml" ]; then
        print_error "请在项目根目录下运行此脚本"
        exit 1
    fi
    
    check_requirements
    read_remote_config
    backup_remote_database
    download_backup
    import_to_local
    cleanup_remote
    show_summary
}

# 执行主函数
main
