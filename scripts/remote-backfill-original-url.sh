#!/bin/bash

# 远程执行 original_url 补全脚本
# 用途：从本地连接到远程服务器执行补全操作

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  远程 Original URL 补全工具${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 读取远程服务器配置
if [ -f "scripts/.remote-config" ]; then
    source scripts/.remote-config
    echo -e "${GREEN}✓ 从配置文件读取${NC}"
else
    echo -e "${YELLOW}请输入远程服务器信息:${NC}"
    read -p "远程主机地址: " REMOTE_HOST
    read -p "远程用户名: " REMOTE_USER
    read -p "远程项目路径: " REMOTE_PATH
    read -p "SSH端口 (默认: 22): " REMOTE_PORT
    REMOTE_PORT=${REMOTE_PORT:-22}
fi

echo "  主机: $REMOTE_USER@$REMOTE_HOST"
echo "  路径: $REMOTE_PATH"
echo ""

# 检查 SSH 连接
echo -e "${YELLOW}检查 SSH 连接...${NC}"
if ssh -p "${REMOTE_PORT:-22}" -o ConnectTimeout=5 "$REMOTE_USER@$REMOTE_HOST" "echo 'OK'" 2>/dev/null; then
    echo -e "${GREEN}✓ SSH 连接成功${NC}"
else
    echo -e "${RED}✗ SSH 连接失败${NC}"
    exit 1
fi

# 确认操作
echo ""
echo -e "${YELLOW}此操作将在远程服务器上:${NC}"
echo "  1. 上传 SQL 脚本"
echo "  2. 执行补全操作"
echo "  3. 显示执行结果"
echo ""
read -p "确认要继续吗? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}操作已取消${NC}"
    exit 0
fi

# 备份数据库（可选）
echo ""
read -p "是否先备份远程数据库? (yes/no): " BACKUP

if [ "$BACKUP" = "yes" ]; then
    echo -e "${YELLOW}正在备份远程数据库...${NC}"
    ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "cd $REMOTE_PATH && ./scripts/backup-database.sh" 2>&1 | tail -5
    echo -e "${GREEN}✓ 备份完成${NC}"
fi

# 上传 SQL 脚本
echo ""
echo -e "${YELLOW}上传 SQL 脚本到远程服务器...${NC}"
scp -P "${REMOTE_PORT:-22}" scripts/backfill-original-url.sql "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/scripts/"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 上传成功${NC}"
else
    echo -e "${RED}✗ 上传失败${NC}"
    exit 1
fi

# 执行补全操作
echo ""
echo -e "${GREEN}开始执行补全操作...${NC}"
echo ""

ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "cd $REMOTE_PATH && bash -c '
source .env
docker exec -i -e PGPASSWORD=\"\$POSTGRES_PASSWORD\" panda-wiki-postgres \
    psql -U panda-wiki -d panda-wiki < scripts/backfill-original-url.sql
'"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  补全操作成功完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 显示验证结果
    echo -e "${YELLOW}验证结果:${NC}"
    ssh -p "${REMOTE_PORT:-22}" "$REMOTE_USER@$REMOTE_HOST" "cd $REMOTE_PATH && docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c \"
    SELECT 
        COUNT(*) as total_documents,
        COUNT(CASE WHEN original_url IS NOT NULL AND original_url != '' THEN 1 END) as has_original_url,
        ROUND(100.0 * COUNT(CASE WHEN original_url IS NOT NULL AND original_url != '' THEN 1 END) / NULLIF(COUNT(*), 0), 2) as coverage_percent
    FROM nodes 
    WHERE type = 2;
    \""
    
    echo ""
    echo -e "${YELLOW}下一步:${NC}"
    echo "  1. 检查详细数据: ./scripts/check-remote-original-url.sh"
    echo "  2. 验证应用功能"
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  补全操作失败!${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo -e "${YELLOW}数据已自动回滚，不会有任何影响${NC}"
    exit 1
fi
