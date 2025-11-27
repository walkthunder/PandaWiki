#!/bin/bash

# PostgreSQL数据库恢复脚本
# 用途：从备份文件恢复PandaWiki的PostgreSQL数据库

set -e

# 配置变量
BACKUP_DIR="./backups/postgres"
CONTAINER_NAME="panda-wiki-postgres"
DB_NAME="panda-wiki"
DB_USER="panda-wiki"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}PostgreSQL数据库恢复工具${NC}"
echo ""

# 检查备份目录
if [ ! -d "$BACKUP_DIR" ]; then
    echo -e "${RED}错误: 备份目录 $BACKUP_DIR 不存在${NC}"
    exit 1
fi

# 列出可用的备份文件
echo -e "${YELLOW}可用的备份文件:${NC}"
BACKUPS=($(ls -t "$BACKUP_DIR"/panda-wiki_*.sql.gz 2>/dev/null))

if [ ${#BACKUPS[@]} -eq 0 ]; then
    echo -e "${RED}错误: 没有找到备份文件${NC}"
    exit 1
fi

for i in "${!BACKUPS[@]}"; do
    BACKUP_FILE="${BACKUPS[$i]}"
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    BACKUP_DATE=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$BACKUP_FILE" 2>/dev/null || stat -c "%y" "$BACKUP_FILE" 2>/dev/null | cut -d'.' -f1)
    echo "  [$i] $(basename $BACKUP_FILE) - $BACKUP_SIZE - $BACKUP_DATE"
done

# 选择备份文件
echo ""
read -p "请选择要恢复的备份文件编号 [0-$((${#BACKUPS[@]}-1))]: " SELECTION

if ! [[ "$SELECTION" =~ ^[0-9]+$ ]] || [ "$SELECTION" -ge ${#BACKUPS[@]} ]; then
    echo -e "${RED}错误: 无效的选择${NC}"
    exit 1
fi

SELECTED_BACKUP="${BACKUPS[$SELECTION]}"
echo -e "${YELLOW}已选择: $(basename $SELECTED_BACKUP)${NC}"

# 确认操作
echo ""
echo -e "${RED}警告: 此操作将覆盖当前数据库中的所有数据!${NC}"
read -p "确认要继续吗? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}操作已取消${NC}"
    exit 0
fi

# 检查容器是否运行
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}错误: 容器 $CONTAINER_NAME 未运行${NC}"
    exit 1
fi

# 读取数据库密码
if [ -f ".env" ]; then
    source .env
else
    echo -e "${RED}错误: .env 文件不存在${NC}"
    exit 1
fi

if [ -z "$POSTGRES_PASSWORD" ]; then
    echo -e "${RED}错误: POSTGRES_PASSWORD 未设置${NC}"
    exit 1
fi

# 解压备份文件
echo -e "${YELLOW}正在解压备份文件...${NC}"
TEMP_SQL_FILE="/tmp/panda-wiki_restore_$(date +%s).sql"
gunzip -c "$SELECTED_BACKUP" > "$TEMP_SQL_FILE"

# 停止依赖数据库的服务
echo -e "${YELLOW}正在停止相关服务...${NC}"
docker compose stop api consumer raglite

# 执行恢复
echo -e "${YELLOW}正在恢复数据库...${NC}"
docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$CONTAINER_NAME" \
    psql -U "$DB_USER" -d "$DB_NAME" < "$TEMP_SQL_FILE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}数据库恢复成功${NC}"
else
    echo -e "${RED}错误: 数据库恢复失败${NC}"
    rm -f "$TEMP_SQL_FILE"
    exit 1
fi

# 清理临时文件
rm -f "$TEMP_SQL_FILE"

# 重启服务
echo -e "${YELLOW}正在重启服务...${NC}"
docker compose up -d api consumer raglite

echo -e "${GREEN}数据库恢复流程完成!${NC}"
