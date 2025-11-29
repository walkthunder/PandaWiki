#!/bin/bash

# 完整备份脚本（包含文件）
# 用途：备份 PostgreSQL + MinIO 文件

set -e

# 配置变量
BACKUP_ROOT="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="$BACKUP_ROOT/full_with_files_${TIMESTAMP}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  完整备份（包含文件）${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}备份时间: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 1. 备份 PostgreSQL
echo -e "${GREEN}[1/2] 备份 PostgreSQL 数据库...${NC}"
if [ -f ".env" ]; then
    source .env
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" panda-wiki-postgres \
        pg_dump -U panda-wiki -d panda-wiki \
        --format=plain --no-owner --no-acl > "$BACKUP_DIR/postgres.sql"
    
    if [ $? -eq 0 ]; then
        gzip "$BACKUP_DIR/postgres.sql"
        PG_SIZE=$(du -h "$BACKUP_DIR/postgres.sql.gz" | cut -f1)
        echo -e "${GREEN}✓ PostgreSQL 备份完成 (大小: $PG_SIZE)${NC}"
    else
        echo -e "${RED}✗ PostgreSQL 备份失败${NC}"
        exit 1
    fi
else
    echo -e "${RED}错误: .env 文件不存在${NC}"
    exit 1
fi

# 2. 备份 MinIO 文件
echo ""
echo -e "${GREEN}[2/2] 备份 MinIO 文件...${NC}"
if [ -d "./data/minio" ]; then
    echo -e "${YELLOW}正在压缩 MinIO 数据...${NC}"
    tar -czf "$BACKUP_DIR/minio.tar.gz" -C ./data minio
    
    if [ $? -eq 0 ]; then
        MINIO_SIZE=$(du -h "$BACKUP_DIR/minio.tar.gz" | cut -f1)
        echo -e "${GREEN}✓ MinIO 备份完成 (大小: $MINIO_SIZE)${NC}"
    else
        echo -e "${RED}✗ MinIO 备份失败${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}警告: MinIO 数据目录不存在${NC}"
fi

# 备份配置文件
echo ""
echo -e "${YELLOW}备份配置文件...${NC}"
cp .env "$BACKUP_DIR/.env.backup" 2>/dev/null || true
cp docker-compose.yml "$BACKUP_DIR/docker-compose.yml.backup" 2>/dev/null || true

# 计算总大小
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  备份完成!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}备份信息:${NC}"
echo "  位置: $BACKUP_DIR"
echo "  大小: $TOTAL_SIZE"
echo "  PostgreSQL: $PG_SIZE"
echo "  MinIO: $MINIO_SIZE"
echo ""
echo -e "${YELLOW}备份内容:${NC}"
echo "  ✓ 所有文档内容（Markdown）"
echo "  ✓ 用户数据和权限"
echo "  ✓ 知识库配置"
echo "  ✓ 对话历史"
echo "  ✓ 图片和附件文件"
echo "  ✓ 配置文件"
echo ""
echo -e "${GREEN}数据已完整备份，可以安全恢复!${NC}"
