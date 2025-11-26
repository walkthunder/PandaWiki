#!/bin/bash

# 数据库备份脚本

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}💾 数据库备份工具${NC}"
echo ""

# 检查 Docker 是否运行
if ! docker ps | grep -q panda-wiki-postgres; then
  echo -e "${RED}❌ PostgreSQL 容器未运行${NC}"
  exit 1
fi

# 创建备份目录
BACKUP_DIR="backups"
mkdir -p "$BACKUP_DIR"

# 生成备份文件名
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/panda-wiki_$TIMESTAMP.sql"

echo -e "${YELLOW}正在备份数据库...${NC}"
echo "数据库: panda-wiki"
echo "备份文件: $BACKUP_FILE"
echo ""

# 执行备份
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > "$BACKUP_FILE"

# 验证备份
if [ -s "$BACKUP_FILE" ]; then
  BACKUP_SIZE=$(ls -lh "$BACKUP_FILE" | awk '{print $5}')
  echo -e "${GREEN}✅ 备份成功！${NC}"
  echo ""
  echo "文件: $BACKUP_FILE"
  echo "大小: $BACKUP_SIZE"
  echo ""
  
  # 压缩备份（可选）
  echo -e "${YELLOW}正在压缩备份文件...${NC}"
  gzip "$BACKUP_FILE"
  COMPRESSED_FILE="${BACKUP_FILE}.gz"
  COMPRESSED_SIZE=$(ls -lh "$COMPRESSED_FILE" | awk '{print $5}')
  echo -e "${GREEN}✅ 压缩完成！${NC}"
  echo "压缩文件: $COMPRESSED_FILE"
  echo "压缩后大小: $COMPRESSED_SIZE"
  echo ""
  
  # 显示恢复命令
  echo -e "${YELLOW}恢复命令：${NC}"
  echo "gunzip -c $COMPRESSED_FILE | docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki"
else
  echo -e "${RED}❌ 备份失败${NC}"
  exit 1
fi

# 清理旧备份（保留最近 10 个）
echo -e "${YELLOW}清理旧备份...${NC}"
cd "$BACKUP_DIR"
ls -t panda-wiki_*.sql.gz 2>/dev/null | tail -n +11 | xargs -r rm
BACKUP_COUNT=$(ls -1 panda-wiki_*.sql.gz 2>/dev/null | wc -l)
echo -e "${GREEN}✅ 当前保留 $BACKUP_COUNT 个备份文件${NC}"
echo ""
