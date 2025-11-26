#!/bin/bash

# 数据库迁移脚本
# 用途：安全地执行数据库迁移

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}🔄 数据库迁移工具${NC}"
echo ""

# 检查 Docker 是否运行
if ! docker ps | grep -q panda-wiki-postgres; then
  echo -e "${RED}❌ PostgreSQL 容器未运行${NC}"
  echo "请先启动 Docker 服务："
  echo "  docker compose -f docker-compose.local.yml up -d postgres"
  exit 1
fi

# 检查数据库连接
echo -e "${YELLOW}1. 检查数据库连接...${NC}"
if docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki > /dev/null 2>&1; then
  echo -e "${GREEN}✅ 数据库连接正常${NC}"
else
  echo -e "${RED}❌ 无法连接到数据库${NC}"
  exit 1
fi
echo ""

# 显示当前数据库状态
echo -e "${YELLOW}2. 当前数据库状态：${NC}"
echo "数据库名称: panda-wiki"
echo "用户: panda-wiki"
echo ""

# 检查 original_url 字段是否已存在
echo -e "${YELLOW}3. 检查 original_url 字段...${NC}"
if docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" 2>/dev/null | grep -q "original_url"; then
  echo -e "${GREEN}✅ original_url 字段已存在，无需迁移${NC}"
  echo ""
  echo -e "${YELLOW}字段信息：${NC}"
  docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url
  exit 0
fi
echo -e "${YELLOW}⚠️  original_url 字段不存在，需要执行迁移${NC}"
echo ""

# 询问是否继续
read -p "是否继续执行迁移？(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "迁移已取消"
  exit 0
fi
echo ""

# 创建备份
echo -e "${YELLOW}4. 创建数据库备份...${NC}"
BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > "$BACKUP_FILE"
if [ -s "$BACKUP_FILE" ]; then
  BACKUP_SIZE=$(ls -lh "$BACKUP_FILE" | awk '{print $5}')
  echo -e "${GREEN}✅ 备份成功: $BACKUP_FILE (大小: $BACKUP_SIZE)${NC}"
else
  echo -e "${RED}❌ 备份失败${NC}"
  exit 1
fi
echo ""

# 执行迁移
echo -e "${YELLOW}5. 执行数据库迁移...${NC}"
if [ -f "backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql" ]; then
  docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql
  echo -e "${GREEN}✅ 迁移 SQL 执行成功${NC}"
else
  echo -e "${RED}❌ 迁移文件不存在: backend/store/pg/migration/000032_add_original_url_to_nodes.up.sql${NC}"
  exit 1
fi
echo ""

# 验证迁移
echo -e "${YELLOW}6. 验证迁移结果...${NC}"
if docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" 2>/dev/null | grep -q "original_url"; then
  echo -e "${GREEN}✅ 迁移成功！original_url 字段已添加${NC}"
  echo ""
  echo -e "${YELLOW}字段信息：${NC}"
  docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" | grep original_url
else
  echo -e "${RED}❌ 迁移验证失败${NC}"
  echo "请检查数据库日志"
  exit 1
fi
echo ""

# 完成
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 数据库迁移完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}备份文件：${NC}$BACKUP_FILE"
echo -e "${YELLOW}下一步：${NC}"
echo "1. 重启后端服务: ./run-api.sh"
echo "2. 测试创建文档功能"
echo "3. 如有问题，可使用备份恢复："
echo "   docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < $BACKUP_FILE"
echo ""
