#!/bin/bash

# 数据库迁移回滚脚本

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}⚠️  数据库迁移回滚工具${NC}"
echo ""
echo -e "${YELLOW}警告：此操作将删除 original_url 字段及其所有数据！${NC}"
echo ""

# 检查 Docker 是否运行
if ! docker ps | grep -q panda-wiki-postgres; then
  echo -e "${RED}❌ PostgreSQL 容器未运行${NC}"
  exit 1
fi

# 检查字段是否存在
echo -e "${YELLOW}1. 检查 original_url 字段...${NC}"
if ! docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" 2>/dev/null | grep -q "original_url"; then
  echo -e "${GREEN}✅ original_url 字段不存在，无需回滚${NC}"
  exit 0
fi
echo -e "${YELLOW}⚠️  original_url 字段存在${NC}"
echo ""

# 询问是否继续
echo -e "${RED}确认要回滚迁移吗？这将删除 original_url 字段！${NC}"
read -p "输入 'yes' 继续: " -r
echo
if [[ ! $REPLY == "yes" ]]; then
  echo "回滚已取消"
  exit 0
fi
echo ""

# 创建备份
echo -e "${YELLOW}2. 创建数据库备份...${NC}"
BACKUP_FILE="backup_before_rollback_$(date +%Y%m%d_%H%M%S).sql"
docker exec panda-wiki-postgres pg_dump -U panda-wiki panda-wiki > "$BACKUP_FILE"
if [ -s "$BACKUP_FILE" ]; then
  echo -e "${GREEN}✅ 备份成功: $BACKUP_FILE${NC}"
else
  echo -e "${RED}❌ 备份失败${NC}"
  exit 1
fi
echo ""

# 执行回滚
echo -e "${YELLOW}3. 执行回滚...${NC}"
if [ -f "backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql" ]; then
  docker exec -i panda-wiki-postgres psql -U panda-wiki -d panda-wiki < backend/store/pg/migration/000032_add_original_url_to_nodes.down.sql
  echo -e "${GREEN}✅ 回滚 SQL 执行成功${NC}"
else
  echo -e "${RED}❌ 回滚文件不存在${NC}"
  exit 1
fi
echo ""

# 验证回滚
echo -e "${YELLOW}4. 验证回滚结果...${NC}"
if docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c "\d nodes" 2>/dev/null | grep -q "original_url"; then
  echo -e "${RED}❌ 回滚失败，字段仍然存在${NC}"
  exit 1
else
  echo -e "${GREEN}✅ 回滚成功！original_url 字段已删除${NC}"
fi
echo ""

# 完成
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 迁移回滚完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}备份文件：${NC}$BACKUP_FILE"
echo -e "${YELLOW}下一步：${NC}"
echo "1. 切换到旧版本代码"
echo "2. 重启后端服务"
echo ""
