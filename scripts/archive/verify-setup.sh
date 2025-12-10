#!/bin/bash

# 验证本地开发环境配置

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "🔍 验证本地开发环境..."
echo ""

# 1. 检查 Docker 服务
echo -e "${YELLOW}1. 检查 Docker 服务...${NC}"
if docker compose -f docker-compose.local.yml ps | grep -q "Up"; then
  echo -e "${GREEN}✅ Docker 服务正在运行${NC}"
else
  echo -e "${RED}❌ Docker 服务未运行${NC}"
  echo "   请运行: docker compose -f docker-compose.local.yml up -d"
  exit 1
fi
echo ""

# 2. 检查后端 API
echo -e "${YELLOW}2. 检查后端 API...${NC}"
if curl -s http://localhost:8000 > /dev/null 2>&1; then
  echo -e "${GREEN}✅ 后端 API 正在运行 (http://localhost:8000)${NC}"
else
  echo -e "${RED}❌ 后端 API 未运行${NC}"
  echo "   请运行: ./run-api.sh"
  exit 1
fi
echo ""

# 3. 检查 PostgreSQL
echo -e "${YELLOW}3. 检查 PostgreSQL...${NC}"
if docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki > /dev/null 2>&1; then
  echo -e "${GREEN}✅ PostgreSQL 正常${NC}"
else
  echo -e "${RED}❌ PostgreSQL 未就绪${NC}"
  exit 1
fi
echo ""

# 4. 检查 Redis
echo -e "${YELLOW}4. 检查 Redis...${NC}"
if docker exec panda-wiki-redis redis-cli -a panda-wiki ping 2>&1 | grep -q "PONG"; then
  echo -e "${GREEN}✅ Redis 正常${NC}"
else
  echo -e "${RED}❌ Redis 未就绪${NC}"
  exit 1
fi
echo ""

# 5. 检查 MinIO
echo -e "${YELLOW}5. 检查 MinIO...${NC}"
if curl -s http://localhost:9000/minio/health/live > /dev/null 2>&1; then
  echo -e "${GREEN}✅ MinIO 正常${NC}"
else
  echo -e "${RED}❌ MinIO 未就绪${NC}"
  exit 1
fi
echo ""

# 6. 检查 Raglite
echo -e "${YELLOW}6. 检查 Raglite...${NC}"
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Raglite 正常${NC}"
else
  echo -e "${RED}❌ Raglite 未就绪${NC}"
  exit 1
fi
echo ""

# 7. 检查配置
echo -e "${YELLOW}7. 检查后端配置...${NC}"
if [ -f backend/config.yml ]; then
  if grep -q "host=localhost" backend/config.yml; then
    echo -e "${GREEN}✅ 后端配置正确${NC}"
  else
    echo -e "${YELLOW}⚠️  后端配置可能不正确${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  backend/config.yml 不存在${NC}"
fi
echo ""

# 8. 检查管理后台配置
echo -e "${YELLOW}8. 检查管理后台配置...${NC}"
if [ -f web/admin/.env ]; then
  if grep -q "TARGET=http://localhost:8000" web/admin/.env; then
    echo -e "${GREEN}✅ 管理后台配置正确${NC}"
  else
    echo -e "${YELLOW}⚠️  管理后台配置可能不正确${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  web/admin/.env 不存在${NC}"
fi
echo ""

# 总结
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 环境验证完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}下一步：${NC}"
echo "1. 启动管理后台: ./run-admin.sh"
echo "2. 访问: http://localhost:5173"
echo "3. 登录: admin / panda-wiki"
echo "4. 创建知识库"
echo ""
echo -e "${YELLOW}提示：${NC}"
echo "- 创建知识库时，后端日志应该显示: 'skipping caddy sync: socket path is empty'"
echo "- 不应该看到 Caddy 错误"
echo ""
