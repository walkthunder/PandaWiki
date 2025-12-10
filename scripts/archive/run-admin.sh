#!/bin/bash

# 启动管理后台脚本

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🎨 启动管理后台...${NC}"

# 检查依赖服务
if ! docker ps | grep -q panda-wiki-postgres; then
  echo -e "${YELLOW}⚠️  依赖服务未启动，正在启动...${NC}"
  docker compose -f docker-compose.local.yml up -d
  echo "等待服务就绪..."
  sleep 10
fi

# 检查后端 API
if ! curl -s http://localhost:8000 > /dev/null 2>&1; then
  echo -e "${YELLOW}⚠️  后端 API 未启动，请先运行: ./run-api.sh${NC}"
  exit 1
fi

cd web/admin

# 检查依赖
if [ ! -d "node_modules" ]; then
  echo -e "${YELLOW}📦 安装依赖...${NC}"
  pnpm install
fi

echo -e "${GREEN}✅ 启动管理后台在 http://localhost:5173${NC}"
echo -e "${YELLOW}💡 默认账号: admin / panda-wiki${NC}"
echo ""

pnpm dev
