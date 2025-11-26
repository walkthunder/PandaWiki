#!/bin/bash

# 一键启动所有本地开发服务

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}🚀 启动 PandaWiki 本地开发环境${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 1. 检查并启动依赖服务
echo -e "${YELLOW}1️⃣  检查依赖服务...${NC}"
if ! docker ps | grep -q panda-wiki-postgres; then
  echo "启动依赖服务..."
  docker compose -f docker-compose.local.yml up -d
  echo "等待服务就绪..."
  sleep 10
else
  echo -e "${GREEN}✅ 依赖服务已运行${NC}"
fi
echo ""

# 2. 检查后端 API
echo -e "${YELLOW}2️⃣  检查后端 API...${NC}"
if ! curl -s http://localhost:8000 > /dev/null 2>&1; then
  echo -e "${RED}❌ 后端 API 未运行${NC}"
  echo ""
  echo "请在新终端运行："
  echo "  ./run-api.sh"
  echo ""
  read -p "按回车键继续（确认后端已启动）..."
else
  echo -e "${GREEN}✅ 后端 API 正在运行${NC}"
fi
echo ""

# 3. 显示服务信息
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 环境准备完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}📋 服务地址：${NC}"
echo "  🔧 管理后台: http://localhost:5173"
echo "  🌐 前端应用: http://localhost:3010"
echo "  🔌 后端 API: http://localhost:8000"
echo ""
echo -e "${YELLOW}🔑 默认账号：${NC}"
echo "  用户名: admin"
echo "  密码: panda-wiki"
echo ""
echo -e "${YELLOW}📝 下一步：${NC}"
echo "  1. 在新终端运行管理后台: ./run-admin.sh"
echo "  2. 访问 http://localhost:5173 管理知识库"
echo "  3. 在新终端运行前端应用: ./run-app.sh"
echo "  4. 访问 http://localhost:3010 查看知识库"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "  - 管理后台用于管理内容"
echo "  - 前端应用是用户访问的界面"
echo "  - 所有服务都支持热重载"
echo ""
