#!/bin/bash

# 启动前端应用脚本（用户访问的知识库界面）

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}🌐 启动前端应用...${NC}"

# 检查后端 API
if ! curl -s http://localhost:8000 > /dev/null 2>&1; then
  echo -e "${RED}❌ 后端 API 未运行${NC}"
  echo "请先运行: ./run-api.sh"
  exit 1
fi

# 获取知识库 ID
echo -e "${YELLOW}📋 获取知识库信息...${NC}"
KB_INFO=$(docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c "SELECT id, name FROM knowledge_bases ORDER BY created_at DESC LIMIT 1;" 2>/dev/null)

if [ -z "$KB_INFO" ]; then
  echo -e "${RED}❌ 未找到知识库${NC}"
  echo "请先在管理后台创建知识库："
  echo "  1. 访问 http://localhost:5173"
  echo "  2. 登录 (admin / panda-wiki)"
  echo "  3. 创建知识库"
  exit 1
fi

# 解析知识库信息
KB_ID=$(echo "$KB_INFO" | awk '{print $1}' | tr -d ' ')
KB_NAME=$(echo "$KB_INFO" | awk '{print $3}' | tr -d ' ')

echo -e "${GREEN}✅ 找到知识库：${NC}"
echo "  ID: $KB_ID"
echo "  名称: $KB_NAME"
echo ""

# 更新 .env.local
cd web/app

echo -e "${YELLOW}⚙️  配置环境变量...${NC}"
cat > .env.local << EOF
# 本地开发环境配置
# 此文件不会被提交到 Git

# 后端 API 地址
TARGET=http://localhost:8000

# 静态文件地址（MinIO）
STATIC_FILE_TARGET=http://localhost:9000

# 分享页面地址
SHARE_TARGET=http://localhost:8000

# 默认知识库 ID（用于本地开发）
# 这样访问 http://localhost:3010 时会自动使用这个知识库
NEXT_PUBLIC_DEFAULT_KB_ID=$KB_ID
DEV_KB_ID=$KB_ID

# 知识库名称（可选，用于显示）
NEXT_PUBLIC_DEFAULT_KB_NAME=$KB_NAME
EOF

echo -e "${GREEN}✅ 配置完成${NC}"
echo ""

# 检查依赖
if [ ! -d "node_modules" ]; then
  echo -e "${YELLOW}📦 安装依赖...${NC}"
  pnpm install
fi

echo -e "${GREEN}✅ 启动前端应用在 http://localhost:3010${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "  - 知识库: $KB_NAME"
echo "  - 访问: http://localhost:3010"
echo "  - 或带参数: http://localhost:3010?kb_id=$KB_ID"
echo ""

pnpm dev
