#!/bin/bash

# 本地开发环境启动脚本
# 此脚本会：
# 1. 启动所有依赖服务（Docker）
# 2. 等待服务就绪
# 3. 运行数据库迁移
# 4. 启动后端 API 服务

set -e

echo "🚀 启动本地开发环境..."

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. 启动依赖服务
echo -e "${YELLOW}📦 启动依赖服务（Docker）...${NC}"
docker compose -f docker-compose.local.yml up -d

# 2. 等待服务就绪
echo -e "${YELLOW}⏳ 等待服务就绪...${NC}"
sleep 5

# 检查 PostgreSQL 是否就绪
echo -e "${YELLOW}🔍 检查 PostgreSQL...${NC}"
until docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki > /dev/null 2>&1; do
  echo "等待 PostgreSQL 启动..."
  sleep 2
done
echo -e "${GREEN}✅ PostgreSQL 已就绪${NC}"

# 检查 Redis 是否就绪
echo -e "${YELLOW}🔍 检查 Redis...${NC}"
until docker exec panda-wiki-redis redis-cli -a panda-wiki ping > /dev/null 2>&1; do
  echo "等待 Redis 启动..."
  sleep 2
done
echo -e "${GREEN}✅ Redis 已就绪${NC}"

# 检查 NATS 是否就绪
echo -e "${YELLOW}🔍 检查 NATS...${NC}"
sleep 3
echo -e "${GREEN}✅ NATS 已就绪${NC}"

# 检查 MinIO 是否就绪
echo -e "${YELLOW}🔍 检查 MinIO...${NC}"
until curl -s http://localhost:9000/minio/health/live > /dev/null 2>&1; do
  echo "等待 MinIO 启动..."
  sleep 2
done
echo -e "${GREEN}✅ MinIO 已就绪${NC}"

# 检查 Raglite 是否就绪
echo -e "${YELLOW}🔍 检查 Raglite...${NC}"
until curl -s http://localhost:8080/health > /dev/null 2>&1; do
  echo "等待 Raglite 启动..."
  sleep 2
done
echo -e "${GREEN}✅ Raglite 已就绪${NC}"

# 3. 备份并使用本地配置
echo -e "${YELLOW}⚙️  配置后端...${NC}"
cd backend
if [ -f config.yml ] && [ ! -f config.yml.backup ]; then
  cp config.yml config.yml.backup
  echo -e "${GREEN}✅ 已备份原配置文件为 config.yml.backup${NC}"
fi
cp config.local.yml config.yml
echo -e "${GREEN}✅ 已应用本地开发配置${NC}"

# 4. 生成代码（如果需要）
echo -e "${YELLOW}🔧 生成代码（Swagger + Wire）...${NC}"
if ! make generate > /dev/null 2>&1; then
  echo -e "${RED}⚠️  代码生成失败，请检查 Go 环境和依赖${NC}"
  echo -e "${YELLOW}💡 提示：请确保已安装 swag 和 wire 工具${NC}"
  echo "   go install github.com/swaggo/swag/cmd/swag@latest"
  echo "   go install github.com/google/wire/cmd/wire@latest"
fi

# 5. 运行数据库迁移
echo -e "${YELLOW}🗄️  运行数据库迁移...${NC}"
if go run cmd/migrate/main.go; then
  echo -e "${GREEN}✅ 数据库迁移完成${NC}"
else
  echo -e "${RED}⚠️  数据库迁移失败${NC}"
  echo -e "${YELLOW}💡 提示：可能需要先生成代码或检查数据库连接${NC}"
fi

# 6. 提示用户
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 本地开发环境已就绪！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}📝 服务信息：${NC}"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis: localhost:6379"
echo "  - MinIO: http://localhost:9000 (Console: http://localhost:9001)"
echo "  - NATS: localhost:4222"
echo "  - Qdrant: http://localhost:6333"
echo "  - Raglite: http://localhost:8080"
echo ""
echo -e "${YELLOW}🚀 启动后端服务：${NC}"
echo "  cd backend && go run cmd/api/main.go"
echo ""
echo -e "${YELLOW}🐛 或使用 IDE 调试模式启动${NC}"
echo ""
echo -e "${YELLOW}🛑 停止依赖服务：${NC}"
echo "  docker compose -f docker-compose.local.yml down"
echo ""
