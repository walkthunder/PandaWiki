#!/bin/bash

# 快速启动 API 服务脚本
# 前提：依赖服务已经启动

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🚀 启动 API 服务...${NC}"

# 检查依赖服务
if ! docker ps | grep -q panda-wiki-postgres; then
  echo -e "${YELLOW}⚠️  依赖服务未启动，正在启动...${NC}"
  docker compose -f docker-compose.local.yml up -d
  echo "等待服务就绪..."
  sleep 10
fi

# 切换到 backend 目录并启动
cd backend

# 确保使用本地配置
if [ ! -f config.yml ] || ! grep -q "host=localhost" config.yml; then
  echo -e "${YELLOW}⚙️  应用本地配置...${NC}"
  if [ -f config.yml ] && [ ! -f config.yml.backup ]; then
    cp config.yml config.yml.backup
  fi
  cp config.local.yml config.yml
fi

echo -e "${GREEN}✅ 启动 API 服务在 http://localhost:8000${NC}"
echo ""

# 设置环境变量以覆盖配置
export PG_DSN="host=localhost user=panda-wiki password=panda-wiki dbname=panda-wiki port=5432 sslmode=disable TimeZone=Asia/Shanghai"
export MQ_NATS_SERVER="nats://localhost:4222"
export NATS_PASSWORD="panda-wiki"
export REDIS_ADDR="localhost:6379"
export REDIS_PASSWORD="panda-wiki"
export S3_ENDPOINT="localhost:9000"
export S3_SECRET_KEY="panda-wiki"
export JWT_SECRET="panda-wiki"
export ADMIN_PASSWORD="panda-wiki"
export RAG_CT_RAG_BASE_URL="http://localhost:8080/api/v1"
export DATA_DIR="./data"
export SSL_DIR="./data/ssl"
# Caddy 在 macOS 上有兼容性问题，本地开发不需要
export CADDY_API=""

go run ./cmd/api
