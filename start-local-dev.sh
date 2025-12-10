#!/bin/bash

# PandaWiki 本地开发环境一键启动脚本
# 用法: ./start-local-dev.sh

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🚀 启动 PandaWiki 本地开发环境${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1. 检查 Docker 是否运行
log_info "检查 Docker 状态..."
if ! docker info > /dev/null 2>&1; then
    log_error "Docker 未运行，请先启动 Docker"
    exit 1
fi
log_success "Docker 运行正常"

# 2. 检查并启动 Docker 依赖服务
log_info "检查 Docker 依赖服务..."

# 检查关键服务是否已运行
POSTGRES_RUNNING=$(docker ps -q -f name=panda-wiki-postgres -f status=running)
REDIS_RUNNING=$(docker ps -q -f name=panda-wiki-redis -f status=running)
MINIO_RUNNING=$(docker ps -q -f name=panda-wiki-minio -f status=running)
RAGLITE_RUNNING=$(docker ps -q -f name=panda-wiki-raglite -f status=running)

if [ -n "$POSTGRES_RUNNING" ] && [ -n "$REDIS_RUNNING" ] && [ -n "$MINIO_RUNNING" ] && [ -n "$RAGLITE_RUNNING" ]; then
    log_success "Docker 依赖服务已在运行，跳过启动"
else
    log_info "启动 Docker 依赖服务..."
    docker compose -f docker-compose.dev.yml up -d
    
    # 等待服务就绪
    log_info "等待服务就绪..."
    sleep 5
fi

# 等待 PostgreSQL
log_info "等待 PostgreSQL..."
until docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki > /dev/null 2>&1; do
    sleep 2
done
log_success "PostgreSQL 已就绪"

# 等待 Redis
log_info "等待 Redis..."
until docker exec panda-wiki-redis redis-cli -a admin123 ping > /dev/null 2>&1; do
    sleep 2
done
log_success "Redis 已就绪"

# 等待 MinIO（检查容器状态）
log_info "等待 MinIO..."
MINIO_READY=false
for i in {1..10}; do
    if docker ps -f name=panda-wiki-minio -f status=running | grep -q panda-wiki-minio; then
        MINIO_READY=true
        break
    fi
    sleep 1
done
if [ "$MINIO_READY" = true ]; then
    log_success "MinIO 已就绪"
else
    log_warning "MinIO 可能未完全启动"
fi

# 等待 Raglite（检查端口）
log_info "等待 Raglite..."
RAGLITE_READY=false
for i in {1..15}; do
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        RAGLITE_READY=true
        break
    fi
    sleep 2
done
if [ "$RAGLITE_READY" = true ]; then
    log_success "Raglite 已就绪"
else
    log_warning "Raglite 可能未完全启动，请检查日志: docker logs panda-wiki-raglite"
fi

# 4. 配置后端
log_info "配置后端..."
cd backend

# 检查开发配置文件是否存在
if [ ! -f config.dev.yml ]; then
    log_error "config.dev.yml 不存在，请先创建开发配置文件"
    exit 1
fi

log_success "使用开发配置: config.dev.yml"

# 创建必要的目录
mkdir -p data/ssl
log_success "创建数据目录"

cd "$PROJECT_ROOT"

# 5. 启动 API 服务（后台）
log_info "启动 API 服务..."

# 检查是否已有 API 进程在运行
if lsof -i :8000 > /dev/null 2>&1; then
    log_warning "端口 8000 已被占用，尝试停止旧进程..."
    pkill -f "go run ./cmd/api" || true
    sleep 2
fi

cd backend
nohup env DATA_DIR=./data SSL_DIR=./data/ssl CONFIG_FILE=config.dev.yml go run ./cmd/api > ../logs/api.log 2>&1 &
API_PID=$!
echo $API_PID > ../logs/api.pid
cd "$PROJECT_ROOT"

# 等待 API 启动
log_info "等待 API 服务启动..."
sleep 5

if curl -s http://localhost:8000/api/v1/user/login > /dev/null 2>&1; then
    log_success "API 服务已启动 (PID: $API_PID, http://localhost:8000)"
else
    log_warning "API 服务可能未完全启动，请检查日志: tail -f logs/api.log"
fi

# 6. 配置 Web App 环境
log_info "配置 Web App 环境..."
cd web/app

# 检查开发环境配置文件是否存在
if [ ! -f .env.dev ]; then
    log_error ".env.dev 不存在，请先创建开发环境配置文件"
    exit 1
fi

# 复制开发环境配置为 .env.local (Next.js 优先读取 .env.local)
cp .env.dev .env.local
log_success "使用开发环境配置: .env.dev"

cd "$PROJECT_ROOT"

# 7. 启动 Web App（后台）
log_info "启动 Web App..."

# 检查是否已有进程在运行
if lsof -i :3010 > /dev/null 2>&1; then
    log_warning "端口 3010 已被占用，尝试停止旧进程..."
    pkill -f "next dev" || true
    sleep 2
fi

cd web/app
nohup pnpm dev > ../../logs/app.log 2>&1 &
APP_PID=$!
echo $APP_PID > ../../logs/app.pid
cd "$PROJECT_ROOT"

# 等待 Web App 启动
log_info "等待 Web App 启动..."
sleep 8

if curl -s http://localhost:3010 > /dev/null 2>&1; then
    log_success "Web App 已启动 (PID: $APP_PID, http://localhost:3010)"
else
    log_warning "Web App 可能未完全启动，请检查日志: tail -f logs/app.log"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 所有服务已启动！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}📝 服务地址：${NC}"
echo "  - Web App:    http://localhost:3010"
echo "  - API 服务:   http://localhost:8000"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis:      localhost:6379"
echo "  - MinIO:      http://localhost:9000 (Console: http://localhost:9001)"
echo "  - Qdrant:     http://localhost:6333"
echo "  - Raglite:    http://localhost:8080"
echo ""
echo -e "${YELLOW}🔧 常用命令：${NC}"
echo "  - 查看 API 日志:  tail -f logs/api.log"
echo "  - 查看 App 日志:  tail -f logs/app.log"
echo "  - 停止所有服务:   ./stop-local-dev.sh"
echo ""
echo -e "${YELLOW}💡 默认账号：${NC}"
echo "  - 用户名: admin"
echo "  - 密码:   admin123"
echo ""
echo -e "${YELLOW}📌 进程 ID：${NC}"
echo "  - API PID:  $API_PID (保存在 logs/api.pid)"
echo "  - App PID:  $APP_PID (保存在 logs/app.pid)"
echo ""
