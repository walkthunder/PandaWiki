#!/bin/bash

# PandaWiki 本地开发环境停止脚本
# 用法: ./stop-local-dev.sh

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

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🛑 停止 PandaWiki 本地开发环境${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1. 停止 Web App
log_info "停止 Web App..."
if [ -f logs/app.pid ]; then
    APP_PID=$(cat logs/app.pid)
    if ps -p $APP_PID > /dev/null 2>&1; then
        kill $APP_PID
        log_success "Web App 已停止 (PID: $APP_PID)"
    else
        log_warning "Web App 进程不存在"
    fi
    rm logs/app.pid
else
    log_warning "未找到 Web App PID 文件"
    # 尝试通过端口查找并停止
    if lsof -i :3010 > /dev/null 2>&1; then
        pkill -f "next dev" || true
        log_success "已停止占用 3010 端口的进程"
    fi
fi

# 2. 停止 API 服务
log_info "停止 API 服务..."
if [ -f logs/api.pid ]; then
    API_PID=$(cat logs/api.pid)
    if ps -p $API_PID > /dev/null 2>&1; then
        kill $API_PID
        log_success "API 服务已停止 (PID: $API_PID)"
    else
        log_warning "API 服务进程不存在"
    fi
    rm logs/api.pid
else
    log_warning "未找到 API PID 文件"
    # 尝试通过端口查找并停止
    if lsof -i :8000 > /dev/null 2>&1; then
        pkill -f "go run ./cmd/api" || true
        log_success "已停止占用 8000 端口的进程"
    fi
fi

# 3. 停止 Docker 服务
log_info "停止 Docker 服务..."
docker compose -f docker-compose.local.yml down
log_success "Docker 服务已停止"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 所有服务已停止！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
