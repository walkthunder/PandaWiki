#!/bin/bash

# PandaWiki 本地开发环境状态检查脚本
# 用法: ./check-local-dev.sh

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}📊 PandaWiki 本地开发环境状态${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查函数
check_service() {
    local name=$1
    local check_cmd=$2
    
    if eval "$check_cmd" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name"
        return 1
    fi
}

check_port() {
    local name=$1
    local port=$2
    
    if lsof -i :$port > /dev/null 2>&1; then
        local pid=$(lsof -ti :$port)
        echo -e "  ${GREEN}✓${NC} $name (端口 $port, PID: $pid)"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name (端口 $port 未监听)"
        return 1
    fi
}

# Docker 服务
echo -e "${YELLOW}Docker 服务:${NC}"
check_service "Docker" "docker info"
check_service "PostgreSQL" "docker ps | grep -q panda-wiki-postgres"
check_service "Redis" "docker ps | grep -q panda-wiki-redis"
check_service "MinIO" "docker ps | grep -q panda-wiki-minio"
check_service "NATS" "docker ps | grep -q panda-wiki-nats"
check_service "Qdrant" "docker ps | grep -q panda-wiki-qdrant"
check_service "Raglite" "docker ps | grep -q panda-wiki-raglite"
check_service "Caddy" "docker ps | grep -q panda-wiki-caddy"
check_service "Crawler" "docker ps | grep -q panda-wiki-crawler"
echo ""

# 应用服务
echo -e "${YELLOW}应用服务:${NC}"
check_port "API 服务" 8000
check_port "Web App" 3010
echo ""

# 服务端点检查
echo -e "${YELLOW}服务端点:${NC}"
check_service "API Health" "curl -s http://localhost:8000/api/v1/user/login"
check_service "Web App" "curl -s http://localhost:3010"
check_service "PostgreSQL" "docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki"
check_service "Redis" "docker exec panda-wiki-redis redis-cli -a admin123 ping"
check_service "MinIO" "curl -s http://localhost:9000/minio/health/live"
check_service "Raglite" "curl -s http://localhost:8080/health"
echo ""

# 进程信息
echo -e "${YELLOW}进程信息:${NC}"
if [ -f logs/api.pid ]; then
    API_PID=$(cat logs/api.pid)
    if ps -p $API_PID > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} API 进程运行中 (PID: $API_PID)"
    else
        echo -e "  ${RED}✗${NC} API 进程不存在 (PID 文件: $API_PID)"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} 未找到 API PID 文件"
fi

if [ -f logs/app.pid ]; then
    APP_PID=$(cat logs/app.pid)
    if ps -p $APP_PID > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Web App 进程运行中 (PID: $APP_PID)"
    else
        echo -e "  ${RED}✗${NC} Web App 进程不存在 (PID 文件: $APP_PID)"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} 未找到 Web App PID 文件"
fi
echo ""

# 日志文件
echo -e "${YELLOW}日志文件:${NC}"
if [ -f logs/api.log ]; then
    API_LOG_SIZE=$(du -h logs/api.log | cut -f1)
    echo -e "  ${GREEN}✓${NC} API 日志: logs/api.log ($API_LOG_SIZE)"
else
    echo -e "  ${YELLOW}⚠${NC} API 日志文件不存在"
fi

if [ -f logs/app.log ]; then
    APP_LOG_SIZE=$(du -h logs/app.log | cut -f1)
    echo -e "  ${GREEN}✓${NC} Web App 日志: logs/app.log ($APP_LOG_SIZE)"
else
    echo -e "  ${YELLOW}⚠${NC} Web App 日志文件不存在"
fi
echo ""

# 配置文件
echo -e "${YELLOW}配置文件:${NC}"
if [ -f backend/config.yml ]; then
    if grep -q "admin123" backend/config.yml 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} backend/config.yml (本地开发配置)"
    else
        echo -e "  ${YELLOW}⚠${NC} backend/config.yml (可能不是本地开发配置)"
    fi
else
    echo -e "  ${RED}✗${NC} backend/config.yml 不存在"
fi

if [ -f .env ]; then
    echo -e "  ${GREEN}✓${NC} .env"
else
    echo -e "  ${YELLOW}⚠${NC} .env 不存在"
fi

if [ -f web/app/.env ]; then
    echo -e "  ${GREEN}✓${NC} web/app/.env"
else
    echo -e "  ${YELLOW}⚠${NC} web/app/.env 不存在"
fi
echo ""

# 快捷命令提示
echo -e "${YELLOW}🔧 快捷命令:${NC}"
echo "  - 查看 API 日志:    tail -f logs/api.log"
echo "  - 查看 App 日志:    tail -f logs/app.log"
echo "  - 重启所有服务:     ./stop-local-dev.sh && ./start-local-dev.sh"
echo "  - 停止所有服务:     ./stop-local-dev.sh"
echo ""
