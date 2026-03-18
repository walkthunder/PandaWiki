#!/bin/bash

# PandaWiki 本地开发环境验证脚本
# 用法: ./verify-local-dev.sh

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
echo -e "${BLUE}🔍 PandaWiki 本地开发环境验证${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 验证计数器
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# 验证函数
verify_check() {
    local check_name=$1
    local check_cmd=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    log_info "验证: $check_name"
    
    if eval "$check_cmd" > /dev/null 2>&1; then
        log_success "$check_name - ✓"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "$check_name - ✗"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

# 1. 核心服务验证
echo -e "${YELLOW}🔧 核心服务验证${NC}"
verify_check "Docker 运行状态" "docker info"
verify_check "PostgreSQL 容器" "docker ps | grep -q panda-wiki-postgres"
verify_check "Redis 容器" "docker ps | grep -q panda-wiki-redis"
verify_check "MinIO 容器" "docker ps | grep -q panda-wiki-minio"
verify_check "Qdrant 容器" "docker ps | grep -q panda-wiki-qdrant"
verify_check "Raglite 容器" "docker ps | grep -q panda-wiki-raglite"
echo ""

# 2. 端口监听验证
echo -e "${YELLOW}🔌 端口监听验证${NC}"
verify_check "API 端口 8000" "lsof -i :8000"
verify_check "Web App 端口 3010" "lsof -i :3010"
verify_check "PostgreSQL 端口 5432" "lsof -i :5432"
verify_check "Redis 端口 6379" "lsof -i :6379"
verify_check "MinIO 端口 9000" "lsof -i :9000"
verify_check "Qdrant 端口 6333" "lsof -i :6333"
verify_check "Raglite 端口 8080" "lsof -i :8080"
echo ""

# 3. HTTP 服务验证
echo -e "${YELLOW}🌐 HTTP 服务验证${NC}"
verify_check "Web App 响应" "curl -s http://localhost:3010"
verify_check "API 服务响应" "curl -s http://localhost:8000/api/v1/user/login"
verify_check "Raglite 健康检查" "curl -s http://localhost:8080/health"
echo ""

# 4. 数据库连接验证
echo -e "${YELLOW}🗄️ 数据库连接验证${NC}"
verify_check "PostgreSQL 连接" "docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki"
verify_check "Redis 连接" "docker exec panda-wiki-redis redis-cli -a admin123 ping"
verify_check "Qdrant API 访问" "curl -s -H 'api-key: admin123' http://localhost:6333/health"
echo ""

# 5. 配置文件验证
echo -e "${YELLOW}⚙️ 配置文件验证${NC}"
verify_check "环境变量文件" "test -f .env"
verify_check "后端开发配置" "test -f backend/config.dev.yml"
verify_check "前端开发配置" "test -f web/app/.env.dev"
verify_check "前端本地配置" "test -f web/app/.env.local"
echo ""

# 6. 日志文件验证
echo -e "${YELLOW}📋 日志文件验证${NC}"
verify_check "API 日志文件" "test -f logs/api.log"
verify_check "Consumer 日志文件" "test -f logs/consumer.log"
verify_check "Web App 日志文件" "test -f logs/app.log"
echo ""

# 7. 进程验证
echo -e "${YELLOW}🔄 进程验证${NC}"
if [ -f logs/api.pid ]; then
    API_PID=$(cat logs/api.pid)
    verify_check "API 进程运行" "ps -p $API_PID"
else
    log_warning "API PID 文件不存在"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

if [ -f logs/consumer.pid ]; then
    CONSUMER_PID=$(cat logs/consumer.pid)
    verify_check "Consumer 进程运行" "ps -p $CONSUMER_PID"
else
    log_warning "Consumer PID 文件不存在"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

if [ -f logs/app.pid ]; then
    APP_PID=$(cat logs/app.pid)
    verify_check "Web App 进程运行" "ps -p $APP_PID"
else
    log_warning "Web App PID 文件不存在"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi
echo ""

# 验证结果汇总
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}📊 验证结果汇总${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}总验证项: $TOTAL_CHECKS${NC}"
echo -e "${GREEN}通过验证: $PASSED_CHECKS${NC}"
echo -e "${RED}失败验证: $FAILED_CHECKS${NC}"
echo ""

# 计算成功率
SUCCESS_RATE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

if [ $SUCCESS_RATE -ge 90 ]; then
    echo -e "${GREEN}🎉 验证通过！本地开发环境运行良好 (成功率: ${SUCCESS_RATE}%)${NC}"
    echo ""
    echo -e "${YELLOW}🔗 快速访问链接：${NC}"
    echo "  - 应用首页: http://localhost:3010"
    echo "  - API 文档: http://localhost:8000/swagger/index.html"
    echo "  - MinIO 控制台: http://localhost:9001"
    echo ""
    echo -e "${YELLOW}💡 默认登录信息：${NC}"
    echo "  - 用户名: admin"
    echo "  - 密码: admin123"
    echo ""
    echo -e "${YELLOW}🔧 常用命令：${NC}"
    echo "  - 查看状态: ./check-local-dev.sh"
    echo "  - 查看日志: tail -f logs/api.log"
    echo "  - 重启服务: ./stop-local-dev.sh && ./start-local-dev.sh"
    echo ""
    exit 0
elif [ $SUCCESS_RATE -ge 70 ]; then
    echo -e "${YELLOW}⚠️  部分验证失败，但基本功能可用 (成功率: ${SUCCESS_RATE}%)${NC}"
    echo ""
    echo -e "${YELLOW}🔧 建议操作：${NC}"
    echo "  1. 检查失败的服务: ./check-local-dev.sh"
    echo "  2. 查看相关日志: tail -f logs/*.log"
    echo "  3. 重启问题服务"
    echo ""
    exit 0
else
    echo -e "${RED}❌ 验证失败较多，环境可能有问题 (成功率: ${SUCCESS_RATE}%)${NC}"
    echo ""
    echo -e "${YELLOW}🔧 故障排查步骤：${NC}"
    echo "  1. 停止所有服务: ./stop-local-dev.sh"
    echo "  2. 检查 Docker 状态: docker info"
    echo "  3. 重新启动服务: ./start-local-dev.sh"
    echo "  4. 查看详细日志: tail -f logs/*.log"
    echo "  5. 检查端口占用: lsof -i :8000"
    echo ""
    echo -e "${YELLOW}📚 参考文档：${NC}"
    echo "  - 快速启动指南: LOCAL_DEV_QUICK_START.md"
    echo "  - 详细脚本说明: LOCAL_DEV_SCRIPTS.md"
    echo ""
    exit 1
fi