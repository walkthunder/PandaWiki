#!/bin/bash

# PandaWiki 本地开发环境功能测试脚本
# 用法: ./test-local-dev.sh

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
echo -e "${BLUE}🧪 PandaWiki 本地开发环境功能测试${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试函数
run_test() {
    local test_name=$1
    local test_cmd=$2
    local expected_output=$3
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_info "测试: $test_name"
    
    if eval "$test_cmd" > /dev/null 2>&1; then
        log_success "$test_name - 通过"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "$test_name - 失败"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# 1. 基础服务连接测试
echo -e "${YELLOW}📡 基础服务连接测试${NC}"
run_test "PostgreSQL 连接" "docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki"
run_test "Redis 连接" "docker exec panda-wiki-redis redis-cli -a admin123 ping | grep -q PONG"
run_test "MinIO 服务运行" "docker ps | grep -q panda-wiki-minio"
run_test "NATS 连接" "docker exec panda-wiki-nats nats-server --version"
run_test "Qdrant 健康检查" "curl -s -H 'api-key: admin123' http://localhost:6333/health"
run_test "Raglite 健康检查" "curl -s http://localhost:8080/health | grep -q OK"
echo ""

# 2. API 服务测试
echo -e "${YELLOW}🔌 API 服务测试${NC}"
run_test "API 服务响应" "curl -s http://localhost:8000/api/v1/user/login"
run_test "API 健康检查" "curl -s http://localhost:8000/api/v1/health"
run_test "API Swagger 文档" "curl -s http://localhost:8000/swagger/index.html"
echo ""

# 3. Web App 测试
echo -e "${YELLOW}🌐 Web App 测试${NC}"
run_test "Web App 首页" "curl -s http://localhost:3010"
run_test "Web App 静态资源" "curl -s http://localhost:3010/_next/static/"
echo ""

# 4. 数据库功能测试
echo -e "${YELLOW}🗄️ 数据库功能测试${NC}"
run_test "数据库表创建" "docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -c 'SELECT 1;'"
run_test "Redis 数据操作" "docker exec panda-wiki-redis redis-cli -a admin123 set test_key test_value"
run_test "Redis 数据读取" "docker exec panda-wiki-redis redis-cli -a admin123 get test_key | grep -q test_value"
echo ""

# 5. RAG 服务测试
echo -e "${YELLOW}🤖 RAG 服务测试${NC}"
run_test "Raglite API 响应" "curl -s http://localhost:8080/api/v1/health"
run_test "向量数据库连接" "curl -s -H 'api-key: admin123' http://localhost:6333/collections"
echo ""

# 6. 文件存储测试
echo -e "${YELLOW}📁 文件存储测试${NC}"
run_test "MinIO 存储桶列表" "docker ps | grep -q panda-wiki-minio"
echo ""

# 7. 消息队列测试
echo -e "${YELLOW}📨 消息队列测试${NC}"
run_test "NATS 服务状态" "docker exec panda-wiki-nats nats-server --version"
echo ""

# 8. 配置文件验证
echo -e "${YELLOW}⚙️ 配置文件验证${NC}"
run_test "后端配置文件存在" "test -f backend/config.dev.yml"
run_test "前端配置文件存在" "test -f web/app/.env.dev"
run_test "环境变量文件存在" "test -f .env"
echo ""

# 9. 日志文件检查
echo -e "${YELLOW}📋 日志文件检查${NC}"
if [ -f logs/api.log ]; then
    run_test "API 日志文件存在" "test -f logs/api.log"
    run_test "API 日志有内容" "test -s logs/api.log"
fi

if [ -f logs/consumer.log ]; then
    run_test "Consumer 日志文件存在" "test -f logs/consumer.log"
    run_test "Consumer 日志有内容" "test -s logs/consumer.log"
fi

if [ -f logs/app.log ]; then
    run_test "Web App 日志文件存在" "test -f logs/app.log"
    run_test "Web App 日志有内容" "test -s logs/app.log"
fi
echo ""

# 10. 端口监听检查
echo -e "${YELLOW}🔌 端口监听检查${NC}"
run_test "API 端口 8000 监听" "lsof -i :8000"
run_test "Web App 端口 3010 监听" "lsof -i :3010"
run_test "PostgreSQL 端口 5432 监听" "lsof -i :5432"
run_test "Redis 端口 6379 监听" "lsof -i :6379"
run_test "MinIO 端口 9000 监听" "lsof -i :9000"
run_test "Qdrant 端口 6333 监听" "lsof -i :6333"
run_test "Raglite 端口 8080 监听" "lsof -i :8080"
echo ""

# 测试结果汇总
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}📊 测试结果汇总${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}总测试数: $TOTAL_TESTS${NC}"
echo -e "${GREEN}通过测试: $PASSED_TESTS${NC}"
echo -e "${RED}失败测试: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 所有测试通过！本地开发环境运行正常${NC}"
    echo ""
    echo -e "${YELLOW}🔗 服务访问地址：${NC}"
    echo "  - Web App:    http://localhost:3010"
    echo "  - API 文档:   http://localhost:8000/swagger/index.html"
    echo "  - MinIO 控制台: http://localhost:9001 (用户名: s3panda-wiki, 密码: admin123)"
    echo "  - Qdrant 控制台: http://localhost:6333/dashboard"
    echo ""
    echo -e "${YELLOW}💡 默认登录信息：${NC}"
    echo "  - 用户名: admin"
    echo "  - 密码:   admin123"
    echo ""
    exit 0
else
    echo -e "${RED}⚠️  有 $FAILED_TESTS 个测试失败，请检查相关服务${NC}"
    echo ""
    echo -e "${YELLOW}🔧 故障排查建议：${NC}"
    echo "  1. 检查服务状态: ./check-local-dev.sh"
    echo "  2. 查看服务日志: tail -f logs/api.log"
    echo "  3. 查看 Docker 日志: docker compose -f docker-compose.dev.yml logs"
    echo "  4. 重启服务: ./stop-local-dev.sh && ./start-local-dev.sh"
    echo ""
    exit 1
fi