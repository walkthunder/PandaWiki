#!/bin/bash

# PandaWiki 本地开发环境统一启动脚本
# 用法：
#   ./dev.sh start     - 启动所有服务
#   ./dev.sh stop      - 停止所有服务
#   ./dev.sh restart   - 重启所有服务
#   ./dev.sh status    - 查看服务状态
#   ./dev.sh logs      - 查看服务日志
#   ./dev.sh clean     - 清理并重启

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

# PID 文件目录
PID_DIR="$PROJECT_ROOT/.dev"
mkdir -p "$PID_DIR"

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

# 检查依赖服务
check_docker_services() {
    log_info "检查 Docker 服务..."
    
    local services=("panda-wiki-postgres" "panda-wiki-redis" "panda-wiki-nats" "panda-wiki-minio" "panda-wiki-raglite")
    local all_running=true
    
    for service in "${services[@]}"; do
        if docker ps | grep -q "$service"; then
            echo "  ✓ $service"
        else
            echo "  ✗ $service (未运行)"
            all_running=false
        fi
    done
    
    if [ "$all_running" = false ]; then
        return 1
    fi
    return 0
}

# 启动 Docker 依赖服务
start_docker_services() {
    log_info "启动 Docker 依赖服务..."
    docker compose -f docker-compose.local.yml up -d
    
    log_info "等待服务就绪..."
    sleep 5
    
    # 等待 PostgreSQL
    until docker exec panda-wiki-postgres pg_isready -U panda-wiki -d panda-wiki > /dev/null 2>&1; do
        echo "  等待 PostgreSQL..."
        sleep 2
    done
    log_success "PostgreSQL 已就绪"
    
    # 等待 Redis
    until docker exec panda-wiki-redis redis-cli -a panda-wiki ping > /dev/null 2>&1; do
        echo "  等待 Redis..."
        sleep 2
    done
    log_success "Redis 已就绪"
    
    # 等待 MinIO
    until curl -s http://localhost:9000/minio/health/live > /dev/null 2>&1; do
        echo "  等待 MinIO..."
        sleep 2
    done
    log_success "MinIO 已就绪"
    
    # 等待 Raglite
    until curl -s http://localhost:8080/health > /dev/null 2>&1; do
        echo "  等待 Raglite..."
        sleep 2
    done
    log_success "Raglite 已就绪"
}

# 配置后端
setup_backend() {
    log_info "配置后端..."
    cd backend
    
    # 备份并使用本地配置
    if [ -f config.yml ] && [ ! -f config.yml.backup ]; then
        cp config.yml config.yml.backup
    fi
    cp config.local.yml config.yml
    
    cd "$PROJECT_ROOT"
    log_success "后端配置完成"
}

# 启动 API 服务
start_api() {
    log_info "启动 API 服务..."
    
    # 检查是否已经在运行
    if [ -f "$PID_DIR/api.pid" ]; then
        local pid=$(cat "$PID_DIR/api.pid")
        if ps -p $pid > /dev/null 2>&1; then
            log_warning "API 服务已在运行 (PID: $pid)"
            return 0
        fi
    fi
    
    cd backend
    
    # 设置环境变量
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
    export CADDY_API=""
    
    # 后台启动
    nohup go run ./cmd/api > "$PID_DIR/api.log" 2>&1 &
    echo $! > "$PID_DIR/api.pid"
    
    cd "$PROJECT_ROOT"
    
    # 等待启动
    sleep 3
    if curl -s http://localhost:8000 > /dev/null 2>&1; then
        log_success "API 服务已启动 (http://localhost:8000)"
    else
        log_error "API 服务启动失败，查看日志: tail -f $PID_DIR/api.log"
        return 1
    fi
}

# 启动 Consumer 服务
start_consumer() {
    log_info "启动 Consumer 服务..."
    
    # 检查是否已经在运行
    if [ -f "$PID_DIR/consumer.pid" ]; then
        local pid=$(cat "$PID_DIR/consumer.pid")
        if ps -p $pid > /dev/null 2>&1; then
            log_warning "Consumer 服务已在运行 (PID: $pid)"
            return 0
        fi
    fi
    
    cd backend
    
    # 设置环境变量
    export PG_DSN="host=localhost user=panda-wiki password=panda-wiki dbname=panda-wiki port=5432 sslmode=disable TimeZone=Asia/Shanghai"
    export MQ_NATS_SERVER="nats://localhost:4222"
    export NATS_PASSWORD="panda-wiki"
    export REDIS_ADDR="localhost:6379"
    export REDIS_PASSWORD="panda-wiki"
    export S3_ENDPOINT="localhost:9000"
    export S3_SECRET_KEY="panda-wiki"
    export JWT_SECRET="panda-wiki"
    export RAG_CT_RAG_BASE_URL="http://localhost:8080/api/v1"
    export DATA_DIR="./data"
    export SSL_DIR="./data/ssl"
    export CADDY_API="../data/caddy/run/caddy-admin.sock"
    
    # 后台启动
    nohup go run ./cmd/consumer > "$PID_DIR/consumer.log" 2>&1 &
    echo $! > "$PID_DIR/consumer.pid"
    
    cd "$PROJECT_ROOT"
    
    sleep 2
    log_success "Consumer 服务已启动"
}

# 停止服务
stop_service() {
    local service=$1
    local pid_file="$PID_DIR/${service}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p $pid > /dev/null 2>&1; then
            kill $pid
            rm "$pid_file"
            log_success "$service 服务已停止"
        else
            rm "$pid_file"
            log_warning "$service 服务未运行"
        fi
    else
        log_warning "$service 服务未运行"
    fi
}

# 停止所有服务
stop_all() {
    log_info "停止所有服务..."
    
    stop_service "api"
    stop_service "consumer"
    
    log_info "停止 Docker 服务..."
    docker compose -f docker-compose.local.yml down
    
    log_success "所有服务已停止"
}

# 查看服务状态
show_status() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}服务状态${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Docker 服务
    echo -e "${YELLOW}Docker 服务:${NC}"
    check_docker_services || true
    echo ""
    
    # API 服务
    echo -e "${YELLOW}API 服务:${NC}"
    if [ -f "$PID_DIR/api.pid" ]; then
        local pid=$(cat "$PID_DIR/api.pid")
        if ps -p $pid > /dev/null 2>&1; then
            echo "  ✓ 运行中 (PID: $pid, http://localhost:8000)"
        else
            echo "  ✗ 未运行 (PID 文件存在但进程不存在)"
        fi
    else
        echo "  ✗ 未运行"
    fi
    echo ""
    
    # Consumer 服务
    echo -e "${YELLOW}Consumer 服务:${NC}"
    if [ -f "$PID_DIR/consumer.pid" ]; then
        local pid=$(cat "$PID_DIR/consumer.pid")
        if ps -p $pid > /dev/null 2>&1; then
            echo "  ✓ 运行中 (PID: $pid)"
        else
            echo "  ✗ 未运行 (PID 文件存在但进程不存在)"
        fi
    else
        echo "  ✗ 未运行"
    fi
    echo ""
}

# 查看日志
show_logs() {
    local service=$1
    
    if [ -z "$service" ]; then
        echo "用法: ./dev.sh logs [api|consumer]"
        return 1
    fi
    
    local log_file="$PID_DIR/${service}.log"
    
    if [ -f "$log_file" ]; then
        tail -f "$log_file"
    else
        log_error "日志文件不存在: $log_file"
        return 1
    fi
}

# 清理并重启
clean_restart() {
    log_info "清理并重启..."
    
    stop_all
    
    log_info "清理数据..."
    rm -rf "$PID_DIR"/*.log
    
    start_all
}

# 启动所有服务
start_all() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}🚀 启动 PandaWiki 本地开发环境${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # 1. 启动 Docker 服务
    if ! check_docker_services > /dev/null 2>&1; then
        start_docker_services
    else
        log_success "Docker 服务已在运行"
    fi
    
    # 2. 配置后端
    setup_backend
    
    # 3. 启动 API
    start_api
    
    # 4. 启动 Consumer
    start_consumer
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✅ 所有服务已启动！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}📝 服务地址：${NC}"
    echo "  - API 服务: http://localhost:8000"
    echo "  - 管理后台: 运行 'cd web/admin && pnpm dev' (http://localhost:5173)"
    echo "  - 前端应用: 运行 'cd web/app && pnpm dev' (http://localhost:3010)"
    echo ""
    echo -e "${YELLOW}🔧 常用命令：${NC}"
    echo "  - 查看状态: ./dev.sh status"
    echo "  - 查看日志: ./dev.sh logs api|consumer"
    echo "  - 停止服务: ./dev.sh stop"
    echo "  - 重启服务: ./dev.sh restart"
    echo ""
    echo -e "${YELLOW}💡 默认账号：${NC}"
    echo "  - 用户名: admin"
    echo "  - 密码: panda-wiki"
    echo ""
}

# 主函数
main() {
    local command=${1:-start}
    
    case "$command" in
        start)
            start_all
            ;;
        stop)
            stop_all
            ;;
        restart)
            stop_all
            sleep 2
            start_all
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs $2
            ;;
        clean)
            clean_restart
            ;;
        *)
            echo "用法: $0 {start|stop|restart|status|logs|clean}"
            echo ""
            echo "命令说明:"
            echo "  start   - 启动所有服务"
            echo "  stop    - 停止所有服务"
            echo "  restart - 重启所有服务"
            echo "  status  - 查看服务状态"
            echo "  logs    - 查看服务日志 (logs api|consumer)"
            echo "  clean   - 清理并重启"
            exit 1
            ;;
    esac
}

main "$@"
