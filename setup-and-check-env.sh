#!/bin/bash

# PandaWiki 本地环境自动配置和检查脚本
# 功能：检查环境配置、自动修复问题、验证 raglite 版本兼容性

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# 错误计数
ERROR_COUNT=0
WARNING_COUNT=0

log_section "🔍 PandaWiki 本地环境配置检查和自动修复"

# 1. 检查 Docker
log_section "1️⃣ 检查 Docker 环境"
if ! docker info > /dev/null 2>&1; then
    log_error "Docker 未运行，请先启动 Docker"
    exit 1
fi
log_success "Docker 运行正常"

# 2. 检查必要的目录
log_section "2️⃣ 检查和创建必要目录"
REQUIRED_DIRS=(
    "logs"
    "data"
    "data/postgres"
    "data/redis"
    "data/minio"
    "data/qdrant"
    "data/raglite"
    "data/nats"
    "data/caddy"
    "backend/data"
    "backend/data/ssl"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log_success "创建目录: $dir"
    else
        log_info "目录已存在: $dir"
    fi
done

# 3. 检查配置文件
log_section "3️⃣ 检查配置文件"

# 检查 .env
if [ ! -f .env ]; then
    log_error ".env 文件不存在"
    ERROR_COUNT=$((ERROR_COUNT + 1))
else
    log_success ".env 文件存在"
fi

# 检查后端配置
if [ ! -f backend/config.dev.yml ]; then
    log_error "backend/config.dev.yml 不存在"
    ERROR_COUNT=$((ERROR_COUNT + 1))
else
    log_success "backend/config.dev.yml 存在"
    
    # 检查 raglite 配置
    if grep -q "ct_rag:" backend/config.dev.yml; then
        log_success "raglite 配置存在"
    else
        log_warning "raglite 配置可能不完整"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi
fi

# 检查前端配置
if [ ! -f web/app/.env.dev ]; then
    log_error "web/app/.env.dev 不存在"
    ERROR_COUNT=$((ERROR_COUNT + 1))
else
    log_success "web/app/.env.dev 存在"
fi

# 4. 检查 Raglite 版本兼容性
log_section "4️⃣ 检查 Raglite 版本兼容性"

# 检查 docker-compose 中的 raglite 版本
COMPOSE_RAGLITE_VERSION=$(grep "panda-wiki-raglite:" docker-compose.dev.yml | grep -oP ':\K[0-9-]+')
log_info "docker-compose.dev.yml 中的 raglite 版本: $COMPOSE_RAGLITE_VERSION"

# 检查本地已有的 raglite 镜像
if docker images | grep -q "panda-wiki-raglite"; then
    LOCAL_RAGLITE_VERSION=$(docker images | grep "panda-wiki-raglite" | awk '{print $2}' | head -1)
    log_info "本地 raglite 镜像版本: $LOCAL_RAGLITE_VERSION"
    
    if [ "$COMPOSE_RAGLITE_VERSION" != "$LOCAL_RAGLITE_VERSION" ]; then
        log_warning "版本不匹配！docker-compose: $COMPOSE_RAGLITE_VERSION, 本地镜像: $LOCAL_RAGLITE_VERSION"
        log_info "将拉取最新版本: $COMPOSE_RAGLITE_VERSION"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    else
        log_success "raglite 版本匹配"
    fi
else
    log_info "本地没有 raglite 镜像，将拉取"
fi

# 检查 Go SDK 版本
log_info "检查 raglite-go-sdk 版本..."
cd backend
SDK_VERSION=$(go list -m github.com/chaitin/raglite-go-sdk 2>/dev/null || echo "未找到")
cd "$PROJECT_ROOT"
log_info "raglite-go-sdk 版本: $SDK_VERSION"

if [ "$SDK_VERSION" = "未找到" ]; then
    log_error "未找到 raglite-go-sdk 依赖"
    ERROR_COUNT=$((ERROR_COUNT + 1))
else
    log_success "raglite-go-sdk 已安装"
fi

# 5. 检查 Go 依赖
log_section "5️⃣ 检查 Go 依赖"
log_info "验证 Go 模块..."
cd backend
if go mod verify > /dev/null 2>&1; then
    log_success "Go 模块验证通过"
else
    log_warning "Go 模块验证失败，尝试修复..."
    go mod tidy
    log_success "已执行 go mod tidy"
    WARNING_COUNT=$((WARNING_COUNT + 1))
fi
cd "$PROJECT_ROOT"

# 6. 检查 Node.js 依赖
log_section "6️⃣ 检查 Node.js 依赖"
if [ -d "web/app/node_modules" ]; then
    log_success "Node.js 依赖已安装"
else
    log_warning "Node.js 依赖未安装"
    log_info "请运行: cd web/app && pnpm install"
    WARNING_COUNT=$((WARNING_COUNT + 1))
fi

# 7. 拉取最新 Docker 镜像
log_section "7️⃣ 拉取 Docker 镜像"
log_info "拉取最新镜像（这可能需要几分钟）..."
if docker compose -f docker-compose.dev.yml pull; then
    log_success "Docker 镜像拉取成功"
else
    log_error "Docker 镜像拉取失败"
    ERROR_COUNT=$((ERROR_COUNT + 1))
fi

# 8. 检查端口占用
log_section "8️⃣ 检查端口占用"
PORTS=(8000 3010 5432 6379 9000 9001 4222 6333 8080)
PORT_NAMES=("API" "Web App" "PostgreSQL" "Redis" "MinIO" "MinIO Console" "NATS" "Qdrant" "Raglite")

for i in "${!PORTS[@]}"; do
    PORT=${PORTS[$i]}
    NAME=${PORT_NAMES[$i]}
    
    if lsof -i :$PORT > /dev/null 2>&1; then
        PID=$(lsof -ti :$PORT)
        log_warning "端口 $PORT ($NAME) 已被占用 (PID: $PID)"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    else
        log_success "端口 $PORT ($NAME) 可用"
    fi
done

# 9. 检查 raglite API 兼容性
log_section "9️⃣ 检查 Raglite SDK API 兼容性"
log_info "分析代码中使用的 raglite API..."

# 检查代码中使用的主要 API
RAGLITE_APIS=(
    "Datasets.Create"
    "Datasets.Delete"
    "Documents.Upload"
    "Documents.Update"
    "Documents.BatchDelete"
    "Documents.List"
    "Search.Retrieve"
    "Models.Create"
    "Models.Update"
    "Models.Upsert"
    "Models.Delete"
    "Models.List"
)

log_info "代码中使用的 raglite API:"
for api in "${RAGLITE_APIS[@]}"; do
    if grep -r "$api" backend/store/rag/ct.go > /dev/null 2>&1; then
        echo "  ✓ $api"
    fi
done

log_success "API 使用检查完成"

# 10. 生成诊断报告
log_section "📊 诊断报告"

echo -e "${CYAN}配置文件状态:${NC}"
echo "  ✓ .env: $([ -f .env ] && echo '存在' || echo '缺失')"
echo "  ✓ backend/config.dev.yml: $([ -f backend/config.dev.yml ] && echo '存在' || echo '缺失')"
echo "  ✓ web/app/.env.dev: $([ -f web/app/.env.dev ] && echo '存在' || echo '缺失')"
echo ""

echo -e "${CYAN}Raglite 版本信息:${NC}"
echo "  ✓ Docker 镜像版本: $COMPOSE_RAGLITE_VERSION"
echo "  ✓ Go SDK 版本: $SDK_VERSION"
echo ""

echo -e "${CYAN}问题统计:${NC}"
if [ $ERROR_COUNT -eq 0 ] && [ $WARNING_COUNT -eq 0 ]; then
    log_success "没有发现问题！环境配置正常"
else
    echo -e "  ${RED}错误: $ERROR_COUNT${NC}"
    echo -e "  ${YELLOW}警告: $WARNING_COUNT${NC}"
fi
echo ""

# 11. 提供修复建议
if [ $ERROR_COUNT -gt 0 ] || [ $WARNING_COUNT -gt 0 ]; then
    log_section "🔧 修复建议"
    
    if [ $ERROR_COUNT -gt 0 ]; then
        echo -e "${RED}严重问题需要手动修复:${NC}"
        echo "  1. 确保所有配置文件存在"
        echo "  2. 检查 Go 依赖是否正确安装"
        echo ""
    fi
    
    if [ $WARNING_COUNT -gt 0 ]; then
        echo -e "${YELLOW}警告可以通过以下方式修复:${NC}"
        echo "  1. 停止占用端口的进程: ./stop-local-dev.sh"
        echo "  2. 安装 Node.js 依赖: cd web/app && pnpm install"
        echo "  3. 更新 Go 依赖: cd backend && go mod tidy"
        echo ""
    fi
fi

# 12. 询问是否启动服务
log_section "🚀 启动服务"
if [ $ERROR_COUNT -eq 0 ]; then
    echo -e "${GREEN}环境检查通过！${NC}"
    echo ""
    read -p "是否现在启动所有服务？(y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "启动服务..."
        ./start-local-dev.sh
    else
        log_info "跳过启动，你可以稍后运行: ./start-local-dev.sh"
    fi
else
    log_error "发现 $ERROR_COUNT 个错误，请先修复后再启动服务"
    exit 1
fi

log_section "✅ 完成"
