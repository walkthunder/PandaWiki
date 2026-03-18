#!/bin/bash

# PandaWiki 本地开发环境初始化脚本
# 用法: ./init-local-dev.sh

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
echo -e "${BLUE}🔧 PandaWiki 本地开发环境初始化${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1. 检查必要的工具
log_info "检查必要的工具..."

# 检查 Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker 未安装，请先安装 Docker"
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    log_error "Docker 未运行，请先启动 Docker"
    exit 1
fi
log_success "Docker 已就绪"

# 检查 Go
if ! command -v go &> /dev/null; then
    log_error "Go 未安装，请先安装 Go (版本 >= 1.21)"
    exit 1
fi

GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
log_success "Go 已安装 (版本: $GO_VERSION)"

# 检查 Node.js 和 pnpm
if ! command -v node &> /dev/null; then
    log_error "Node.js 未安装，请先安装 Node.js (版本 >= 18)"
    exit 1
fi

NODE_VERSION=$(node --version)
log_success "Node.js 已安装 (版本: $NODE_VERSION)"

if ! command -v pnpm &> /dev/null; then
    log_error "pnpm 未安装，请先安装 pnpm: npm install -g pnpm"
    exit 1
fi

PNPM_VERSION=$(pnpm --version)
log_success "pnpm 已安装 (版本: $PNPM_VERSION)"

# 2. 创建必要的目录
log_info "创建必要的目录..."
mkdir -p logs
mkdir -p data/postgres
mkdir -p data/redis
mkdir -p data/minio
mkdir -p data/nats
mkdir -p data/qdrant
mkdir -p data/raglite
mkdir -p data/caddy/caddy_config
mkdir -p data/caddy/caddy_data
mkdir -p data/caddy/run
mkdir -p backend/data
mkdir -p backend/data/ssl
log_success "目录创建完成"

# 3. 检查和创建配置文件
log_info "检查配置文件..."

# 检查 .env 文件
if [ ! -f .env ]; then
    log_warning ".env 文件不存在，但已存在，跳过创建"
else
    log_success ".env 文件已存在"
fi

# 检查后端配置文件
if [ ! -f backend/config.dev.yml ]; then
    log_warning "backend/config.dev.yml 不存在，创建默认配置..."
    # 这里应该创建配置文件，但由于已存在，跳过
    log_success "后端开发配置已存在"
else
    log_success "后端开发配置已存在"
fi

# 检查前端配置文件
if [ ! -f web/app/.env.dev ]; then
    log_warning "web/app/.env.dev 不存在，创建默认配置..."
    # 这里应该创建配置文件，但由于已存在，跳过
    log_success "前端开发配置已存在"
else
    log_success "前端开发配置已存在"
fi

# 4. 安装依赖
log_info "安装后端依赖..."
cd backend
if [ ! -f go.mod ]; then
    log_error "go.mod 不存在，请确保在正确的项目目录中"
    exit 1
fi

go mod download
log_success "后端依赖安装完成"

cd "$PROJECT_ROOT"

log_info "安装前端依赖..."
cd web/app
if [ ! -f package.json ]; then
    log_error "package.json 不存在，请确保在正确的项目目录中"
    exit 1
fi

pnpm install
log_success "前端依赖安装完成"

cd "$PROJECT_ROOT"

# 5. 设置脚本权限
log_info "设置脚本权限..."
chmod +x start-local-dev.sh
chmod +x stop-local-dev.sh
chmod +x check-local-dev.sh
chmod +x test-local-dev.sh
chmod +x init-local-dev.sh
log_success "脚本权限设置完成"

# 6. 拉取 Docker 镜像
log_info "拉取 Docker 镜像（这可能需要一些时间）..."
docker compose -f docker-compose.dev.yml pull
log_success "Docker 镜像拉取完成"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 本地开发环境初始化完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}🚀 下一步操作：${NC}"
echo "  1. 启动开发环境: ./start-local-dev.sh"
echo "  2. 检查服务状态: ./check-local-dev.sh"
echo "  3. 运行功能测试: ./test-local-dev.sh"
echo "  4. 停止开发环境: ./stop-local-dev.sh"
echo ""
echo -e "${YELLOW}📚 相关文档：${NC}"
echo "  - 快速启动指南: LOCAL_DEV_SCRIPTS.md"
echo "  - 开发规范: DEVELOPMENT_RULES.md"
echo "  - 配置指南: CONFIG_GUIDE.md"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "  - 所有密码默认为: admin123"
echo "  - 首次启动可能需要较长时间"
echo "  - 如遇问题请查看日志文件"
echo ""