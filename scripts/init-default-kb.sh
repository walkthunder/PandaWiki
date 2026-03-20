#!/bin/bash

# 初始化默认知识库脚本
# 用于在空数据库中创建默认知识库

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🔧 初始化默认知识库${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 默认知识库ID（与 web/app/.env.dev 中的 DEV_KB_ID 一致）
DEFAULT_KB_ID="860d7e13-a4f1-4103-ba86-59ff8c11b790"
DEFAULT_KB_NAME="默认知识库"

# API地址
API_URL="http://localhost:8000"

# 默认管理员账号
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin123"

# 1. 检查API是否可用
log_info "检查API服务..."
if ! curl -s "$API_URL/api/v1/user/login" > /dev/null 2>&1; then
    log_error "API服务未运行，请先启动: ./start-local-dev.sh"
    exit 1
fi
log_success "API服务正常"

# 2. 登录获取token
log_info "登录管理员账号..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/user/login" \
  -H "Content-Type: application/json" \
  -d "{\"account\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}")

# 检查登录是否成功
if echo "$LOGIN_RESPONSE" | grep -q "token"; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    log_success "登录成功"
else
    log_error "登录失败，请检查管理员账号密码"
    echo "响应: $LOGIN_RESPONSE"
    exit 1
fi

# 3. 检查知识库是否已存在
log_info "检查知识库是否存在..."
KB_LIST=$(curl -s -X GET "$API_URL/api/v1/knowledge_base/list" \
  -H "Authorization: Bearer $TOKEN")

if echo "$KB_LIST" | grep -q "$DEFAULT_KB_ID"; then
    log_success "默认知识库已存在，无需创建"
    exit 0
fi

# 4. 创建默认知识库
log_info "创建默认知识库..."
CREATE_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/knowledge_base" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$DEFAULT_KB_NAME\",
    \"hosts\": [\"localhost\"],
    \"ports\": [3010]
  }")

# 检查创建是否成功
if echo "$CREATE_RESPONSE" | grep -q "success.*true"; then
    CREATED_KB_ID=$(echo "$CREATE_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
    log_success "知识库创建成功！ID: $CREATED_KB_ID"
    
    # 如果创建的ID与默认ID不同，提示用户更新配置
    if [ "$CREATED_KB_ID" != "$DEFAULT_KB_ID" ]; then
        log_info "创建的知识库ID与配置不同"
        echo ""
        echo -e "${YELLOW}请更新以下配置文件中的 DEV_KB_ID:${NC}"
        echo "  web/app/.env.dev"
        echo "  web/app/.env.local"
        echo ""
        echo -e "${YELLOW}将 DEV_KB_ID 改为: $CREATED_KB_ID${NC}"
        echo ""
    fi
else
    log_error "创建知识库失败"
    echo "响应: $CREATE_RESPONSE"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 初始化完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}📝 知识库信息：${NC}"
echo "  - 名称: $DEFAULT_KB_NAME"
echo "  - ID:   $CREATED_KB_ID"
echo ""
echo -e "${YELLOW}🌐 访问地址：${NC}"
echo "  - Web App: http://localhost:3010"
echo ""

