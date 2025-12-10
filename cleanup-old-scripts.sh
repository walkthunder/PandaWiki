#!/bin/bash

# 清理旧的本地开发脚本
# 将过时的脚本移动到 scripts/archive 目录

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🧹 清理旧的本地开发脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 创建归档目录
mkdir -p scripts/archive

echo -e "${YELLOW}📦 移动旧脚本到 scripts/archive/...${NC}"
echo ""

# 需要归档的旧脚本
old_scripts=(
    "dev.sh"
    "start-all.sh"
    "run-api.sh"
    "run-app.sh"
    "run-admin.sh"
    "run-consumer.sh"
    "verify-setup.sh"
)

moved_count=0

for script in "${old_scripts[@]}"; do
    if [ -f "$script" ]; then
        mv "$script" scripts/archive/
        echo -e "  ${GREEN}✓${NC} $script → scripts/archive/"
        moved_count=$((moved_count + 1))
    else
        echo -e "  ${YELLOW}⊘${NC} $script (不存在)"
    fi
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 清理完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ $moved_count -gt 0 ]; then
    echo -e "${YELLOW}📊 统计：${NC}"
    echo "  - 移动了 $moved_count 个旧脚本"
    echo "  - 归档位置: scripts/archive/"
    echo ""
fi

echo -e "${YELLOW}🎯 当前可用的脚本：${NC}"
echo ""
echo -e "${GREEN}主要脚本：${NC}"
echo "  ./start-local-dev.sh    - 一键启动所有服务"
echo "  ./stop-local-dev.sh     - 停止所有服务"
echo "  ./check-local-dev.sh    - 检查服务状态"
echo ""
echo -e "${GREEN}文档：${NC}"
echo "  LOCAL_DEV_QUICK_START.md  - 快速启动指南"
echo "  LOCAL_DEV_SCRIPTS.md      - 脚本详细说明"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "  - 新脚本使用 admin123 作为统一密码（来自 .env）"
echo "  - 旧脚本使用 panda-wiki 作为密码（已过时）"
echo "  - 如需恢复旧脚本，可从 scripts/archive/ 目录复制"
echo ""
