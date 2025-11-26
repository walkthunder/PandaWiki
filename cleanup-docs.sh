#!/bin/bash

# 文档清理脚本 - 将过时文档移动到归档目录

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}📦 清理文档...${NC}"

# 创建归档目录
mkdir -p docs/archive

# 移动过时的文档
echo "移动过时文档到 docs/archive/..."

# 这些文档已被 LOCAL_DEV_README.md 和 README_DEV.md 替代
docs_to_archive=(
    "FIRST_TIME_SETUP.md"
    "SETUP_SUMMARY.md"
    "LOCAL_DEV_QUICK_START.md"
    "LOCAL_DEV_PROXY_GUIDE.md"
)

for doc in "${docs_to_archive[@]}"; do
    if [ -f "$doc" ]; then
        mv "$doc" docs/archive/
        echo "  ✓ $doc"
    fi
done

# 移动过时的脚本
echo ""
echo "移动过时脚本到 docs/archive/..."

scripts_to_archive=(
    "start-local-dev.sh"
)

for script in "${scripts_to_archive[@]}"; do
    if [ -f "$script" ]; then
        mv "$script" docs/archive/
        echo "  ✓ $script"
    fi
done

echo ""
echo -e "${GREEN}✅ 清理完成！${NC}"
echo ""
echo "保留的主要文档："
echo "  - README_DEV.md          # 开发快速开始"
echo "  - LOCAL_DEV_README.md    # 详细开发指南"
echo "  - DATABASE_MIGRATION_GUIDE.md"
echo "  - QUICK_START.md"
echo ""
echo "保留的脚本："
echo "  - dev.sh                 # 统一启动脚本"
echo "  - run-api.sh            # 单独启动 API"
echo "  - run-consumer.sh       # 单独启动 Consumer"
echo "  - run-admin.sh          # 启动管理后台"
echo "  - run-app.sh            # 启动前端应用"
echo ""
echo "归档的文档在: docs/archive/"
