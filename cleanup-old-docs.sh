#!/bin/bash

# 清理旧的和重复的文档
# 将过时的文档移动到 docs/archive 目录

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}📚 清理旧的和重复的文档${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 创建归档目录
mkdir -p docs/archive

echo -e "${YELLOW}📦 移动旧文档到 docs/archive/...${NC}"
echo ""

# 需要归档的旧文档（已被新文档替代）
old_docs=(
    "LOCAL_DEV_README.md"      # 被 LOCAL_DEV_QUICK_START.md 替代
    "README_DEV.md"            # 被 LOCAL_DEV_QUICK_START.md 替代
    "DEVELOPMENT.md"           # 被 LOCAL_DEV_SCRIPTS.md 替代
    "QUICK_REFERENCE.md"       # 内容已整合到新文档
    "DEPLOYMENT_QUICK_REF.md"  # 内容已整合到 DEPLOYMENT_GUIDE.md
    "CHANGELOG_DEV.md"         # 开发日志，可归档
)

moved_count=0

for doc in "${old_docs[@]}"; do
    if [ -f "$doc" ]; then
        mv "$doc" docs/archive/
        echo -e "  ${GREEN}✓${NC} $doc → docs/archive/"
        moved_count=$((moved_count + 1))
    else
        echo -e "  ${YELLOW}⊘${NC} $doc (不存在)"
    fi
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ 清理完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ $moved_count -gt 0 ]; then
    echo -e "${YELLOW}📊 统计：${NC}"
    echo "  - 移动了 $moved_count 个旧文档"
    echo "  - 归档位置: docs/archive/"
    echo ""
fi

echo -e "${YELLOW}📖 当前主要文档：${NC}"
echo ""
echo -e "${GREEN}本地开发：${NC}"
echo "  LOCAL_DEV_QUICK_START.md  - 快速启动指南（推荐阅读）"
echo "  LOCAL_DEV_SCRIPTS.md      - 脚本详细说明"
echo "  LOCAL_DEV_GUIDE.md        - 完整开发指南"
echo ""
echo -e "${GREEN}部署相关：${NC}"
echo "  DEPLOYMENT_GUIDE.md       - 部署指南"
echo "  DEPLOYMENT_SUMMARY.md     - 部署总结"
echo ""
echo -e "${GREEN}数据库：${NC}"
echo "  DATABASE_MIGRATION_GUIDE.md      - 数据库迁移指南"
echo "  MIGRATION_QUICK_REFERENCE.md     - 迁移快速参考"
echo ""
echo -e "${GREEN}其他：${NC}"
echo "  README.md                 - 项目主文档"
echo "  QUICK_START.md            - 快速开始"
echo "  PROJECT_STRUCTURE.md      - 项目结构"
echo "  START_HERE.md             - 从这里开始"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "  - 新手请先阅读: LOCAL_DEV_QUICK_START.md"
echo "  - 详细说明请看: LOCAL_DEV_SCRIPTS.md"
echo "  - 如需恢复旧文档，可从 docs/archive/ 目录复制"
echo ""
