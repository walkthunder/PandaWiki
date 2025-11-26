#!/bin/bash

# 停止本地开发环境

set -e

echo "🛑 停止本地开发环境..."

# 停止依赖服务
docker compose -f docker-compose.local.yml down

# 恢复配置文件
if [ -f backend/config.yml.backup ]; then
  mv backend/config.yml.backup backend/config.yml
  echo "✅ 已恢复原配置文件"
fi

echo "✅ 本地开发环境已停止"
