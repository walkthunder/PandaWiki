#!/bin/bash

# 测试Raglite集成

echo "=== 测试Raglite集成 ==="
echo ""

# 1. 测试Raglite服务健康
echo "1. 检查Raglite服务状态..."
docker ps | grep raglite
echo ""

# 2. 测试Raglite API（需要认证）
echo "2. 测试Raglite API..."
curl -s http://localhost:8080/api/v1/models 2>&1 | head -5
echo ""

# 3. 测试后端API
echo "3. 测试后端API..."
curl -s http://localhost:8000/api/v1/user/login 2>&1 | head -5
echo ""

# 4. 检查所有Docker服务
echo "4. 检查所有Docker服务..."
docker ps --format "table {{.Names}}\t{{.Status}}" | grep panda-wiki
echo ""

echo "=== 测试完成 ==="
