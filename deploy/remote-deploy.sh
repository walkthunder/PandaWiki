#!/bin/bash

# 远程部署脚本 - 用于在服务器上加载Docker镜像并更新容器

set -e  # 遇到错误时退出

# 配置变量
PROJECT_PATH="/root"  # PandaWiki项目在服务器上的路径，例如: /opt/pandawiki
IMAGE_TAR_PATH="/tmp/panda-wiki-api.tar"  # 镜像tar文件在服务器上的路径
SERVICE_NAME="api"  # docker-compose.yml中定义的服务名称
CONTAINER_NAME="panda-wiki-api"  # 容器名称

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}开始远程部署流程...${NC}"

# 检查必要参数
if [ -z "$PROJECT_PATH" ]; then
    echo -e "${RED}错误: 请设置 PROJECT_PATH 变量为PandaWiki项目在服务器上的路径${NC}"
    exit 1
fi

# 检查镜像tar文件是否存在
if [ ! -f "$IMAGE_TAR_PATH" ]; then
    echo -e "${RED}错误: 镜像文件 $IMAGE_TAR_PATH 不存在${NC}"
    exit 1
fi

# 进入项目目录（提前进入以便执行备份）
cd $PROJECT_PATH

# 部署前自动备份数据库
echo -e "${YELLOW}步骤0: 部署前备份数据库...${NC}"
BACKUP_DIR="./backups/postgres"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/pre_deploy_${TIMESTAMP}.sql.gz"

# 检查容器是否运行
if docker ps --format '{{.Names}}' | grep -q "^panda-wiki-postgres$"; then
    # 读取数据库密码
    if [ -f ".env" ]; then
        source .env
        if [ -n "$POSTGRES_PASSWORD" ]; then
            echo -e "${YELLOW}正在备份数据库...${NC}"
            docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" panda-wiki-postgres \
                pg_dump -U panda-wiki -d panda-wiki \
                --format=plain --no-owner --no-acl | gzip > "$BACKUP_FILE"
            
            if [ $? -eq 0 ]; then
                BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
                echo -e "${GREEN}数据库备份成功: $BACKUP_FILE (大小: $BACKUP_SIZE)${NC}"
            else
                echo -e "${RED}警告: 数据库备份失败，但继续部署${NC}"
            fi
        else
            echo -e "${YELLOW}警告: POSTGRES_PASSWORD 未设置，跳过备份${NC}"
        fi
    else
        echo -e "${YELLOW}警告: .env 文件不存在，跳过备份${NC}"
    fi
else
    echo -e "${YELLOW}警告: PostgreSQL容器未运行，跳过备份${NC}"
fi

# 1. 加载Docker镜像
echo -e "${YELLOW}步骤1: 加载Docker镜像...${NC}"
docker load -i $IMAGE_TAR_PATH

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Docker镜像加载成功${NC}"
else
    echo -e "${RED}错误: Docker镜像加载失败${NC}"
    exit 1
fi

# 2. 停止指定的服务（已在步骤0中进入项目目录）
echo -e "${YELLOW}步骤2: 停止 $SERVICE_NAME 服务...${NC}"
docker compose stop $SERVICE_NAME

# 3. 删除旧的容器
echo -e "${YELLOW}步骤3: 删除旧的容器...${NC}"
docker compose rm -f $SERVICE_NAME

# 4. 启动服务（会使用新加载的镜像）
echo -e "${YELLOW}步骤4: 启动 $SERVICE_NAME 服务...${NC}"
docker compose up -d $SERVICE_NAME
# 重启Caddy
docker compose restart caddy

# 5. 检查容器状态
echo -e "${YELLOW}步骤5: 检查容器状态...${NC}"
sleep 5  # 等待容器启动
CONTAINER_STATUS=$(docker ps -f name=$CONTAINER_NAME --format "{{.Status}}")

if [[ $CONTAINER_STATUS == *"Up"* ]]; then
    echo -e "${GREEN}容器 $CONTAINER_NAME 已成功启动并运行${NC}"
else
    echo -e "${RED}警告: 容器 $CONTAINER_NAME 可能未正常运行，请检查日志${NC}"
    docker compose logs $SERVICE_NAME
fi

# 6. 清理镜像tar文件
echo -e "${YELLOW}步骤6: 清理镜像tar文件...${NC}"
rm $IMAGE_TAR_PATH
echo -e "${GREEN}镜像tar文件已清理${NC}"

echo -e "${GREEN}远程部署完成!${NC}"