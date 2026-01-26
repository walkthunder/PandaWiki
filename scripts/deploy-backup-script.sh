#!/bin/bash

# 部署备份脚本到服务器
# 用途: 将备份脚本和依赖文件部署到线上服务器

set -e

# 配置
SERVER_IP="${SERVER_IP:-8.140.221.27}"
SERVER_USER="${SERVER_USER:-root}"
SERVER_PATH="${SERVER_PATH:-/root}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# SSH 执行命令
ssh_exec() {
    if [ -z "$SSH_KEY_PATH" ]; then
        ssh -o ConnectTimeout=10 "$SERVER_USER@$SERVER_IP" "$1"
    else
        ssh -i "$SSH_KEY_PATH" -o ConnectTimeout=10 "$SERVER_USER@$SERVER_IP" "$1"
    fi
}

# SCP 传输文件
scp_file() {
    local src="$1"
    local dst="$2"
    
    if [ -z "$SSH_KEY_PATH" ]; then
        scp "$src" "$SERVER_USER@$SERVER_IP:$dst"
    else
        scp -i "$SSH_KEY_PATH" "$src" "$SERVER_USER@$SERVER_IP:$dst"
    fi
}

echo ""
echo "=========================================="
echo "   部署备份脚本到服务器"
echo "=========================================="
echo ""

# 检查本地文件
print_info "检查本地文件..."
if [ ! -f "scripts/backup-to-cos.sh" ]; then
    print_error "备份脚本不存在: scripts/backup-to-cos.sh"
    exit 1
fi

if [ ! -f "scripts/upload_backup_to_cos.py" ]; then
    print_error "上传脚本不存在: scripts/upload_backup_to_cos.py"
    exit 1
fi

print_success "本地文件检查完成"

# 检查 SSH 连接
print_info "检查 SSH 连接到 $SERVER_USER@$SERVER_IP ..."
if ssh_exec "echo 'SSH connection OK'" > /dev/null 2>&1; then
    print_success "SSH 连接正常"
else
    print_error "无法连接到服务器"
    exit 1
fi

# 创建服务器目录
print_info "创建服务器目录..."
ssh_exec "mkdir -p ${SERVER_PATH}/scripts ${SERVER_PATH}/backups ${SERVER_PATH}/logs"
print_success "目录创建完成"

# 上传脚本文件
print_info "上传备份脚本..."
scp_file "scripts/backup-to-cos.sh" "${SERVER_PATH}/scripts/"
scp_file "scripts/upload_backup_to_cos.py" "${SERVER_PATH}/scripts/"
print_success "脚本上传完成"

# 设置执行权限
print_info "设置执行权限..."
ssh_exec "chmod +x ${SERVER_PATH}/scripts/backup-to-cos.sh ${SERVER_PATH}/scripts/upload_backup_to_cos.py"
print_success "权限设置完成"

# 检查 Python 和依赖
print_info "检查服务器环境..."
if ssh_exec "command -v python3 &> /dev/null"; then
    print_success "Python3 已安装"
else
    print_error "Python3 未安装，请先安装 Python3"
    exit 1
fi

# 安装腾讯云 COS SDK
print_info "检查腾讯云 COS SDK..."
if ssh_exec "python3 -c 'import qcloud_cos' 2>/dev/null"; then
    print_success "腾讯云 COS SDK 已安装"
else
    print_info "正在安装腾讯云 COS SDK..."
    ssh_exec "pip3 install -q cos-python-sdk-v5"
    print_success "腾讯云 COS SDK 安装完成"
fi

# 测试备份脚本
echo ""
print_info "是否立即测试备份脚本? (y/n)"
read -p "> " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "执行测试备份..."
    ssh_exec "cd ${SERVER_PATH} && bash scripts/backup-to-cos.sh"
fi

# 显示 crontab 配置建议
echo ""
echo "=========================================="
echo "           部署完成"
echo "=========================================="
echo ""
print_success "备份脚本已成功部署到服务器"
echo ""
echo "📍 脚本位置: ${SERVER_PATH}/scripts/backup-to-cos.sh"
echo "📍 日志目录: ${SERVER_PATH}/logs/"
echo "📍 备份目录: ${SERVER_PATH}/backups/"
echo ""
echo "💡 配置定时任务建议:"
echo ""
echo "在服务器上执行:"
echo "  ssh $SERVER_USER@$SERVER_IP"
echo "  crontab -e"
echo ""
echo "添加以下行:"
echo ""
echo "  # 每天凌晨3点执行完整备份"
echo "  0 3 * * * cd ${SERVER_PATH} && bash scripts/backup-to-cos.sh >> logs/backup.log 2>&1"
echo ""
echo "  # 每周日凌晨4点执行完整备份（额外保险）"
echo "  0 4 * * 0 cd ${SERVER_PATH} && bash scripts/backup-to-cos.sh >> logs/backup_weekly.log 2>&1"
echo ""
echo "=========================================="
