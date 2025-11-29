#!/bin/bash
#
# 验证和整理输出文件脚本
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/validate_and_organize.py"

# 检查 Python 脚本是否存在
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "❌ 错误: 找不到 validate_and_organize.py"
    exit 1
fi

# 检查并激活虚拟环境（如果存在）
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
elif [ -d "$SCRIPT_DIR/.venv" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

# 检查 Python 是否可用
if ! command -v python3 &> /dev/null; then
    echo "❌ 错误: 未找到 python3"
    exit 1
fi

# 执行 Python 脚本，传递所有参数
python3 "$PYTHON_SCRIPT" "$@"

# 保存退出码
EXIT_CODE=$?

# 如果激活了虚拟环境，则停用
if [ -n "$VIRTUAL_ENV" ]; then
    deactivate 2>/dev/null || true
fi

# 返回 Python 脚本的退出码
exit $EXIT_CODE
