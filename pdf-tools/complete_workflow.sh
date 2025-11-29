#!/bin/bash
#
# 完整的 PDF 转 Markdown 工作流程
# 包括：转换 -> 验证 -> 上传到 COS
#

set -e  # 遇到错误时退出

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "PDF 转 Markdown 完整工作流程"
echo "============================================================"

# 检查参数
if [ $# -lt 1 ]; then
    echo "使用方法: $0 <PDF目录> [选项]"
    echo ""
    echo "示例:"
    echo "  $0 ./docs/standards"
    echo "  $0 ./docs/standards --max-workers 4"
    echo "  $0 ./docs/standards --skip-cos"
    echo ""
    echo "选项:"
    echo "  --max-workers N    设置最大并发数（默认: 2）"
    echo "  --skip-cos         跳过 COS 上传步骤"
    echo "  --help             显示帮助信息"
    exit 1
fi

INPUT_DIR="$1"
shift

# 解析选项
MAX_WORKERS=2
SKIP_COS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        --skip-cos)
            SKIP_COS=true
            shift
            ;;
        --help)
            echo "PDF 转 Markdown 完整工作流程"
            echo ""
            echo "此脚本会依次执行："
            echo "1. 批量转换 PDF 到 Markdown"
            echo "2. 验证和整理输出文件"
            echo "3. 上传图片到腾讯云 COS（可选）"
            echo ""
            echo "使用方法: $0 <PDF目录> [选项]"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 检查输入目录
if [ ! -d "$INPUT_DIR" ]; then
    echo "❌ 错误: 输入目录不存在: $INPUT_DIR"
    exit 1
fi

echo "📁 输入目录: $INPUT_DIR"
echo "⚙️  最大并发数: $MAX_WORKERS"
echo "🌐 上传到 COS: $([ "$SKIP_COS" = true ] && echo "跳过" || echo "是")"
echo ""

# 步骤 1: 批量转换 PDF
echo "🚀 步骤 1/3: 批量转换 PDF 到 Markdown"
echo "------------------------------------------------------------"
if [ -f "$SCRIPT_DIR/convert_optimized.sh" ]; then
    "$SCRIPT_DIR/convert_optimized.sh" --input-dir "$INPUT_DIR" --max-workers "$MAX_WORKERS"
    CONVERT_EXIT_CODE=$?
else
    echo "❌ 错误: 找不到 convert_optimized.sh"
    exit 1
fi

if [ $CONVERT_EXIT_CODE -ne 0 ]; then
    echo "⚠️  转换过程中有错误，但继续执行验证步骤..."
fi

echo ""

# 步骤 2: 验证和整理
echo "🔍 步骤 2/3: 验证和整理输出文件"
echo "------------------------------------------------------------"
if [ -f "$SCRIPT_DIR/validate_outputs.sh" ]; then
    "$SCRIPT_DIR/validate_outputs.sh"
    VALIDATE_EXIT_CODE=$?
else
    echo "❌ 错误: 找不到 validate_outputs.sh"
    exit 1
fi

if [ $VALIDATE_EXIT_CODE -ne 0 ]; then
    echo "❌ 验证失败"
    exit 1
fi

echo ""

# 步骤 3: 上传到 COS（可选）
if [ "$SKIP_COS" = false ]; then
    echo "☁️  步骤 3/3: 上传图片到腾讯云 COS"
    echo "------------------------------------------------------------"
    # 检查是否有有效文件
    if [ ! -d "$SCRIPT_DIR/outputs/valid" ] || [ -z "$(ls -A "$SCRIPT_DIR/outputs/valid"/*.png 2>/dev/null)" ]; then
        echo "⚠️  没有找到有效的图片文件，跳过 COS 上传"
    else
        if [ -f "$SCRIPT_DIR/upload_to_cos.sh" ]; then
            "$SCRIPT_DIR/upload_to_cos.sh"
            COS_EXIT_CODE=$?
        else
            echo "❌ 错误: 找不到 upload_to_cos.sh"
            exit 1
        fi
        
        if [ $COS_EXIT_CODE -ne 0 ]; then
            echo "⚠️  COS 上传过程中有错误"
        fi
    fi
else
    echo "⊘ 步骤 3/3: 跳过 COS 上传"
    echo "------------------------------------------------------------"
    echo "如需上传图片到 COS，请运行: ./upload_to_cos.sh"
fi

echo ""

# 总结
echo "============================================================"
echo "工作流程完成！"
echo "============================================================"

# 显示结果摘要
if [ -f "$SCRIPT_DIR/outputs/validation_report.md" ]; then
    echo "📊 转换结果摘要:"
    grep -E "转换成功率|总 MD 文件数|有效 MD 文件|无效 MD 文件" "$SCRIPT_DIR/outputs/validation_report.md" | head -4
    echo ""
fi

echo "📁 输出文件位置:"
echo "   - 有效文件: outputs/valid/"
echo "   - 无效文件: outputs/invalid/"
echo "   - 验证报告: outputs/validation_report.md"

if [ "$SKIP_COS" = false ] && [ -f "$SCRIPT_DIR/outputs/valid/cos_upload_report.md" ]; then
    echo "   - COS 上传报告: outputs/valid/cos_upload_report.md"
fi

echo ""
echo "💡 下一步建议:"
echo "   1. 查看验证报告: cat outputs/validation_report.md"
echo "   2. 检查有效文件: ls -la outputs/valid/"

if [ "$SKIP_COS" = false ]; then
    echo "   3. 查看 COS 报告: cat outputs/valid/cos_upload_report.md"
    echo "   4. （可选）删除本地图片: rm outputs/valid/*.png"
else
    echo "   3. 上传到 COS: ./upload_to_cos.sh"
fi

echo ""
echo "🎉 所有任务完成！"
