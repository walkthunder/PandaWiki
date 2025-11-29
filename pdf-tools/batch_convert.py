#!/usr/bin/env python3
"""
批量 PDF 转 Markdown 转换工具

使用方法:
    python batch_convert.py --input-dir <输入目录> [选项]

示例:
    python batch_convert.py --input-dir ./pdfs --output-dir ./markdown --recursive
    python batch_convert.py --input-dir ./pdfs --max-workers 8 --skip-existing
"""

import argparse
import sys
from pathlib import Path

from batch.config_manager import ConversionConfig
from batch.batch_converter import BatchConverter


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='批量 PDF 转 Markdown 转换工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --input-dir ./pdfs
  %(prog)s --input-dir ./pdfs --output-dir ./markdown --recursive
  %(prog)s --input-dir ./pdfs --max-workers 8 --skip-existing
  %(prog)s --config config.yaml --input-dir ./pdfs
        """
    )
    
    # 必需参数
    parser.add_argument(
        '--input-dir',
        type=str,
        required=True,
        help='输入目录路径（包含 PDF 文件）'
    )
    
    # 可选参数
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='输出目录路径（默认: outputs）'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='递归扫描子目录'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        default=None,
        help='最大并发转换数（默认: 4）'
    )
    
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='跳过已存在的输出文件'
    )
    
    parser.add_argument(
        '--no-ocr',
        action='store_true',
        help='禁用 OCR 功能'
    )
    
    parser.add_argument(
        '--no-images',
        action='store_true',
        help='禁用图像提取'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='配置文件路径（YAML 格式）'
    )
    
    return parser.parse_args()


def main():
    """主函数"""
    # 解析参数
    args = parse_args()
    
    try:
        # 创建配置
        config = ConversionConfig.from_args(args)
        
        # 验证配置
        is_valid, error_message = config.validate()
        if not is_valid:
            print(f"❌ 配置错误: {error_message}", file=sys.stderr)
            sys.exit(1)
        
        # 创建批量转换器
        converter = BatchConverter(config)
        
        # 发现 PDF 文件
        print(f"🔍 扫描目录: {config.input_dir}")
        pdf_files = converter.discover_pdfs(config.input_dir, config.recursive)
        
        if not pdf_files:
            print(f"⚠️  警告: 在 {config.input_dir} 中未找到 PDF 文件")
            sys.exit(0)
        
        print(f"📄 发现 {len(pdf_files)} 个 PDF 文件")
        print(f"📁 输出目录: {config.output_dir}")
        print(f"⚙️  并发数: {config.max_workers}")
        print(f"🔄 递归扫描: {'是' if config.recursive else '否'}")
        print(f"⏭️  跳过已存在: {'是' if config.skip_existing else '否'}")
        print()
        
        # 执行批量转换
        print("🚀 开始转换...")
        report = converter.convert_batch(pdf_files)
        
        # 显示摘要
        report.print_summary()
        
        # 保存报告
        report_path = config.output_dir / "conversion_report.txt"
        report.save_to_file(report_path)
        print(f"📊 转换报告已保存到: {report_path}")
        
        # 保存错误报告（如果有错误）
        if converter.error_handler.has_errors():
            error_report_path = config.output_dir / "error_report.txt"
            converter.error_handler.save_error_report(error_report_path)
            print(f"⚠️  错误报告已保存到: {error_report_path}")
        
        # 根据结果设置退出码
        if report.failed > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断操作")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 发生错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
