#!/usr/bin/env python3
"""
优化的批量 PDF 转 Markdown 转换工具

特点：
- 自动跳过大于 50MB 的文件
- 显示文件大小信息
- 更好的错误处理
"""

import argparse
import sys
from pathlib import Path

from batch.config_manager import ConversionConfig
from batch.batch_converter import BatchConverter


def format_size(size_bytes):
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}TB"


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='优化的批量 PDF 转 Markdown 转换工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --input-dir ./pdfs
  %(prog)s --input-dir ./pdfs --output-dir ./markdown --recursive
  %(prog)s --input-dir ./pdfs --max-workers 2
        """
    )
    
    parser.add_argument(
        '--input-dir',
        type=str,
        required=True,
        help='输入目录路径（包含 PDF 文件）'
    )
    
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
        default=2,
        help='最大并发数（默认: 2，建议不超过 4）'
    )
    
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='跳过已存在的输出文件'
    )
    
    parser.add_argument(
        '--max-size-mb',
        type=int,
        default=50,
        help='最大文件大小（MB），超过此大小的文件将被跳过（默认: 50）'
    )
    
    return parser.parse_args()


def main():
    """主函数"""
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
        all_pdf_files = converter.discover_pdfs(config.input_dir, config.recursive)
        
        if not all_pdf_files:
            print(f"⚠️  警告: 在 {config.input_dir} 中未找到 PDF 文件")
            sys.exit(0)
        
        # 过滤大文件
        max_size_bytes = args.max_size_mb * 1024 * 1024
        pdf_files = []
        skipped_large = []
        
        for pdf in all_pdf_files:
            size = pdf.stat().st_size
            if size > max_size_bytes:
                skipped_large.append((pdf, size))
            else:
                pdf_files.append(pdf)
        
        print(f"📄 发现 {len(all_pdf_files)} 个 PDF 文件")
        if skipped_large:
            print(f"⚠️  跳过 {len(skipped_large)} 个大文件（>{args.max_size_mb}MB）:")
            for pdf, size in skipped_large[:5]:  # 只显示前 5 个
                print(f"   - {pdf.name} ({format_size(size)})")
            if len(skipped_large) > 5:
                print(f"   ... 还有 {len(skipped_large) - 5} 个")
        
        if not pdf_files:
            print("⚠️  所有文件都被跳过，没有可转换的文件")
            sys.exit(0)
        
        print(f"✅ 将转换 {len(pdf_files)} 个文件")
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
