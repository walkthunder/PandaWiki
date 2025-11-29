#!/usr/bin/env python3
"""
基本功能测试脚本

用于验证批量转换功能是否正常工作。
"""

import sys
from pathlib import Path

# 添加当前目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from batch.config_manager import ConversionConfig
from batch.batch_converter import BatchConverter


def test_config_creation():
    """测试配置创建"""
    print("测试 1: 配置创建...")
    
    config = ConversionConfig(
        input_dir=Path("./test_pdfs"),
        output_dir=Path("./test_output"),
        recursive=False,
        max_workers=2
    )
    
    assert config.input_dir == Path("./test_pdfs")
    assert config.output_dir == Path("./test_output")
    assert config.max_workers == 2
    
    print("✓ 配置创建测试通过")


def test_config_validation():
    """测试配置验证"""
    print("\n测试 2: 配置验证...")
    
    # 测试不存在的目录
    config = ConversionConfig(
        input_dir=Path("./nonexistent_dir"),
        output_dir=Path("./test_output")
    )
    
    is_valid, error_msg = config.validate()
    assert not is_valid
    assert "不存在" in error_msg
    
    print("✓ 配置验证测试通过")


def test_pdf_discovery():
    """测试 PDF 文件发现"""
    print("\n测试 3: PDF 文件发现...")
    
    # 使用当前目录作为测试（应该没有 PDF 文件）
    config = ConversionConfig(
        input_dir=Path("."),
        output_dir=Path("./test_output")
    )
    
    converter = BatchConverter(config)
    pdf_files = converter.discover_pdfs(Path("."), recursive=False)
    
    print(f"  发现 {len(pdf_files)} 个 PDF 文件")
    print("✓ PDF 文件发现测试通过")


def test_output_path_generation():
    """测试输出路径生成"""
    print("\n测试 4: 输出路径生成...")
    
    config = ConversionConfig(
        input_dir=Path("./input"),
        output_dir=Path("./output")
    )
    
    converter = BatchConverter(config)
    
    # 测试简单路径
    pdf_path = Path("./input/test.pdf")
    output_path = converter._get_output_path(pdf_path)
    
    assert output_path.name == "test.md"
    assert "output" in str(output_path)
    
    print(f"  输入: {pdf_path}")
    print(f"  输出: {output_path}")
    print("✓ 输出路径生成测试通过")


def main():
    """运行所有测试"""
    print("=" * 60)
    print("批量 PDF 转 Markdown - 基本功能测试")
    print("=" * 60)
    
    try:
        test_config_creation()
        test_config_validation()
        test_pdf_discovery()
        test_output_path_generation()
        
        print("\n" + "=" * 60)
        print("✓ 所有测试通过！")
        print("=" * 60)
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
