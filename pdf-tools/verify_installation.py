#!/usr/bin/env python3
"""
安装验证脚本

检查批量转换工具是否正确安装。
"""

import sys
from pathlib import Path


def check_file_exists(filepath, description):
    """检查文件是否存在"""
    if Path(filepath).exists():
        print(f"✓ {description}: {filepath}")
        return True
    else:
        print(f"✗ {description} 不存在: {filepath}")
        return False


def check_directory_exists(dirpath, description):
    """检查目录是否存在"""
    if Path(dirpath).exists() and Path(dirpath).is_dir():
        print(f"✓ {description}: {dirpath}")
        return True
    else:
        print(f"✗ {description} 不存在: {dirpath}")
        return False


def main():
    """主函数"""
    print("=" * 60)
    print("批量 PDF 转 Markdown - 安装验证")
    print("=" * 60)
    print()
    
    all_ok = True
    
    # 检查核心文件
    print("检查核心文件:")
    all_ok &= check_file_exists("extract.py", "原始转换脚本")
    all_ok &= check_file_exists("batch_convert.py", "批量转换主程序")
    all_ok &= check_file_exists("convert.sh", "Shell 包装脚本")
    all_ok &= check_file_exists("requirements.txt", "依赖列表")
    print()
    
    # 检查批量处理模块
    print("检查批量处理模块:")
    all_ok &= check_directory_exists("batch", "批量处理目录")
    all_ok &= check_file_exists("batch/__init__.py", "模块初始化文件")
    all_ok &= check_file_exists("batch/models.py", "数据模型")
    all_ok &= check_file_exists("batch/config_manager.py", "配置管理")
    all_ok &= check_file_exists("batch/progress_reporter.py", "进度报告")
    all_ok &= check_file_exists("batch/error_handler.py", "错误处理")
    all_ok &= check_file_exists("batch/batch_converter.py", "批量转换器")
    print()
    
    # 检查配置文件
    print("检查配置文件:")
    all_ok &= check_directory_exists("config", "配置目录")
    all_ok &= check_file_exists("config/config.yaml", "默认配置")
    all_ok &= check_file_exists("config/batch_config.yaml", "批量转换配置示例")
    print()
    
    # 检查文档
    print("检查文档:")
    all_ok &= check_file_exists("README.md", "主文档")
    all_ok &= check_file_exists("BATCH_CONVERT_README.md", "批量转换文档")
    all_ok &= check_file_exists("QUICKSTART.md", "快速入门指南")
    print()
    
    # 检查测试目录
    print("检查测试目录:")
    all_ok &= check_directory_exists("tests", "测试目录")
    all_ok &= check_file_exists("tests/__init__.py", "测试模块初始化")
    print()
    
    # 检查脚本权限
    print("检查脚本权限:")
    convert_sh = Path("convert.sh")
    if convert_sh.exists():
        import os
        if os.access(convert_sh, os.X_OK):
            print(f"✓ convert.sh 有执行权限")
        else:
            print(f"⚠️  convert.sh 没有执行权限，运行: chmod +x convert.sh")
            all_ok = False
    print()
    
    # 总结
    print("=" * 60)
    if all_ok:
        print("✓ 所有检查通过！安装成功。")
        print()
        print("下一步:")
        print("1. 安装依赖: pip install -r requirements.txt")
        print("2. 查看快速入门: cat QUICKSTART.md")
        print("3. 运行转换: ./convert.sh --input-dir <你的PDF目录>")
    else:
        print("✗ 某些检查失败，请检查安装。")
        return 1
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
