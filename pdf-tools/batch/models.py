"""
数据模型定义

包含批量转换过程中使用的所有数据类。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List
from datetime import datetime


@dataclass
class PDFFileInfo:
    """PDF 文件信息"""
    path: Path
    relative_path: Path  # 相对于输入目录的路径
    size: int
    output_path: Path


@dataclass
class ConversionError:
    """转换错误信息"""
    pdf_path: Path
    error_type: str
    error_message: str
    traceback: str
    timestamp: datetime


@dataclass
class ConversionResult:
    """单个文件的转换结果"""
    pdf_path: Path
    output_path: Optional[Path]
    success: bool
    error_message: Optional[str]
    processing_time: float


@dataclass
class ConversionReport:
    """批量转换报告"""
    total_files: int
    successful: int
    failed: int
    skipped: int
    results: List[ConversionResult]
    total_time: float
    
    def save_to_file(self, output_path: Path):
        """保存报告到文件"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("批量 PDF 转 Markdown 转换报告\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"总文件数: {self.total_files}\n")
            f.write(f"成功: {self.successful}\n")
            f.write(f"失败: {self.failed}\n")
            f.write(f"跳过: {self.skipped}\n")
            f.write(f"总耗时: {self.total_time:.2f} 秒\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("详细结果\n")
            f.write("=" * 80 + "\n\n")
            
            for result in self.results:
                status = "✓ 成功" if result.success else "✗ 失败"
                f.write(f"{status} | {result.pdf_path.name}\n")
                if result.output_path:
                    f.write(f"  输出: {result.output_path}\n")
                if result.error_message:
                    f.write(f"  错误: {result.error_message}\n")
                f.write(f"  耗时: {result.processing_time:.2f} 秒\n\n")
    
    def print_summary(self):
        """打印摘要到控制台"""
        print("\n" + "=" * 80)
        print("转换完成！")
        print("=" * 80)
        print(f"总文件数: {self.total_files}")
        print(f"✓ 成功: {self.successful}")
        print(f"✗ 失败: {self.failed}")
        print(f"⊘ 跳过: {self.skipped}")
        print(f"总耗时: {self.total_time:.2f} 秒")
        print("=" * 80 + "\n")
