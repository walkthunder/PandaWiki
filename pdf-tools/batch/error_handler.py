"""
错误处理模块

提供统一的错误处理和报告功能。
"""

import logging
import traceback
from pathlib import Path
from typing import List
from datetime import datetime

from .models import ConversionError, ConversionResult


class ErrorHandler:
    """错误处理器"""
    
    def __init__(self, logger: logging.Logger):
        """
        初始化错误处理器
        
        Args:
            logger: 日志记录器
        """
        self.logger = logger
        self.errors: List[ConversionError] = []
    
    def handle_conversion_error(self, pdf_path: Path, error: Exception) -> ConversionResult:
        """
        处理转换错误
        
        Args:
            pdf_path: PDF 文件路径
            error: 异常对象
            
        Returns:
            ConversionResult: 失败的转换结果
        """
        error_info = ConversionError(
            pdf_path=pdf_path,
            error_type=type(error).__name__,
            error_message=str(error),
            traceback=traceback.format_exc(),
            timestamp=datetime.now()
        )
        self.errors.append(error_info)
        self.logger.error(f"转换失败 {pdf_path}: {error}")
        
        return ConversionResult(
            pdf_path=pdf_path,
            output_path=None,
            success=False,
            error_message=str(error),
            processing_time=0.0
        )
    
    def save_error_report(self, output_path: Path):
        """
        保存错误报告到文件
        
        Args:
            output_path: 输出文件路径
        """
        if not self.errors:
            return
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("错误报告\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"总错误数: {len(self.errors)}\n\n")
            
            for i, error in enumerate(self.errors, 1):
                f.write(f"错误 #{i}\n")
                f.write("-" * 80 + "\n")
                f.write(f"文件: {error.pdf_path}\n")
                f.write(f"错误类型: {error.error_type}\n")
                f.write(f"错误消息: {error.error_message}\n")
                f.write(f"时间: {error.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n详细堆栈:\n{error.traceback}\n")
                f.write("=" * 80 + "\n\n")
        
        self.logger.info(f"错误报告已保存到: {output_path}")
    
    def has_errors(self) -> bool:
        """检查是否有错误"""
        return len(self.errors) > 0
    
    def get_error_count(self) -> int:
        """获取错误数量"""
        return len(self.errors)
