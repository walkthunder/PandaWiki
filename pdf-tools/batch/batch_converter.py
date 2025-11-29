"""
批量转换器模块

提供批量 PDF 转 Markdown 的核心功能。
"""

import sys
import os
import logging
import time
import traceback
from pathlib import Path
from typing import List
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

# 添加父目录到 Python 路径，以便导入 extract 模块
sys.path.insert(0, str(Path(__file__).parent.parent))

from .config_manager import ConversionConfig
from .models import ConversionResult, ConversionReport, ConversionError
from .progress_reporter import ProgressReporter
from .error_handler import ErrorHandler


def _convert_single_static(pdf_path: Path, input_dir: Path, output_dir: Path, skip_existing: bool) -> ConversionResult:
    """
    静态函数：转换单个 PDF 文件（用于多进程）
    
    Args:
        pdf_path: PDF 文件路径
        input_dir: 输入目录
        output_dir: 输出目录
        skip_existing: 是否跳过已存在的文件
        
    Returns:
        ConversionResult: 转换结果
    """
    start_time = time.time()
    
    try:
        # 检查文件大小，跳过大于 50MB 的文件
        file_size_mb = pdf_path.stat().st_size / (1024 * 1024)
        if file_size_mb > 50:
            return ConversionResult(
                pdf_path=pdf_path,
                output_path=None,
                success=False,
                error_message=f"文件过大 ({file_size_mb:.1f}MB)，跳过处理",
                processing_time=0.0
            )
        
        # 计算输出路径
        try:
            relative_path = pdf_path.relative_to(input_dir)
        except ValueError:
            relative_path = Path(pdf_path.name)
        
        output_path = output_dir / relative_path.parent / f"{pdf_path.stem}.md"
        
        # 检查是否应跳过
        if skip_existing and output_path.exists():
            return ConversionResult(
                pdf_path=pdf_path,
                output_path=output_path,
                success=True,
                error_message=None,
                processing_time=0.0
            )
        
        # 创建输出目录
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 临时设置环境变量（每个进程独立）
        import os
        os.environ['OUTPUT_DIR'] = str(output_path.parent)
        
        # 导入并执行转换
        from extract import MarkdownPDFExtractor
        import re
        
        # 执行转换
        extractor = MarkdownPDFExtractor(str(pdf_path))
        markdown_content, markdown_pages = extractor.extract()
        
        # 读取生成的 Markdown 文件并修复图片路径
        generated_file = output_path.parent / f"{pdf_path.stem}.md"
        if generated_file.exists():
            with open(generated_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 修复图片路径：将绝对路径改为相对路径（仅文件名）
            # 匹配 ![alt](path) 格式
            content = re.sub(
                r'!\[(.*?)\]\(.*?([^/\\]+\.png)\)',
                r'![\1](\2)',
                content
            )
            
            # 写回文件
            with open(generated_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 如果需要移动文件
            if generated_file != output_path:
                generated_file.rename(output_path)
        
        processing_time = time.time() - start_time
        
        return ConversionResult(
            pdf_path=pdf_path,
            output_path=output_path,
            success=True,
            error_message=None,
            processing_time=processing_time
        )
        
    except Exception as e:
        processing_time = time.time() - start_time
        
        return ConversionResult(
            pdf_path=pdf_path,
            output_path=None,
            success=False,
            error_message=str(e),
            processing_time=processing_time
        )


class BatchConverter:
    """批量转换器"""
    
    def __init__(self, config: ConversionConfig):
        """
        初始化批量转换器
        
        Args:
            config: 转换配置
        """
        self.config = config
        self.logger = self._setup_logger()
        self.error_handler = ErrorHandler(self.logger)
        self.progress_reporter = None
    
    def _setup_logger(self) -> logging.Logger:
        """设置日志记录器"""
        logger = logging.getLogger('batch_converter')
        logger.setLevel(logging.INFO)
        
        # 创建日志目录
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # 文件处理器
        log_file = log_dir / "batch_convert.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # 格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        
        return logger
    
    def discover_pdfs(self, input_dir: Path, recursive: bool = False) -> List[Path]:
        """
        发现所有待转换的 PDF 文件
        
        Args:
            input_dir: 输入目录
            recursive: 是否递归扫描子目录
            
        Returns:
            PDF 文件路径列表
        """
        pdf_files = []
        
        if recursive:
            # 递归扫描
            pdf_files = list(input_dir.rglob("*.pdf"))
            pdf_files.extend(list(input_dir.rglob("*.PDF")))
        else:
            # 仅扫描当前目录
            pdf_files = list(input_dir.glob("*.pdf"))
            pdf_files.extend(list(input_dir.glob("*.PDF")))
        
        # 去重并排序
        pdf_files = sorted(set(pdf_files))
        
        self.logger.info(f"发现 {len(pdf_files)} 个 PDF 文件")
        return pdf_files
    
    def _get_output_path(self, pdf_path: Path) -> Path:
        """
        计算输出文件路径（保持目录结构）
        
        Args:
            pdf_path: PDF 文件路径
            
        Returns:
            输出 Markdown 文件路径
        """
        # 计算相对路径
        try:
            relative_path = pdf_path.relative_to(self.config.input_dir)
        except ValueError:
            # 如果无法计算相对路径，使用文件名
            relative_path = Path(pdf_path.name)
        
        # 构建输出路径
        output_path = self.config.output_dir / relative_path.parent / f"{pdf_path.stem}.md"
        
        return output_path
    
    def _should_skip(self, pdf_path: Path) -> bool:
        """
        检查是否应跳过已存在的文件
        
        Args:
            pdf_path: PDF 文件路径
            
        Returns:
            是否应跳过
        """
        if not self.config.skip_existing:
            return False
        
        output_path = self._get_output_path(pdf_path)
        return output_path.exists()
    
    def convert_single(self, pdf_path: Path) -> ConversionResult:
        """
        转换单个 PDF 文件
        
        Args:
            pdf_path: PDF 文件路径
            
        Returns:
            ConversionResult: 转换结果
        """
        start_time = time.time()
        
        try:
            # 检查是否应跳过
            if self._should_skip(pdf_path):
                self.logger.info(f"跳过已存在的文件: {pdf_path}")
                return ConversionResult(
                    pdf_path=pdf_path,
                    output_path=self._get_output_path(pdf_path),
                    success=True,
                    error_message=None,
                    processing_time=0.0
                )
            
            # 导入现有的 MarkdownPDFExtractor
            from extract import MarkdownPDFExtractor
            
            # 创建输出目录
            output_path = self._get_output_path(pdf_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 临时修改配置以使用正确的输出目录
            original_output_dir = os.environ.get('OUTPUT_DIR')
            os.environ['OUTPUT_DIR'] = str(output_path.parent)
            
            try:
                # 执行转换
                extractor = MarkdownPDFExtractor(str(pdf_path))
                markdown_content, markdown_pages = extractor.extract()
                
                # 移动生成的文件到正确位置
                generated_file = output_path.parent / f"{pdf_path.stem}.md"
                if generated_file != output_path and generated_file.exists():
                    generated_file.rename(output_path)
                
            finally:
                # 恢复原始配置
                if original_output_dir:
                    os.environ['OUTPUT_DIR'] = original_output_dir
                elif 'OUTPUT_DIR' in os.environ:
                    del os.environ['OUTPUT_DIR']
            
            processing_time = time.time() - start_time
            
            self.logger.info(f"成功转换: {pdf_path} -> {output_path}")
            
            return ConversionResult(
                pdf_path=pdf_path,
                output_path=output_path,
                success=True,
                error_message=None,
                processing_time=processing_time
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            self.logger.error(f"转换失败: {pdf_path}, 错误: {e}")
            
            return ConversionResult(
                pdf_path=pdf_path,
                output_path=None,
                success=False,
                error_message=str(e),
                processing_time=processing_time
            )
    
    def convert_batch(self, pdf_files: List[Path]) -> ConversionReport:
        """
        批量转换 PDF 文件
        
        Args:
            pdf_files: PDF 文件路径列表
            
        Returns:
            ConversionReport: 转换报告
        """
        if not pdf_files:
            return ConversionReport(
                total_files=0,
                successful=0,
                failed=0,
                skipped=0,
                results=[],
                total_time=0.0
            )
        
        start_time = time.time()
        results = []
        
        # 初始化进度报告器（在主进程中）
        progress_reporter = ProgressReporter(len(pdf_files))
        
        try:
            # 使用进程池并行处理
            with ProcessPoolExecutor(max_workers=self.config.max_workers) as executor:
                # 提交所有任务 - 使用静态方法避免序列化整个对象
                future_to_pdf = {
                    executor.submit(
                        _convert_single_static,
                        pdf,
                        self.config.input_dir,
                        self.config.output_dir,
                        self.config.skip_existing
                    ): pdf 
                    for pdf in pdf_files
                }
                
                # 收集结果
                for future in as_completed(future_to_pdf):
                    pdf = future_to_pdf[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # 更新进度
                        status = "Skipped" if result.success and result.processing_time == 0.0 else \
                                "Success" if result.success else "Failed"
                        progress_reporter.update(
                            len(results),
                            pdf.name,
                            status
                        )
                        
                        # 如果失败，记录错误
                        if not result.success:
                            error_info = ConversionError(
                                pdf_path=pdf,
                                error_type="ConversionError",
                                error_message=result.error_message or "Unknown error",
                                traceback="",
                                timestamp=datetime.now()
                            )
                            self.error_handler.errors.append(error_info)
                            
                    except Exception as e:
                        self.logger.error(f"处理任务时出错: {pdf}, 错误: {e}")
                        result = ConversionResult(
                            pdf_path=pdf,
                            output_path=None,
                            success=False,
                            error_message=str(e),
                            processing_time=0.0
                        )
                        results.append(result)
                        progress_reporter.update(len(results), pdf.name, "Failed")
                        
                        # 记录错误
                        error_info = ConversionError(
                            pdf_path=pdf,
                            error_type=type(e).__name__,
                            error_message=str(e),
                            traceback=traceback.format_exc(),
                            timestamp=datetime.now()
                        )
                        self.error_handler.errors.append(error_info)
        
        finally:
            elapsed_time = time.time() - start_time
            progress_reporter.finish(elapsed_time)
        
        # 生成报告
        return self._generate_report(results, elapsed_time)
    
    def _generate_report(self, results: List[ConversionResult], elapsed_time: float) -> ConversionReport:
        """
        生成转换报告
        
        Args:
            results: 转换结果列表
            elapsed_time: 总耗时
            
        Returns:
            ConversionReport: 转换报告
        """
        successful = sum(1 for r in results if r.success and r.processing_time > 0)
        skipped = sum(1 for r in results if r.success and r.processing_time == 0)
        failed = sum(1 for r in results if not r.success)
        
        return ConversionReport(
            total_files=len(results),
            successful=successful,
            failed=failed,
            skipped=skipped,
            results=results,
            total_time=elapsed_time
        )
