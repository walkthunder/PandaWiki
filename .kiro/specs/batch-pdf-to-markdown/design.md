# Design Document

## Overview

本设计文档描述了批量 PDF 转 Markdown 工具的架构和实现细节。该工具基于现有的 pdf-to-markdown 代码进行优化和扩展，提供高效的批量处理能力、清晰的用户界面和健壮的错误处理机制。

**重要说明**：
- **现有代码**: `pdf-to-markdown/extract.py` 中的 `MarkdownPDFExtractor` 类包含核心 PDF 转换逻辑，这部分代码已经过验证且功能完善，应保持不变
- **新增代码**: 所有批量处理、并行执行、进度报告等功能将作为新模块添加，不修改现有的核心转换逻辑
- **代码组织**: 新代码将放在独立的目录中，与现有代码清晰分离

核心设计理念：
- 保持现有核心转换逻辑不变
- 通过包装和扩展的方式添加批量处理功能
- 模块化架构，便于维护和扩展
- 并行处理提升性能
- 完善的错误处理和日志记录
- 用户友好的命令行界面

## Architecture

系统采用分层架构设计：

```
┌─────────────────────────────────────┐
│     Command Line Interface          │
│  (batch_convert.py / convert.sh)    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Batch Processor Layer          │
│   - File Discovery                  │
│   - Parallel Processing             │
│   - Progress Tracking               │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    PDF Conversion Layer             │
│   - MarkdownPDFExtractor (优化版)   │
│   - Text/Image/Table Extraction     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Support Services               │
│   - Configuration Manager           │
│   - Logger                          │
│   - Progress Reporter               │
│   - Error Handler                   │
└─────────────────────────────────────┘
```

## Components and Interfaces

### 1. BatchConverter

批量转换的主控制器。

```python
class BatchConverter:
    def __init__(self, config: ConversionConfig):
        """初始化批量转换器"""
        
    def discover_pdfs(self, input_dir: Path, recursive: bool = False) -> List[Path]:
        """发现所有待转换的 PDF 文件"""
        
    def convert_batch(self, pdf_files: List[Path]) -> ConversionReport:
        """批量转换 PDF 文件"""
        
    def convert_single(self, pdf_path: Path) -> ConversionResult:
        """转换单个 PDF 文件"""
```

### 2. MarkdownPDFExtractor (现有代码 - 保持不变)

**位置**: `pdf-to-markdown/extract.py`

这是现有的核心转换类，包含所有 PDF 到 Markdown 的转换逻辑：
- 文本提取和格式化
- 图像提取和标注
- 表格提取
- OCR 处理
- 代码块检测
- 链接提取

**不需要修改此类**，批量处理器将直接使用它。

```python
# 现有代码 - 位于 pdf-to-markdown/extract.py
class MarkdownPDFExtractor(PDFExtractor):
    def __init__(self, pdf_path):
        # 现有实现
        
    def extract(self):
        # 现有实现
        
    # ... 其他现有方法
```

### 3. ConversionConfig

配置管理类。

```python
@dataclass
class ConversionConfig:
    input_dir: Path
    output_dir: Path
    recursive: bool = False
    max_workers: int = 4
    enable_ocr: bool = True
    enable_image_extraction: bool = True
    skip_existing: bool = False
    page_delimiter: str = "<||WXb23TXrUn3Rxz00yNNr89HV||>"
    
    @classmethod
    def from_yaml(cls, config_path: Path) -> 'ConversionConfig':
        """从 YAML 文件加载配置"""
        
    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'ConversionConfig':
        """从命令行参数创建配置"""
```

### 4. ProgressReporter

进度报告组件。

```python
class ProgressReporter:
    def __init__(self, total: int):
        """初始化进度报告器"""
        
    def update(self, current: int, filename: str, status: str):
        """更新进度"""
        
    def finish(self, elapsed_time: float):
        """完成并显示总结"""
```

### 5. ConversionReport

转换结果报告。

```python
@dataclass
class ConversionResult:
    pdf_path: Path
    output_path: Optional[Path]
    success: bool
    error_message: Optional[str]
    processing_time: float

@dataclass
class ConversionReport:
    total_files: int
    successful: int
    failed: int
    skipped: int
    results: List[ConversionResult]
    total_time: float
    
    def save_to_file(self, output_path: Path):
        """保存报告到文件"""
        
    def print_summary(self):
        """打印摘要到控制台"""
```

## Data Models

### PDF 文件信息

```python
@dataclass
class PDFFileInfo:
    path: Path
    relative_path: Path  # 相对于输入目录的路径
    size: int
    output_path: Path
```

### 错误信息

```python
@dataclass
class ConversionError:
    pdf_path: Path
    error_type: str
    error_message: str
    traceback: str
    timestamp: datetime
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: 批量转换完整性

*For any* 输入目录中的 PDF 文件列表，批量转换后，成功转换的文件数 + 失败的文件数 + 跳过的文件数应等于总文件数
**Validates: Requirements 1.2, 1.4**

### Property 2: 文件路径结构保持

*For any* 在输入目录子目录中的 PDF 文件，其输出 Markdown 文件的相对路径应与输入文件的相对路径相同
**Validates: Requirements 6.1**

### Property 3: 错误隔离

*For any* 批量转换过程，单个文件的转换失败不应导致整个批处理停止
**Validates: Requirements 4.1**

### Property 4: 输出文件命名一致性

*For any* PDF 文件，其输出的 Markdown 文件名应为原 PDF 文件名（不含扩展名）加上 .md 扩展名
**Validates: Requirements 6.3**

### Property 5: 跳过已存在文件的幂等性

*For any* 已转换的文件，当启用跳过选项时，重新运行批量转换应跳过该文件且不修改其内容
**Validates: Requirements 8.3**

### Property 6: 进度报告准确性

*For any* 批量转换过程，报告的当前进度数应始终小于或等于总文件数
**Validates: Requirements 3.1, 3.2**

### Property 7: 配置参数有效性

*For any* 用户提供的配置参数，系统应在执行转换前验证其有效性
**Validates: Requirements 2.5, 4.4**

## Error Handling

### 错误分类

1. **输入验证错误**
   - 输入目录不存在
   - 输入目录无读取权限
   - 输入目录中无 PDF 文件

2. **文件处理错误**
   - PDF 文件损坏或无法打开
   - PDF 文件受密码保护
   - 磁盘空间不足

3. **转换错误**
   - 图像提取失败
   - OCR 处理失败
   - 表格提取失败

4. **输出错误**
   - 输出目录无写入权限
   - 文件名冲突
   - 磁盘写入失败

### 错误处理策略

```python
class ErrorHandler:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.errors: List[ConversionError] = []
        
    def handle_conversion_error(self, pdf_path: Path, error: Exception) -> ConversionResult:
        """处理转换错误"""
        error_info = ConversionError(
            pdf_path=pdf_path,
            error_type=type(error).__name__,
            error_message=str(error),
            traceback=traceback.format_exc(),
            timestamp=datetime.now()
        )
        self.errors.append(error_info)
        self.logger.error(f"Failed to convert {pdf_path}: {error}")
        
        return ConversionResult(
            pdf_path=pdf_path,
            output_path=None,
            success=False,
            error_message=str(error),
            processing_time=0.0
        )
        
    def save_error_report(self, output_path: Path):
        """保存错误报告"""
        with open(output_path, 'w', encoding='utf-8') as f:
            for error in self.errors:
                f.write(f"File: {error.pdf_path}\n")
                f.write(f"Error Type: {error.error_type}\n")
                f.write(f"Message: {error.error_message}\n")
                f.write(f"Time: {error.timestamp}\n")
                f.write(f"Traceback:\n{error.traceback}\n")
                f.write("-" * 80 + "\n")
```

## Testing Strategy

### Unit Testing

使用 pytest 进行单元测试，覆盖以下组件：

1. **配置管理测试**
   - 测试从 YAML 加载配置
   - 测试从命令行参数创建配置
   - 测试配置验证逻辑

2. **文件发现测试**
   - 测试非递归文件发现
   - 测试递归文件发现
   - 测试空目录处理

3. **路径处理测试**
   - 测试相对路径计算
   - 测试输出路径生成
   - 测试文件名处理

4. **错误处理测试**
   - 测试各种错误场景
   - 测试错误报告生成

### Property-Based Testing

使用 Hypothesis 进行基于属性的测试：

1. **批量转换完整性测试**
   - 生成随机的文件列表
   - 验证转换结果计数的正确性

2. **路径结构保持测试**
   - 生成随机的目录结构
   - 验证输出路径的正确性

3. **配置参数验证测试**
   - 生成随机的配置参数
   - 验证参数验证逻辑

### Integration Testing

1. **端到端转换测试**
   - 使用示例 PDF 文件
   - 验证完整的转换流程
   - 检查输出文件的正确性

2. **并行处理测试**
   - 测试多文件并行转换
   - 验证线程安全性

3. **错误恢复测试**
   - 模拟各种错误场景
   - 验证系统的恢复能力

## Implementation Details

### 并行处理实现

使用 Python 的 `concurrent.futures.ProcessPoolExecutor` 实现并行处理：

```python
# 新增代码 - batch/batch_converter.py
def convert_batch(self, pdf_files: List[Path]) -> ConversionReport:
    start_time = time.time()
    results = []
    
    with ProcessPoolExecutor(max_workers=self.config.max_workers) as executor:
        future_to_pdf = {
            executor.submit(self.convert_single, pdf): pdf 
            for pdf in pdf_files
        }
        
        for future in as_completed(future_to_pdf):
            pdf = future_to_pdf[future]
            try:
                result = future.result()
                results.append(result)
                self.progress_reporter.update(
                    len(results), 
                    pdf.name, 
                    "Success" if result.success else "Failed"
                )
            except Exception as e:
                self.error_handler.handle_conversion_error(pdf, e)
    
    elapsed_time = time.time() - start_time
    return self._generate_report(results, elapsed_time)

def convert_single(self, pdf_path: Path) -> ConversionResult:
    """调用现有的 MarkdownPDFExtractor 进行转换"""
    try:
        # 使用现有的 extract.py 中的 MarkdownPDFExtractor
        from extract import MarkdownPDFExtractor
        
        extractor = MarkdownPDFExtractor(str(pdf_path))
        markdown_content, markdown_pages = extractor.extract()
        
        # 返回转换结果
        return ConversionResult(
            pdf_path=pdf_path,
            output_path=self._get_output_path(pdf_path),
            success=True,
            error_message=None,
            processing_time=time.time() - start_time
        )
    except Exception as e:
        return self.error_handler.handle_conversion_error(pdf_path, e)
```

### 内存优化

1. **流式处理**: 现有的 `MarkdownPDFExtractor` 已经实现了逐页处理，无需修改
2. **资源清理**: 在批量处理中，每个文件转换完成后立即释放 Python 对象
3. **进程隔离**: 使用 ProcessPoolExecutor 确保每个文件在独立进程中处理，避免内存泄漏
4. **图像优化**: 现有代码已经实现了图像压缩，无需修改

### 命令行脚本

创建两个脚本：

1. **batch_convert.py**: Python 主程序
2. **convert.sh**: Shell 包装脚本，提供更简单的接口

```bash
#!/bin/bash
# convert.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/batch_convert.py"

# 激活虚拟环境（如果存在）
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# 执行 Python 脚本
python "$PYTHON_SCRIPT" "$@"
```

## Performance Considerations

1. **并行度**: 默认使用 CPU 核心数的 75% 作为并行工作进程数
2. **内存限制**: 单个进程最大内存使用限制为 2GB
3. **批处理大小**: 对于大量文件，分批处理以避免内存溢出
4. **缓存策略**: 缓存图像标注模型以避免重复加载

## File Structure

```
pdf-to-markdown/                    # 现有目录
├── extract.py                      # [现有] 单文件转换脚本 - 不修改
├── config/
│   └── config.yaml                 # [现有] 默认配置 - 不修改
├── requirements.txt                # [现有] 依赖列表 - 可能需要更新
├── logs/                           # [现有] 日志目录
├── outputs/                        # [现有] 默认输出目录
│
├── batch_convert.py                # [新增] 批量转换主程序
├── convert.sh                      # [新增] Shell 包装脚本
├── batch/                          # [新增] 批量处理模块目录
│   ├── __init__.py                 # [新增]
│   ├── batch_converter.py          # [新增] BatchConverter 类
│   ├── config_manager.py           # [新增] ConversionConfig 类
│   ├── progress_reporter.py        # [新增] ProgressReporter 类
│   ├── error_handler.py            # [新增] ErrorHandler 类
│   └── models.py                   # [新增] 数据模型
│
└── tests/                          # [新增] 测试目录
    ├── __init__.py                 # [新增]
    ├── test_batch_converter.py     # [新增]
    ├── test_config.py              # [新增]
    ├── test_progress.py            # [新增]
    └── test_properties.py          # [新增] 基于属性的测试
```

**文件说明**：
- `[现有]`: 已存在的文件，不应修改（除非必要）
- `[新增]`: 需要创建的新文件
- 所有新增的批量处理代码都在 `batch/` 目录下，与现有代码清晰分离
