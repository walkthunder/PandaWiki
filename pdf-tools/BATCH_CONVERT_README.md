# 批量 PDF 转 Markdown 工具

## 概述

这是一个批量 PDF 转 Markdown 的工具，基于现有的 `extract.py` 进行扩展，提供高效的批量处理能力。

## 特性

- ✅ 批量转换多个 PDF 文件
- ✅ 支持递归扫描子目录
- ✅ 并行处理提升性能
- ✅ 实时进度显示
- ✅ 完善的错误处理
- ✅ 保持目录结构
- ✅ 跳过已转换文件
- ✅ 详细的转换报告

## 安装

1. 确保已安装所有依赖：

```bash
cd pdf-to-markdown
pip install -r requirements.txt
```

2. 安装 Tesseract OCR（用于图像文字识别）：

- macOS: `brew install tesseract`
- Ubuntu: `sudo apt-get install tesseract-ocr`
- Windows: 从 [GitHub](https://github.com/UB-Mannheim/tesseract/wiki) 下载安装

## 使用方法

### 基本用法

```bash
# 使用 Python 脚本
python batch_convert.py --input-dir ./pdfs

# 或使用 Shell 脚本（推荐）
./convert.sh --input-dir ./pdfs
```

### 常用选项

```bash
# 指定输出目录
./convert.sh --input-dir ./pdfs --output-dir ./markdown

# 递归扫描子目录
./convert.sh --input-dir ./pdfs --recursive

# 设置并发数（默认 4）
./convert.sh --input-dir ./pdfs --max-workers 8

# 跳过已存在的文件
./convert.sh --input-dir ./pdfs --skip-existing

# 禁用 OCR
./convert.sh --input-dir ./pdfs --no-ocr

# 禁用图像提取
./convert.sh --input-dir ./pdfs --no-images

# 使用配置文件
./convert.sh --config config.yaml --input-dir ./pdfs
```

### 完整示例

```bash
# 批量转换，递归扫描，8 个并发，跳过已存在文件
./convert.sh \
  --input-dir ./documents/pdfs \
  --output-dir ./documents/markdown \
  --recursive \
  --max-workers 8 \
  --skip-existing
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--input-dir` | 输入目录路径（必需） | - |
| `--output-dir` | 输出目录路径 | `outputs` |
| `--recursive` | 递归扫描子目录 | `False` |
| `--max-workers` | 最大并发转换数 | `4` |
| `--skip-existing` | 跳过已存在的输出文件 | `False` |
| `--no-ocr` | 禁用 OCR 功能 | `False` |
| `--no-images` | 禁用图像提取 | `False` |
| `--config` | 配置文件路径（YAML） | - |

## 配置文件

你可以使用 YAML 配置文件来设置默认选项：

```yaml
# config.yaml
input_dir: ./pdfs
output_dir: ./markdown
recursive: true
max_workers: 8
enable_ocr: true
enable_image_extraction: true
skip_existing: false
page_delimiter: "<||WXb23TXrUn3Rxz00yNNr89HV||>"
```

使用配置文件：

```bash
./convert.sh --config config.yaml
```

注意：命令行参数会覆盖配置文件中的设置。

## 输出结构

转换后的文件会保持原有的目录结构：

```
输入目录:
pdfs/
├── doc1.pdf
├── doc2.pdf
└── subfolder/
    └── doc3.pdf

输出目录:
markdown/
├── doc1.md
├── doc2.md
├── subfolder/
│   └── doc3.md
├── conversion_report.txt  # 转换报告
└── error_report.txt       # 错误报告（如果有错误）
```

## 转换报告

转换完成后，会在输出目录生成两个报告文件：

1. **conversion_report.txt**: 包含所有文件的转换结果
2. **error_report.txt**: 包含失败文件的详细错误信息（仅在有错误时生成）

## 与单文件转换的区别

| 特性 | extract.py（单文件） | batch_convert.py（批量） |
|------|---------------------|------------------------|
| 处理方式 | 单个文件 | 批量处理 |
| 并行处理 | 不支持 | 支持 |
| 进度显示 | 无 | 实时进度条 |
| 错误处理 | 单个失败即停止 | 继续处理其他文件 |
| 报告生成 | 无 | 详细报告 |
| 目录结构 | 不保持 | 保持原有结构 |

## 性能建议

1. **并发数设置**：
   - CPU 密集型任务，建议设置为 CPU 核心数的 75%
   - 例如 8 核 CPU，设置 `--max-workers 6`

2. **内存使用**：
   - 每个进程约占用 500MB-1GB 内存
   - 确保有足够的可用内存

3. **大文件处理**：
   - 对于大型 PDF（100+ 页），建议降低并发数
   - 使用 `--max-workers 2` 或 `--max-workers 4`

## 常见问题

### Q: 转换速度慢怎么办？

A: 可以尝试：
- 增加 `--max-workers` 参数
- 使用 `--no-ocr` 禁用 OCR（如果不需要）
- 使用 `--skip-existing` 跳过已转换的文件

### Q: 某些文件转换失败怎么办？

A: 
- 查看 `error_report.txt` 了解详细错误信息
- 失败的文件不会影响其他文件的转换
- 可以单独使用 `extract.py` 处理失败的文件

### Q: 如何只转换新增的 PDF？

A: 使用 `--skip-existing` 参数：

```bash
./convert.sh --input-dir ./pdfs --skip-existing
```

### Q: 转换后的图像在哪里？

A: 图像会保存在与 Markdown 文件相同的目录下，文件名格式为：
`{pdf_name}_image_{page}_{number}.png`

### Q: 可以自定义输出文件名吗？

A: 目前输出文件名与输入 PDF 文件名相同（扩展名改为 .md）。如需自定义，可以修改 `batch/batch_converter.py` 中的 `_get_output_path()` 方法。

## 日志文件

日志文件保存在 `logs/batch_convert.log`，包含详细的转换过程信息。

## 故障排除

### 问题：找不到 extract 模块

**解决方案**：确保在 `pdf-to-markdown` 目录下运行脚本。

### 问题：权限错误

**解决方案**：
```bash
chmod +x convert.sh
```

### 问题：虚拟环境未激活

**解决方案**：脚本会自动检测并激活虚拟环境（如果存在）。也可以手动激活：
```bash
source venv/bin/activate  # 或 source .venv/bin/activate
```

## 技术架构

```
batch_convert.py (主程序)
    ↓
BatchConverter (批量转换器)
    ↓
MarkdownPDFExtractor (核心转换逻辑 - 来自 extract.py)
```

所有批量处理代码都在 `batch/` 目录下，与现有的 `extract.py` 完全分离，不会影响原有功能。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

与主项目相同。
