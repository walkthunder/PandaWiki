# PDF 批量转 Markdown 工具

[English](README.md) | 简体中文

## 🚀 快速开始

### 一键转换

```bash
./convert.sh --input-dir ./你的PDF目录
```

就这么简单！

## 📖 功能特性

- ✅ **批量转换** - 一次处理多个 PDF 文件
- ✅ **递归扫描** - 自动扫描子目录
- ✅ **并行处理** - 多核加速，转换更快
- ✅ **实时进度** - 清晰的进度条显示
- ✅ **智能错误处理** - 单个文件失败不影响其他文件
- ✅ **保持结构** - 输出保持原有目录结构
- ✅ **增量转换** - 跳过已转换的文件
- ✅ **详细报告** - 自动生成转换报告

## 📦 安装

### 1. 安装 Python 依赖

```bash
cd pdf-to-markdown
pip install -r requirements.txt
```

### 2. 安装 Tesseract OCR

**macOS:**
```bash
brew install tesseract
```

**Ubuntu/Debian:**
```bash
sudo apt-get install tesseract-ocr
```

**Windows:**
从 [GitHub](https://github.com/UB-Mannheim/tesseract/wiki) 下载安装

## 💡 使用示例

### 基础用法

```bash
# 转换单个目录
./convert.sh --input-dir ./pdfs

# 递归扫描子目录
./convert.sh --input-dir ./pdfs --recursive

# 指定输出目录
./convert.sh --input-dir ./pdfs --output-dir ./markdown
```

### 高级用法

```bash
# 使用 8 个并发进程（加速转换）
./convert.sh --input-dir ./pdfs --max-workers 8

# 跳过已转换的文件（增量转换）
./convert.sh --input-dir ./pdfs --skip-existing

# 禁用 OCR（更快但可能丢失图像中的文字）
./convert.sh --input-dir ./pdfs --no-ocr

# 组合使用
./convert.sh \
  --input-dir ./pdfs \
  --output-dir ./markdown \
  --recursive \
  --max-workers 8 \
  --skip-existing
```

### 使用配置文件

创建配置文件 `my-config.yaml`:

```yaml
input_dir: ./pdfs
output_dir: ./markdown
recursive: true
max_workers: 8
skip_existing: true
```

运行：

```bash
./convert.sh --config my-config.yaml
```

## 📊 输出结果

转换完成后，你会得到：

```
outputs/
├── document1.md              # 转换后的 Markdown 文件
├── document2.md
├── subfolder/
│   └── document3.md
├── conversion_report.txt     # 转换摘要报告
└── error_report.txt          # 错误详情（如果有）
```

## 🎯 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--input-dir` | 输入目录（必需） | - |
| `--output-dir` | 输出目录 | `outputs` |
| `--recursive` | 递归扫描子目录 | `False` |
| `--max-workers` | 最大并发数 | `4` |
| `--skip-existing` | 跳过已存在的文件 | `False` |
| `--no-ocr` | 禁用 OCR | `False` |
| `--no-images` | 禁用图像提取 | `False` |
| `--config` | 配置文件路径 | - |

## 🔧 性能优化建议

### 并发数设置

- **4 核 CPU**: `--max-workers 3`
- **8 核 CPU**: `--max-workers 6`
- **16 核 CPU**: `--max-workers 12`

建议设置为 CPU 核心数的 75%。

### 大文件处理

对于大型 PDF（100+ 页），建议：

```bash
./convert.sh --input-dir ./pdfs --max-workers 2
```

### 快速转换

如果不需要 OCR：

```bash
./convert.sh --input-dir ./pdfs --no-ocr --max-workers 8
```

## 📚 文档

- [快速入门指南](QUICKSTART.md) - 5 分钟上手
- [完整文档](BATCH_CONVERT_README.md) - 详细使用说明
- [实现总结](IMPLEMENTATION_SUMMARY.md) - 技术细节

## ❓ 常见问题

### Q: 转换速度慢怎么办？

A: 增加并发数：
```bash
./convert.sh --input-dir ./pdfs --max-workers 8
```

### Q: 某些文件转换失败怎么办？

A: 查看错误报告：
```bash
cat outputs/error_report.txt
```

### Q: 如何只转换新增的 PDF？

A: 使用跳过选项：
```bash
./convert.sh --input-dir ./pdfs --skip-existing
```

### Q: 转换后的图像在哪里？

A: 图像保存在与 Markdown 文件相同的目录下。

## 🔍 验证安装

运行验证脚本检查安装是否正确：

```bash
python3 verify_installation.py
```

## 📝 日志

日志文件位置：`logs/batch_convert.log`

## 🆚 与单文件转换的区别

| 特性 | extract.py（单文件） | batch_convert.py（批量） |
|------|---------------------|------------------------|
| 处理方式 | 单个文件 | 批量处理 |
| 并行处理 | ❌ | ✅ |
| 进度显示 | ❌ | ✅ |
| 错误处理 | 失败即停止 | 继续处理其他文件 |
| 报告生成 | ❌ | ✅ |
| 目录结构 | 不保持 | 保持 |

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🎉 开始使用

```bash
# 1. 验证安装
python3 verify_installation.py

# 2. 查看快速入门
cat QUICKSTART.md

# 3. 开始转换
./convert.sh --input-dir ./你的PDF目录
```

祝你使用愉快！🎊
