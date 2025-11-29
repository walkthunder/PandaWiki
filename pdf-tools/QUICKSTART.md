# 快速入门指南

## 5 分钟上手批量 PDF 转 Markdown

### 1. 安装依赖

```bash
cd pdf-to-markdown
pip install -r requirements.txt
```

### 2. 准备 PDF 文件

将你的 PDF 文件放在一个目录中，例如：

```
my-pdfs/
├── document1.pdf
├── document2.pdf
└── reports/
    └── report.pdf
```

### 3. 运行转换

**最简单的方式**：

```bash
./convert.sh --input-dir my-pdfs
```

**递归扫描子目录**：

```bash
./convert.sh --input-dir my-pdfs --recursive
```

**指定输出目录**：

```bash
./convert.sh --input-dir my-pdfs --output-dir my-markdown
```

**加速转换（使用更多并发）**：

```bash
./convert.sh --input-dir my-pdfs --max-workers 8
```

### 4. 查看结果

转换完成后，你会看到：

```
outputs/
├── document1.md
├── document2.md
├── reports/
│   └── report.md
├── conversion_report.txt  # 转换摘要
└── error_report.txt       # 错误详情（如果有）
```

## 常用命令

### 基础转换

```bash
# 转换单个目录
./convert.sh --input-dir ./pdfs

# 转换并保持目录结构
./convert.sh --input-dir ./pdfs --recursive
```

### 性能优化

```bash
# 使用 8 个并发进程
./convert.sh --input-dir ./pdfs --max-workers 8

# 跳过已转换的文件（增量转换）
./convert.sh --input-dir ./pdfs --skip-existing
```

### 自定义选项

```bash
# 禁用 OCR（更快但可能丢失图像中的文字）
./convert.sh --input-dir ./pdfs --no-ocr

# 禁用图像提取（仅提取文本）
./convert.sh --input-dir ./pdfs --no-images
```

### 使用配置文件

```bash
# 创建配置文件 my-config.yaml
cat > my-config.yaml << EOF
input_dir: ./pdfs
output_dir: ./markdown
recursive: true
max_workers: 8
skip_existing: true
EOF

# 使用配置文件
./convert.sh --config my-config.yaml
```

## 故障排除

### 问题：脚本没有执行权限

```bash
chmod +x convert.sh
```

### 问题：找不到 Python

确保已安装 Python 3.8+：

```bash
python3 --version
```

### 问题：缺少依赖

```bash
pip install -r requirements.txt
```

### 问题：Tesseract OCR 未安装

```bash
# macOS
brew install tesseract

# Ubuntu/Debian
sudo apt-get install tesseract-ocr
```

## 下一步

- 查看 [BATCH_CONVERT_README.md](BATCH_CONVERT_README.md) 了解详细文档
- 查看 `conversion_report.txt` 了解转换结果
- 如有错误，查看 `error_report.txt` 了解详情

## 需要帮助？

- 查看完整文档：[BATCH_CONVERT_README.md](BATCH_CONVERT_README.md)
- 查看日志文件：`logs/batch_convert.log`
- 提交 Issue 或联系维护者
