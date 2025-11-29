# Implementation Plan

- [x] 1. 创建项目结构和基础模块
  - 创建 `batch/` 目录及 `__init__.py`
  - 创建 `tests/` 目录及 `__init__.py`
  - 更新 `requirements.txt` 添加测试依赖（pytest, hypothesis）
  - _Requirements: 7.1, 7.2_

- [x] 2. 实现数据模型
  - 在 `batch/models.py` 中实现 `PDFFileInfo` 数据类
  - 在 `batch/models.py` 中实现 `ConversionError` 数据类
  - 在 `batch/models.py` 中实现 `ConversionResult` 数据类
  - 在 `batch/models.py` 中实现 `ConversionReport` 数据类，包含 `save_to_file()` 和 `print_summary()` 方法
  - _Requirements: 1.4, 4.3, 6.4, 6.5_

- [ ]* 2.1 编写数据模型的单元测试
  - 测试 `ConversionReport` 的计数逻辑
  - 测试报告保存和打印功能
  - _Requirements: 1.4_

- [x] 3. 实现配置管理模块
  - 在 `batch/config_manager.py` 中实现 `ConversionConfig` 数据类
  - 实现 `from_yaml()` 类方法从 YAML 文件加载配置
  - 实现 `from_args()` 类方法从命令行参数创建配置
  - 实现配置验证逻辑（验证路径存在性、参数有效性等）
  - _Requirements: 2.5, 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ]* 3.1 编写配置管理的单元测试
  - 测试从 YAML 加载配置
  - 测试从命令行参数创建配置
  - 测试配置验证逻辑
  - _Requirements: 2.5, 5.5_

- [ ]* 3.2 编写配置验证的属性测试
  - **Property 7: 配置参数有效性**
  - **Validates: Requirements 2.5, 4.4**
  - 生成随机配置参数，验证系统正确识别无效配置
  - _Requirements: 2.5_

- [x] 4. 实现进度报告模块
  - 在 `batch/progress_reporter.py` 中实现 `ProgressReporter` 类
  - 实现 `__init__()` 方法初始化总文件数
  - 实现 `update()` 方法更新当前进度、文件名和状态
  - 实现 `finish()` 方法显示总结信息
  - 使用 `tqdm` 或类似库实现进度条显示
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ]* 4.1 编写进度报告的单元测试
  - 测试进度计算的正确性
  - 测试进度显示格式
  - _Requirements: 3.1, 3.2_

- [ ]* 4.2 编写进度报告的属性测试
  - **Property 6: 进度报告准确性**
  - **Validates: Requirements 3.1, 3.2**
  - 验证报告的当前进度数始终 <= 总文件数
  - _Requirements: 3.1, 3.2_

- [x] 5. 实现错误处理模块
  - 在 `batch/error_handler.py` 中实现 `ErrorHandler` 类
  - 实现 `__init__()` 方法初始化日志记录器和错误列表
  - 实现 `handle_conversion_error()` 方法处理单个文件转换错误
  - 实现 `save_error_report()` 方法保存错误报告到文件
  - 确保错误处理不会中断批量处理流程
  - _Requirements: 4.1, 4.2, 4.3_

- [ ]* 5.1 编写错误处理的单元测试
  - 测试错误信息记录
  - 测试错误报告生成
  - _Requirements: 4.2, 4.3_

- [ ]* 5.2 编写错误隔离的属性测试
  - **Property 3: 错误隔离**
  - **Validates: Requirements 4.1**
  - 在文件列表中混入会失败的文件，验证系统继续处理后续文件
  - _Requirements: 4.1_

- [x] 6. 实现批量转换器核心逻辑
  - 在 `batch/batch_converter.py` 中实现 `BatchConverter` 类
  - 实现 `__init__()` 方法，接受 `ConversionConfig` 并初始化各个组件
  - 实现 `discover_pdfs()` 方法扫描目录查找 PDF 文件（支持递归）
  - 实现 `_get_output_path()` 方法计算输出文件路径（保持目录结构）
  - 实现 `_should_skip()` 方法检查是否应跳过已存在的文件
  - _Requirements: 1.1, 1.5, 6.1, 6.3, 8.2, 8.3_

- [ ]* 6.1 编写文件发现的单元测试
  - 测试非递归文件发现
  - 测试递归文件发现
  - 测试空目录处理
  - _Requirements: 1.1, 1.5_

- [ ]* 6.2 编写路径处理的属性测试
  - **Property 2: 文件路径结构保持**
  - **Validates: Requirements 6.1**
  - 生成随机目录结构，验证输出路径的相对结构与输入一致
  - _Requirements: 6.1_

- [ ]* 6.3 编写文件命名的属性测试
  - **Property 4: 输出文件命名一致性**
  - **Validates: Requirements 6.3**
  - 验证输出文件名为输入文件名（不含扩展名）+ .md
  - _Requirements: 6.3_

- [ ]* 6.4 编写跳过逻辑的属性测试
  - **Property 5: 跳过已存在文件的幂等性**
  - **Validates: Requirements 8.3**
  - 验证启用跳过选项时，已存在文件不被修改
  - _Requirements: 8.3_

- [x] 7. 实现单文件转换逻辑
  - 在 `BatchConverter` 中实现 `convert_single()` 方法
  - 导入现有的 `MarkdownPDFExtractor` 类（从 `extract.py`）
  - 调用 `MarkdownPDFExtractor.extract()` 执行转换
  - 处理转换结果并返回 `ConversionResult`
  - 捕获并处理转换过程中的异常
  - _Requirements: 1.2, 1.3, 4.1_

- [ ]* 7.1 编写单文件转换的集成测试
  - 使用示例 PDF 文件测试转换
  - 验证输出 Markdown 文件的正确性
  - _Requirements: 1.3_

- [x] 8. 实现并行批量转换逻辑
  - 在 `BatchConverter` 中实现 `convert_batch()` 方法
  - 使用 `ProcessPoolExecutor` 实现并行处理
  - 集成 `ProgressReporter` 显示进度
  - 集成 `ErrorHandler` 处理错误
  - 生成并返回 `ConversionReport`
  - _Requirements: 1.2, 1.4, 8.1_

- [ ]* 8.1 编写批量转换完整性的属性测试
  - **Property 1: 批量转换完整性**
  - **Validates: Requirements 1.2, 1.4**
  - 验证成功 + 失败 + 跳过 = 总文件数
  - _Requirements: 1.2, 1.4_

- [ ]* 8.2 编写并行处理的集成测试
  - 测试多文件并行转换
  - 验证线程安全性
  - _Requirements: 8.1_

- [x] 9. 实现命令行主程序
  - 创建 `batch_convert.py` 主程序文件
  - 使用 `argparse` 实现命令行参数解析
  - 支持参数：`--input-dir`（必需）、`--output-dir`（可选）、`--recursive`、`--max-workers`、`--skip-existing`、`--no-ocr`、`--no-images`、`--config`、`--help`
  - 实现输入验证（目录存在性、是否包含 PDF 文件）
  - 调用 `BatchConverter` 执行批量转换
  - 显示转换摘要和错误报告
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 4.4, 4.5, 5.1, 5.2, 5.3, 5.4_

- [ ]* 9.1 编写命令行接口的单元测试
  - 测试参数解析
  - 测试输入验证
  - 测试帮助信息显示
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 10. 创建 Shell 包装脚本
  - 创建 `convert.sh` Shell 脚本
  - 检测并激活虚拟环境（如果存在）
  - 调用 `batch_convert.py` 并传递所有参数
  - 添加执行权限
  - _Requirements: 2.1, 2.2_

- [ ]* 10.1 测试 Shell 脚本
  - 在不同场景下测试脚本执行
  - 验证参数传递正确性
  - _Requirements: 2.1_

- [x] 11. 编写使用文档
  - 在项目根目录创建 `BATCH_CONVERT_README.md`
  - 说明批量转换功能的使用方法
  - 提供命令行参数说明和示例
  - 说明与现有 `extract.py` 的区别
  - 提供常见问题解答
  - _Requirements: 2.4_

- [x] 12. 最终检查点 - 确保所有测试通过
  - 运行所有单元测试
  - 运行所有属性测试
  - 运行所有集成测试
  - 使用真实 PDF 文件进行端到端测试
  - 验证错误处理和日志记录
  - 确认所有功能符合需求
