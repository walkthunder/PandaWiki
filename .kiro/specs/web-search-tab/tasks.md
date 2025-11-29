# Implementation Plan

## Overview
本实施计划将"互联网检索"功能分解为一系列增量式的编码任务。每个任务都建立在前一个任务的基础上，确保代码的连续性和可测试性。

## Task List

- [x] 1. 更新 TypeScript 类型定义和接口
  - 扩展 SearchMode 类型，添加 'web-search' 选项
  - 定义 WebSearchContentProps 接口
  - 定义 IframeState 和 ModalSizeConfig 接口
  - 更新 QaModal 组件的类型定义
  - _Requirements: 6.3, 6.5_

- [x] 2. 创建 WebSearchContent 组件基础结构
  - 在与 AiQaContent 和 SearchDocContent 相同的目录创建 WebSearchContent.tsx
  - 实现基本的组件框架和 Props 接口
  - 添加组件导出
  - _Requirements: 6.1, 6.2_

- [x] 3. 实现 WebSearchContent 的 iframe 渲染逻辑
  - 创建 iframe 元素，设置正确的 URL
  - 实现 iframe ref 管理
  - 应用基础样式（无边框、圆角、填充容器）
  - 添加可访问性属性（title, aria-label）
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 4.2, 15.5_

- [x] 4. 实现加载状态管理
  - 添加 loading 状态
  - 创建加载指示器组件，使用正式的状态消息
  - 实现 iframe onLoad 事件处理
  - 实现加载到显示内容的平滑过渡
  - _Requirements: 7.1, 7.2, 7.4, 14.5_

- [x] 5. 实现错误处理机制
  - 添加 error 状态和 errorType 分类
  - 实现 iframe onError 事件处理
  - 创建错误显示组件，使用专业的政务用语
  - 实现重试按钮和重试逻辑
  - 提供针对不同错误类型的指导信息
  - _Requirements: 3.5, 8.1, 8.2, 8.3, 8.4, 8.5, 14.4_

- [x] 6. 实现资源清理和内存管理
  - 添加 isMountedRef 防止卸载后状态更新
  - 实现 useEffect cleanup 函数
  - 在组件卸载时清理 iframe（设置 src 为 'about:blank'）
  - 实现标签切换时的加载状态清理
  - _Requirements: 7.5, 9.5_

- [x] 7. 实现移动端响应式支持
  - 添加 isMobile prop
  - 实现移动端特定的样式和尺寸调整
  - 添加设备旋转的 resize 事件监听
  - 配置 iframe 的 allow 属性以支持触摸手势
  - _Requirements: 4.5, 10.2, 10.3, 10.5_

- [x] 8. 在 QaModal 中添加第三个标签
  - 更新 searchMode 状态类型
  - 添加新的 StyledTab 组件，使用"互联网检索"标签文本
  - 选择并集成合适的图标（Language/Public/Wifi）
  - 实现桌面端显示图标+文本，移动端仅显示图标
  - 应用悬停和选中状态的视觉反馈样式
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 5.1, 5.2, 5.3, 5.4, 5.5, 13.3, 14.3_

- [x] 9. 实现标签切换逻辑和平滑过渡
  - 添加 isTransitioning 状态
  - 实现 handleTabChange 函数，包含过渡状态管理
  - 更新标签点击事件处理，支持 'web-search' 模式
  - 添加 CSS transition 实现平滑的视觉过渡
  - _Requirements: 2.1, 2.4_

- [x] 10. 实现内容组件的条件渲染
  - 根据 searchMode 显示/隐藏对应的内容组件
  - 实现 WebSearchContent 的懒加载（仅在 searchMode === 'web-search' 时渲染）
  - 确保其他标签的内容组件正常工作
  - _Requirements: 2.2, 2.3, 6.4_

- [x] 11. 实现动态模态框尺寸调整
  - 根据 searchMode 动态设置 modalMaxWidth 和 modalMaxHeight
  - web-search 模式：95vw x 95vh
  - 其他模式：恢复原始尺寸（800 x 100%）
  - 添加 CSS transition 实现平滑的尺寸变化
  - 确保保持适当的边距
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [x] 12. 实现模态框关闭时的状态重置
  - 更新 handleModalClose 函数
  - 在关闭动画完成后重置 searchMode 为 'chat'
  - 确保 iframe 资源被正确清理
  - _Requirements: 2.5, 9.5_

- [x] 13. 验证所有关闭机制正常工作
  - 测试 Esc 按钮点击关闭
  - 测试 Esc 键盘按键关闭
  - 测试点击模态框外部关闭
  - 确保从 web-search 标签也能正常关闭
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [x] 14. 应用政府风格的专业样式
  - 更新所有标签文本为正式政务用语："智能问答"、"文档检索"、"互联网检索"
  - 应用专业的配色方案
  - 优化视觉层次，保持清晰、权威的界面
  - 确保文本对比度符合 WCAG AA 标准
  - _Requirements: 13.1, 13.2, 13.4, 14.1, 14.2, 14.3, 15.4, 15.5_

- [x] 15. 融入无线电监测主题元素
  - 根据需求选择最终图标（建议 Language 或 Wifi）
  - 应用技术/科学美学的色彩点缀
  - 添加体现无线电监测专业特色的设计元素
  - _Requirements: 15.1, 15.2, 15.3_

- [x] 16. 完善可访问性支持
  - 为所有标签添加 aria-label
  - 为 iframe 添加完整的 title 和 aria-label
  - 实现加载和错误状态的 aria-live 区域
  - 验证键盘导航（Tab 键、Esc 键）
  - 确保焦点管理的逻辑顺序
  - _Requirements: 15.5_

- [ ]* 17. 编写单元测试
  - [ ]* 17.1 测试 QaModal 渲染三个标签
    - 验证标签文本正确："智能问答"、"文档检索"、"互联网检索"
    - 验证图标存在且尺寸为 16px
    - _Requirements: 1.1, 5.3, 14.1, 14.2, 14.3_

  - [ ]* 17.2 测试响应式标签显示
    - 桌面端：图标+文本
    - 移动端：仅图标
    - _Requirements: 1.2, 1.3_

  - [ ]* 17.3 测试标签切换功能
    - 点击标签更新 searchMode
    - 显示对应的内容组件
    - 隐藏其他内容组件
    - _Requirements: 2.1, 2.2, 2.3_

  - [ ]* 17.4 测试 WebSearchContent iframe 渲染
    - 验证 iframe 元素创建
    - 验证 src URL 正确
    - 验证可访问性属性
    - _Requirements: 3.1, 3.2, 15.5_

  - [ ]* 17.5 测试加载状态管理
    - 初始渲染显示加载指示器
    - onLoad 后隐藏加载指示器
    - 显示 iframe 内容
    - _Requirements: 7.1, 7.2, 7.4_

  - [ ]* 17.6 测试错误处理
    - onError 显示错误消息
    - 显示重试按钮
    - 点击重试重新加载 iframe
    - _Requirements: 8.1, 8.4, 8.5_

  - [ ]* 17.7 测试模态框关闭和状态重置
    - 关闭后 searchMode 重置为 'chat'
    - 验证多种关闭方式（Esc 按钮、Esc 键、外部点击）
    - _Requirements: 2.5, 9.2, 9.3, 9.4_

  - [ ]* 17.8 测试资源清理
    - 组件卸载时 iframe src 设置为 'about:blank'
    - 验证无内存泄漏
    - _Requirements: 9.5_

  - [ ]* 17.9 测试动态模态框尺寸
    - web-search 模式：95vw x 95vh
    - 其他模式：原始尺寸
    - _Requirements: 11.1, 11.3, 11.5_

  - [ ]* 17.10 测试现有功能不受影响
    - "智能问答"标签功能正常
    - "文档检索"标签功能正常
    - _Requirements: 6.4_

- [ ]* 18. 编写属性测试
  - [ ]* 18.1 Property 1: Tab rendering with formal government terminology
    - **Property 1: 标签渲染使用正式政务用语**
    - **Validates: Requirements 1.1, 1.5, 13.2, 13.3, 14.1, 14.2, 14.3**

  - [ ]* 18.2 Property 4: Tab switching with smooth transitions
    - **Property 4: 标签切换具有平滑过渡**
    - **Validates: Requirements 2.1, 2.4**

  - [ ]* 18.3 Property 5: Content visibility based on mode
    - **Property 5: 基于模式的内容可见性**
    - **Validates: Requirements 2.2, 2.3**

  - [ ]* 18.4 Property 9: Iframe dimensions and responsiveness
    - **Property 9: iframe 尺寸和响应式**
    - **Validates: Requirements 3.3, 4.4, 4.5, 10.2, 10.5, 12.2, 12.5**

  - [ ]* 18.5 Property 11: Loading state lifecycle management
    - **Property 11: 加载状态生命周期管理**
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 14.5**

  - [ ]* 18.6 Property 13: Error handling with professional messaging
    - **Property 13: 专业错误处理消息**
    - **Validates: Requirements 3.5, 8.1, 8.2, 8.3, 8.4, 14.4**

  - [ ]* 18.7 Property 19: Dynamic modal sizing with smooth transitions
    - **Property 19: 动态模态框尺寸与平滑过渡**
    - **Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

- [x] 19. Checkpoint - 确保所有测试通过
  - 运行所有单元测试和属性测试
  - 修复任何失败的测试
  - 确保代码质量和功能完整性
  - 如有问题，请向用户寻求指导

- [ ]* 20. 集成测试和端到端测试
  - [ ]* 20.1 完整用户流程测试
    - 打开模态框 → 切换到互联网检索 → iframe 加载 → 关闭模态框
    - 打开模态框 → 切换到互联网检索 → 加载失败 → 点击重试

  - [ ]* 20.2 跨组件交互测试
    - 标签切换时内容组件的正确显示/隐藏
    - 模态框尺寸随标签切换的动态调整

  - [ ]* 20.3 移动端测试
    - 不同视口尺寸下的布局
    - 设备旋转适配
    - 触摸手势支持

  - [ ]* 20.4 性能测试
    - iframe 加载时间
    - 模态框打开/关闭性能
    - 内存使用情况

- [x] 21. 最终验收和文档
  - 验证所有 15 个需求和 75 个验收标准都已满足
  - 更新组件文档和使用说明
  - 准备演示和用户培训材料
  - _Requirements: All_
