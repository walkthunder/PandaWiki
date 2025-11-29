# Design Document

## Overview

本设计文档描述了在 QaModal 组件中添加"互联网检索"功能的技术实现方案。该功能将通过新增第三个标签页的方式，与现有的"智能问答"和"文档检索"功能并列，为上海无线电监测站用户提供联网搜索能力。

**术语说明**: 根据需求文档 Requirement 14，系统将使用"文档检索"作为第二个标签的正式名称，以符合政务规范。这与现有代码中可能使用的"仅搜索文档"或其他变体保持一致。

设计遵循以下核心原则：
- **一致性**: 与现有 UI 组件保持视觉和交互一致性
- **专业性**: 体现政府机构的专业形象和规范用语（Requirements 13, 14）
- **可扩展性**: 采用模块化设计，便于未来功能扩展
- **响应式**: 支持桌面端和移动端的自适应布局，包括设备旋转适配（Requirement 10）
- **性能优化**: 合理管理 iframe 资源，避免内存泄漏
- **无障碍访问**: 确保符合政府系统的可访问性标准（Requirement 15.5）

## Architecture

### 组件层次结构

```
QaModal (主模态框组件)
├── StyledTabs (标签栏容器)
│   ├── StyledTab (智能问答)
│   ├── StyledTab (文档检索)
│   └── StyledTab (互联网检索) [新增]
├── AiQaContent (智能问答内容)
├── SearchDocContent (文档检索内容)
├── WebSearchContent (互联网检索内容) [新增]
└── Esc Button (关闭按钮)
```

### 状态管理

使用 React Hooks 管理组件状态：
- `searchMode`: 当前激活的搜索模式 ('chat' | 'search' | 'web-search')
- `iframeLoaded`: iframe 加载状态（Requirement 7）
- `iframeError`: iframe 错误状态（Requirement 8）
- `modalSize`: 模态框尺寸状态，用于动态调整以适应不同标签（Requirement 11）
- `isTransitioning`: 标签切换过渡状态，确保平滑的视觉过渡（Requirement 2.4）

### 数据流

```
用户点击"互联网检索"标签
    ↓
更新 searchMode 状态为 'web-search'
    ↓
隐藏其他内容组件，显示 WebSearchContent
    ↓
WebSearchContent 渲染 iframe
    ↓
监听 iframe 加载事件
    ↓
更新加载状态，显示内容
```

## Components and Interfaces

### 1. QaModal 组件更新

**修改内容**:
- 扩展 `searchMode` 类型定义，添加 'web-search' 选项
- 新增第三个 StyledTab 组件
- 添加 WebSearchContent 组件的条件渲染
- 更新模态框尺寸逻辑，支持动态调整

**TypeScript 类型定义**:

```typescript
type SearchMode = 'chat' | 'search' | 'web-search';

interface QaModalState {
  searchMode: SearchMode;
  modalMaximized: boolean;
}
```

**关键实现**:

```typescript
const [searchMode, setSearchMode] = useState<SearchMode>('chat');
const [isTransitioning, setIsTransitioning] = useState(false);

// 根据 searchMode 动态调整模态框尺寸 (Requirement 11)
// 为互联网检索提供最大化视口空间，同时保持适当边距
const modalMaxWidth = searchMode === 'web-search' ? '95vw' : 800;
const modalMaxHeight = searchMode === 'web-search' ? '95vh' : '100%';

// 处理标签切换，确保平滑过渡 (Requirement 2.4, 11.4)
const handleTabChange = (newMode: SearchMode) => {
  setIsTransitioning(true);
  setSearchMode(newMode);
  setTimeout(() => setIsTransitioning(false), 300); // 匹配 CSS 过渡时间
};

// 模态框关闭时重置状态 (Requirement 2.5)
const handleModalClose = () => {
  // 等待关闭动画完成后重置
  setTimeout(() => {
    setSearchMode('chat');
  }, 300);
};
```

**设计决策**: 
- 使用 95vw/95vh 而非 100vw/100vh 是为了保持视觉呼吸空间，符合政府系统的专业美学（Requirement 11.2）
- 过渡状态管理确保在内容切换时提供流畅的用户体验（Requirement 2.4）

### 2. WebSearchContent 组件 (新增)

**组件职责**:
- 渲染 iframe 元素（Requirement 3.1）
- 管理 iframe 加载状态（Requirement 7）
- 处理加载错误并提供用户友好的反馈（Requirement 8）
- 提供重试机制（Requirement 8.5）
- 确保 iframe 完整显示外部内容，包括导航栏（Requirement 12）
- 支持移动设备的触摸手势和设备旋转（Requirement 10）

**Props 接口**:

```typescript
interface WebSearchContentProps {
  url?: string; // iframe URL，默认为指定的搜索服务地址 (Requirement 3.2)
  onLoad?: () => void; // 加载完成回调
  onError?: (error: Error) => void; // 错误回调
  isMobile?: boolean; // 移动设备标识，用于响应式调整 (Requirement 10)
}
```

**设计决策**: 
- 添加 `isMobile` prop 以支持移动端特定的尺寸和交互优化（Requirement 10.2）
- iframe 将配置为允许完整显示外部站点的所有 UI 元素，避免双滚动条（Requirement 12.5）

**组件结构**:

```typescript
const WebSearchContent: React.FC<WebSearchContentProps> = ({
  url = 'http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat',
  onLoad,
  onError,
  isMobile = false,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const isMountedRef = useRef(true);

  // 处理 iframe 加载 (Requirement 7.2, 7.4)
  const handleLoad = () => {
    if (!isMountedRef.current) return;
    setLoading(false);
    setError(null);
    onLoad?.();
  };

  // 处理 iframe 错误 (Requirement 8.1, 14.4)
  const handleError = () => {
    if (!isMountedRef.current) return;
    setLoading(false);
    const errorMsg = '无法加载互联网检索服务，请稍后重试'; // 专业、正式的错误消息
    setError(errorMsg);
    onError?.(new Error(errorMsg));
  };

  // 重试加载 (Requirement 8.5)
  const handleRetry = () => {
    setLoading(true);
    setError(null);
    if (iframeRef.current) {
      iframeRef.current.src = url;
    }
  };

  // 清理函数，防止内存泄漏 (Requirement 9.5)
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      if (iframeRef.current) {
        iframeRef.current.src = 'about:blank';
      }
    };
  }, []);

  // 处理设备旋转和尺寸变化 (Requirement 10.5)
  useEffect(() => {
    const handleResize = () => {
      // iframe 会自动适应容器尺寸
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <Box 
      sx={{ 
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        // 移动端特定样式 (Requirement 10.2)
        ...(isMobile && {
          minHeight: '70vh',
        }),
      }}
    >
      {loading && <LoadingIndicator message="正在加载互联网检索服务..." />}
      {error && <ErrorDisplay message={error} onRetry={handleRetry} />}
      <iframe
        ref={iframeRef}
        src={url}
        title="互联网检索服务" // 可访问性 (Requirement 15.5)
        onLoad={handleLoad}
        onError={handleError}
        style={{
          width: '100%',
          height: '100%',
          border: 'none',
          borderRadius: '8px', // 匹配模态框设计 (Requirement 4.2)
          display: loading || error ? 'none' : 'block',
        }}
        // 确保 iframe 支持触摸手势 (Requirement 10.3)
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
      />
    </Box>
  );
};
```

**设计决策**:
- 使用 `isMountedRef` 防止组件卸载后的状态更新，避免内存泄漏
- iframe 设置 `border: 'none'` 以实现无缝集成（Requirement 4.3）
- 加载和错误状态时隐藏 iframe，提供更清晰的用户反馈（Requirement 7.4）
- 使用正式、专业的文案符合政务规范（Requirement 14.4, 14.5）

### 3. 图标选择

**方案**: 使用代表网络连接或信号的图标，体现无线电监测的专业特色（Requirement 15.3）

**图标选项**:
1. **Material-UI Language 图标**: 代表全球互联网连接
2. **Material-UI Public 图标**: 代表公共网络访问
3. **Material-UI Wifi 图标**: 体现无线电监测的信号主题
4. **自定义 SVG 图标**: 可定制的网络/信号图标

**推荐方案**: 使用 `Language` 图标作为主选，因为它清晰表达"互联网"概念，同时保持专业性（Requirement 5.1, 5.2, 13.5）

**实现**:

```typescript
import LanguageIcon from '@mui/icons-material/Language';
// 备选: import PublicIcon from '@mui/icons-material/Public';
// 备选: import WifiIcon from '@mui/icons-material/Wifi';

// 或者使用自定义图标以体现无线电监测特色
const IconHulianwang = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
    {/* 自定义 SVG 路径，可设计为信号波形或网络节点 */}
  </svg>
);
```

**标签渲染** (Requirement 1.2, 1.3, 5.3, 5.4, 5.5):

```typescript
<StyledTab
  label={
    <Stack direction='row' gap={0.5} alignItems='center'>
      <LanguageIcon sx={{ fontSize: 16 }} /> {/* 16px 保持一致性 */}
      {!mobile && <span>互联网检索</span>} {/* 桌面端显示文本 */}
    </Stack>
  }
  value='web-search'
  sx={{
    // 悬停效果应用于图标和文本 (Requirement 1.4, 5.5)
    '&:hover': {
      '& svg, & span': {
        transition: 'color 0.2s ease',
      },
    },
    // 选中状态的颜色方案 (Requirement 5.4)
    '&.Mui-selected': {
      '& svg': {
        color: 'inherit',
      },
    },
  }}
/>
```

**设计决策**:
- 16px 图标尺寸与现有标签保持一致（Requirement 5.3）
- 移动端仅显示图标以节省空间（Requirement 1.3）
- 悬停和选中状态的视觉反馈保持统一（Requirement 1.4, 5.4, 5.5）

## Data Models

### SearchMode 类型

```typescript
type SearchMode = 'chat' | 'search' | 'web-search';
```

### IframeState 接口

```typescript
interface IframeState {
  loading: boolean; // 加载状态 (Requirement 7)
  error: string | null; // 错误消息 (Requirement 8)
  loaded: boolean; // 加载完成标识
  errorType?: 'network' | 'unavailable' | 'timeout' | 'default'; // 错误类型，用于提供针对性指导 (Requirement 8.2, 8.3)
}
```

### ModalSizeConfig 接口

```typescript
interface ModalSizeConfig {
  maxWidth: string | number; // 最大宽度，web-search 模式下为 95vw (Requirement 11.1)
  maxHeight: string | number; // 最大高度，web-search 模式下为 95vh (Requirement 11.3)
  padding: number; // 内边距，保持视觉呼吸空间 (Requirement 11.2)
  transition: string; // CSS 过渡效果，确保平滑尺寸变化 (Requirement 11.4, 11.5)
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property Reflection

在分析了所有需求后，我们识别出以下可测试的属性。大多数属性是具体的示例测试（example tests），因为它们测试特定的 UI 状态和行为。我们将重点关注核心功能的测试，避免冗余。

**合并和简化的属性**:
- 多个关于标签文本的测试（1.1, 13.3, 14.1, 14.2, 14.3）可以合并为一个测试，验证所有三个标签使用正式政务用语
- 关于 iframe 尺寸的多个测试（3.3, 4.4, 4.5, 10.2, 12.2, 12.5）可以合并为验证 iframe 在不同场景（桌面端、移动端、设备旋转）下的正确尺寸
- 关于模态框尺寸的测试（11.1, 11.2, 11.3, 11.4, 11.5）可以合并为验证模态框动态尺寸调整和平滑过渡
- 关于标签交互的测试（1.4, 5.4, 5.5）可以合并为验证悬停和选中状态的视觉反馈
- 关于关闭机制的测试（9.1, 9.2, 9.3, 9.4）可以合并为验证多种关闭方式
- 关于加载状态的测试（7.1, 7.2, 7.3, 7.4, 7.5）可以合并为验证完整的加载生命周期

### Correctness Properties

#### Property 1: Tab rendering with formal government terminology
*For any* render of QaModal, the component should display exactly three tabs with the formal labels "智能问答", "文档检索", and "互联网检索" using professional government-appropriate styling
**Validates: Requirements 1.1, 1.5, 13.2, 13.3, 14.1, 14.2, 14.3**

#### Property 2: Responsive tab display adaptation
*For any* render of QaModal with mobile=true, the tabs should display only icons without text labels, and on desktop both icon and text should be visible
**Validates: Requirements 1.2, 1.3, 10.1**

#### Property 3: Tab interaction visual feedback
*For any* tab hover or selection event, the system should provide appropriate visual feedback with color transitions for both icon and text
**Validates: Requirements 1.4, 5.4, 5.5**

#### Property 4: Tab switching with smooth transitions
*For any* tab click event, the searchMode state should update to match the clicked tab's value with smooth visual transitions
**Validates: Requirements 2.1, 2.4**

#### Property 5: Content visibility based on mode
*For any* searchMode value, only the corresponding content component should be visible while others are hidden
**Validates: Requirements 2.2, 2.3**

#### Property 6: Modal reset on close
*For any* modal close event, after the animation completes, the searchMode should reset to 'chat'
**Validates: Requirements 2.5**

#### Property 7: WebSearchContent iframe rendering with correct URL
*For any* render of WebSearchContent, an iframe element should be created with src="http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat" and proper accessibility attributes
**Validates: Requirements 3.1, 3.2, 15.5**

#### Property 8: Iframe styling consistency
*For any* render of WebSearchContent, the iframe should apply styling consistent with the modal design including rounded corners, proper borders, and padding matching other content areas
**Validates: Requirements 3.4, 4.1, 4.2, 4.3**

#### Property 9: Iframe dimensions and responsiveness
*For any* render of WebSearchContent on desktop or mobile (including device rotation), the iframe should fill the available content area with appropriate dimensions and maintain responsiveness
**Validates: Requirements 3.3, 4.4, 4.5, 10.2, 10.5, 12.2, 12.5**

#### Property 10: Complete iframe content display
*For any* external content loaded in the iframe, all navigation elements, headers, and UI components should be fully visible with proper scroll behavior and no double scrollbars
**Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5**

#### Property 11: Loading state lifecycle management
*For any* WebSearchContent render, a loading indicator with formal status message should be visible from render until the iframe fires its load event, then smoothly transition to showing content
**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 14.5**

#### Property 12: Loading state cleanup on tab switch
*For any* switch away from web-search tab during loading, the loading state should be properly cleaned up
**Validates: Requirements 7.5**

#### Property 13: Error handling with professional messaging
*For any* iframe error event, the system should display a professional, government-appropriate error message with guidance and a retry button
**Validates: Requirements 3.5, 8.1, 8.2, 8.3, 8.4, 14.4**

#### Property 14: Retry functionality
*For any* click on the retry button, the iframe should reload by resetting its src attribute
**Validates: Requirements 8.5**

#### Property 15: Icon presence and consistency
*For any* render of the web-search tab, it should contain an icon representing network connectivity with fontSize of 16px, consistent with other tab icons
**Validates: Requirements 5.1, 5.2, 5.3, 15.3**

#### Property 16: Existing functionality preservation
*For any* interaction with the "智能问答" or "文档检索" tabs, they should continue to function as before without any regression
**Validates: Requirements 6.1, 6.2, 6.3, 6.4**

#### Property 17: Multiple modal close mechanisms
*For any* of the following actions (Esc button click, Esc key press, outside click), the modal should close properly from any tab including web-search
**Validates: Requirements 9.1, 9.2, 9.3, 9.4**

#### Property 18: Resource cleanup on close
*For any* modal close event, iframe resources should be properly cleaned up to prevent memory leaks
**Validates: Requirements 9.5**

#### Property 19: Dynamic modal sizing with smooth transitions
*For any* switch to web-search mode, the modal should smoothly expand to maxWidth=95vw and maxHeight=95vh with appropriate margins, and restore to original size when switching away
**Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

#### Property 20: Mobile device support
*For any* interaction on mobile devices, the system should support touch gestures within the iframe and adjust layout appropriately when the keyboard appears
**Validates: Requirements 10.3, 10.4**

#### Property 21: Professional government styling
*For any* render of the modal, it should use professional color schemes, maintain clean visual hierarchy, and incorporate subtle design elements reflecting radio monitoring themes
**Validates: Requirements 13.1, 13.4, 13.5, 15.1, 15.2, 15.4**

#### Property 22: Accessibility compliance
*For any* render of the modal with web-search content, it should meet government accessibility requirements including proper ARIA labels, keyboard navigation, and readability standards
**Validates: Requirements 15.5**

## Error Handling

### Iframe Loading Errors

**错误场景** (Requirement 8):
1. 网络连接失败
2. 外部服务不可用
3. 跨域限制
4. 超时

**处理策略** (Requirements 8.1, 8.2, 8.3, 8.4, 14.4):

```typescript
const handleIframeError = (error: Error) => {
  // 使用专业、正式的政务用语
  const errorMessages = {
    network: '网络连接失败，请检查您的网络设置后重试',
    unavailable: '互联网检索服务暂时不可用，请稍后重试或联系系统管理员',
    timeout: '服务加载超时，请检查网络连接状态后重试',
    default: '无法加载互联网检索服务，请稍后重试',
  };

  // 根据错误类型显示相应消息和指导
  const message = errorMessages[error.type] || errorMessages.default;
  
  setError({
    message,
    canRetry: true,
    timestamp: Date.now(),
    errorType: error.type || 'default',
  });
};
```

**设计决策**:
- 错误消息使用正式、专业的语言，符合政府系统标准（Requirement 14.4）
- 提供针对性的解决指导，帮助用户理解问题（Requirement 8.2, 8.3）
- 始终提供重试选项，提升用户体验（Requirement 8.4）

### 状态管理错误

**错误场景**:
1. searchMode 状态不一致
2. 组件卸载时的状态更新

**处理策略**:
- 使用 useEffect cleanup 函数清理副作用
- 使用 ref 跟踪组件挂载状态，避免在卸载后更新状态

```typescript
useEffect(() => {
  const isMounted = { current: true };
  
  return () => {
    isMounted.current = false;
  };
}, []);
```

### 资源泄漏防护

**场景**: iframe 创建的 blob URLs 和事件监听器

**处理策略**:

```typescript
useEffect(() => {
  const iframe = iframeRef.current;
  
  return () => {
    // 清理 iframe
    if (iframe) {
      iframe.src = 'about:blank';
    }
  };
}, []);
```

## Testing Strategy

### Unit Testing

使用 React Testing Library 进行单元测试，重点测试：

1. **组件渲染测试**
   - QaModal 渲染三个标签
   - WebSearchContent 渲染 iframe
   - 响应式布局（桌面端 vs 移动端）

2. **交互测试**
   - 标签切换功能
   - 模态框关闭机制
   - 重试按钮功能

3. **状态管理测试**
   - searchMode 状态更新
   - 加载状态管理
   - 错误状态管理

4. **边缘情况测试**
   - 快速切换标签
   - 在加载过程中关闭模态框
   - 多次点击重试按钮

**示例测试**:

```typescript
describe('QaModal with Web Search', () => {
  it('should render three tabs with correct labels', () => {
    render(<QaModal />);
    expect(screen.getByText('智能问答')).toBeInTheDocument();
    expect(screen.getByText('文档检索')).toBeInTheDocument();
    expect(screen.getByText('互联网检索')).toBeInTheDocument();
  });

  it('should switch to web-search mode when clicking the tab', () => {
    render(<QaModal />);
    const webSearchTab = screen.getByText('互联网检索');
    fireEvent.click(webSearchTab);
    expect(screen.getByTestId('web-search-content')).toBeInTheDocument();
  });

  it('should display loading indicator while iframe loads', () => {
    render(<WebSearchContent />);
    expect(screen.getByTestId('loading-indicator')).toBeInTheDocument();
  });
});
```

### Property-Based Testing

本项目将使用 **fast-check** 库进行属性测试。每个属性测试将运行至少 100 次迭代。

**测试库**: fast-check (JavaScript/TypeScript)

**配置**:

```typescript
import fc from 'fast-check';

// 配置测试运行次数
const testConfig = {
  numRuns: 100,
  verbose: true,
};
```

**属性测试示例**:

```typescript
describe('Property-Based Tests', () => {
  it('Property 1: Tab rendering completeness', () => {
    fc.assert(
      fc.property(
        fc.record({
          mobile: fc.boolean(),
          qaModalOpen: fc.boolean(),
        }),
        (props) => {
          const { container } = render(
            <QaModal {...props} />
          );
          
          if (props.qaModalOpen) {
            const tabs = container.querySelectorAll('[role="tab"]');
            expect(tabs).toHaveLength(3);
            
            const labels = Array.from(tabs).map(tab => tab.textContent);
            expect(labels).toContain('智能问答');
            expect(labels).toContain('文档检索');
            expect(labels).toContain('互联网检索');
          }
        }
      ),
      testConfig
    );
  });

  it('Property 4: Content visibility based on mode', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('chat', 'search', 'web-search'),
        (searchMode) => {
          const { container } = render(
            <QaModal initialSearchMode={searchMode} />
          );
          
          const chatContent = container.querySelector('[data-testid="ai-qa-content"]');
          const searchContent = container.querySelector('[data-testid="search-doc-content"]');
          const webSearchContent = container.querySelector('[data-testid="web-search-content"]');
          
          // 只有对应的内容应该可见
          if (searchMode === 'chat') {
            expect(chatContent).toBeVisible();
            expect(searchContent).not.toBeVisible();
            expect(webSearchContent).not.toBeVisible();
          } else if (searchMode === 'search') {
            expect(chatContent).not.toBeVisible();
            expect(searchContent).toBeVisible();
            expect(webSearchContent).not.toBeVisible();
          } else {
            expect(chatContent).not.toBeVisible();
            expect(searchContent).not.toBeVisible();
            expect(webSearchContent).toBeVisible();
          }
        }
      ),
      testConfig
    );
  });
});
```

### Integration Testing

集成测试重点验证：

1. **完整用户流程**
   - 打开模态框 → 切换到互联网检索 → iframe 加载 → 关闭模态框
   - 打开模态框 → 切换到互联网检索 → 加载失败 → 点击重试

2. **跨组件交互**
   - 标签切换时内容组件的正确显示/隐藏
   - 模态框尺寸随标签切换的动态调整

3. **状态持久化**
   - 关闭模态框后状态重置
   - 重新打开模态框时的初始状态

### End-to-End Testing

使用 Playwright 或 Cypress 进行 E2E 测试：

1. **真实 iframe 加载测试**
   - 验证 iframe 能够成功加载外部 URL
   - 验证 iframe 内容可交互

2. **响应式测试**
   - 在不同视口尺寸下测试布局
   - 测试移动端和桌面端的显示差异

3. **性能测试**
   - 测试 iframe 加载时间
   - 测试模态框打开/关闭的性能

## Implementation Plan

### Phase 1: 基础结构搭建

1. 更新 TypeScript 类型定义
   - 扩展 SearchMode 类型
   - 定义 WebSearchContent Props 接口

2. 创建 WebSearchContent 组件骨架
   - 基本组件结构
   - Props 接口实现

3. 更新 QaModal 组件
   - 添加第三个标签
   - 添加 WebSearchContent 条件渲染

### Phase 2: 核心功能实现

1. 实现 iframe 渲染逻辑
   - iframe 元素创建
   - URL 配置
   - 样式应用

2. 实现加载状态管理
   - 加载指示器
   - 加载完成处理

3. 实现错误处理
   - 错误检测
   - 错误消息显示
   - 重试机制

### Phase 3: 样式和交互优化

1. 实现动态模态框尺寸
   - 根据 searchMode 调整尺寸
   - 平滑过渡动画

2. 添加图标
   - 选择或创建合适的图标
   - 集成到标签中

3. 响应式适配
   - 移动端布局调整
   - iframe 尺寸适配

### Phase 4: 政府风格定制 (Requirements 13, 14, 15)

1. 更新文案（Requirement 14）
   - 标签文本使用正式政务用语："智能问答"、"文档检索"、"互联网检索"
   - 错误消息专业化，符合政府系统标准
   - 加载状态使用正式的状态消息

2. 样式调整（Requirement 13）
   - 配色方案调整，使用适合政府应用的专业色彩
   - 视觉层次优化，保持清晰、权威的界面
   - 确保对比度符合可访问性标准

3. 无线电监测主题元素（Requirement 15）
   - 图标选择：使用代表网络连接或信号的图标
   - 色彩点缀：融入技术/科学美学的色彩
   - 设计元素：体现无线电监测的专业特色

### Phase 5: 测试和优化

1. 编写单元测试
2. 编写属性测试
3. 性能优化
4. 资源清理验证

## Security Considerations

### iframe 安全

1. **沙箱属性**: 考虑添加适当的 sandbox 属性限制 iframe 权限
   ```typescript
   <iframe
     sandbox="allow-same-origin allow-scripts allow-forms"
     src={url}
   />
   ```

2. **CSP (Content Security Policy)**: 确保 CSP 策略允许加载指定的外部 URL

3. **HTTPS**: 建议外部服务使用 HTTPS 协议

### XSS 防护

1. 不从 URL 参数直接设置 iframe src
2. 验证和清理所有用户输入
3. 使用 React 的内置 XSS 防护

### 数据隐私

1. iframe 内容与主应用隔离
2. 不在 iframe 和主应用间传递敏感数据
3. 遵守政府数据安全规范

## Component File Structure

**文件组织** (Requirement 6):

```
src/
├── components/
│   ├── QaModal/
│   │   ├── index.tsx              # QaModal 主组件
│   │   ├── AiQaContent.tsx        # 智能问答内容（现有）
│   │   ├── SearchDocContent.tsx   # 文档检索内容（现有）
│   │   └── WebSearchContent.tsx   # 互联网检索内容（新增）
│   └── ...
└── types/
    └── search.ts                   # SearchMode 类型定义
```

**设计决策**:
- WebSearchContent 与其他内容组件放在同一目录，保持代码结构一致性（Requirement 6.1）
- 遵循现有的组件结构和命名模式（Requirement 6.2）
- 使用 TypeScript 确保类型安全（Requirement 6.5）

## Performance Optimization

### 懒加载

只在用户切换到 web-search 标签时才渲染 iframe（性能优化）：

```typescript
{searchMode === 'web-search' && <WebSearchContent />}
```

**设计决策**: 懒加载避免不必要的 iframe 创建，减少初始渲染开销

### 资源管理 (Requirement 9.5)

1. **iframe 卸载**: 组件卸载时清理 iframe，设置 src 为 'about:blank'
2. **事件监听器清理**: 使用 useEffect cleanup 函数
3. **内存泄漏防护**: 使用 ref 跟踪组件挂载状态，避免在卸载后更新状态

```typescript
useEffect(() => {
  const isMounted = { current: true };
  
  return () => {
    isMounted.current = false;
    if (iframeRef.current) {
      iframeRef.current.src = 'about:blank';
    }
  };
}, []);
```

### 加载优化 (Requirement 7)

1. **预连接**: 使用 `<link rel="preconnect">` 预连接外部域名
2. **加载提示**: 提供清晰的加载状态反馈，使用正式的状态消息
3. **超时处理**: 设置合理的加载超时时间（Requirement 7.3）

### 平滑过渡 (Requirements 2.4, 11.4)

使用 CSS transitions 确保标签切换和模态框尺寸变化的平滑视觉效果：

```typescript
const modalStyle = {
  maxWidth: searchMode === 'web-search' ? '95vw' : 800,
  maxHeight: searchMode === 'web-search' ? '95vh' : '100%',
  transition: 'max-width 0.3s ease, max-height 0.3s ease',
};
```

## Accessibility

### 键盘导航 (Requirement 15.5)

1. 标签可通过 Tab 键导航，支持完整的键盘访问
2. Esc 键关闭模态框（Requirement 9.3）
3. iframe 内容支持键盘操作
4. 焦点管理确保逻辑的导航顺序

### 屏幕阅读器 (Requirement 15.5)

1. 为标签添加 aria-label，使用正式的政务用语
2. 为 iframe 添加 title 属性，清晰描述其用途
3. 加载和错误状态使用 aria-live 区域提供实时反馈

```typescript
<iframe
  title="互联网检索服务"
  aria-label="互联网检索界面，用于访问外部搜索服务"
  src={url}
/>

<div role="status" aria-live="polite" aria-atomic="true">
  {loading && "正在加载互联网检索服务..."}
  {error && error.message}
</div>
```

### 对比度和可读性 (Requirements 13.4, 15.5)

1. 确保文本对比度符合 WCAG AA 标准，满足政府系统要求
2. 使用清晰的字体和适当的字号，保持专业形象
3. 提供足够的点击目标尺寸（至少 44x44px）
4. 保持清晰的视觉层次，体现政府机构的权威性

**设计决策**:
- 可访问性设计符合政府系统的标准要求（Requirement 15.5）
- 使用正式、专业的 ARIA 标签文案（Requirement 14）

## Deployment Considerations

### 环境配置

1. **开发环境**: 使用测试 URL
2. **生产环境**: 使用生产 URL
3. **配置管理**: 通过环境变量管理 iframe URL

```typescript
const WEBSEARCH_URL = process.env.NEXT_PUBLIC_WEBSEARCH_URL || 
  'http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat';
```

### 浏览器兼容性

1. 测试主流浏览器（Chrome, Firefox, Safari, Edge）
2. 确保 iframe 在所有目标浏览器中正常工作
3. 提供降级方案（如果 iframe 不支持）

### 监控和日志

1. 记录 iframe 加载失败事件
2. 监控加载时间
3. 收集用户反馈

## Future Enhancements

### 可能的扩展功能

1. **自定义搜索引擎**: 允许配置不同的搜索服务
2. **搜索历史**: 记录用户的搜索历史
3. **搜索结果集成**: 将外部搜索结果集成到主应用
4. **多标签支持**: 支持在 iframe 中打开多个标签
5. **离线模式**: 提供离线时的降级体验

### 技术债务

1. 考虑使用 Web Components 替代 iframe
2. 评估使用 Micro Frontends 架构
3. 优化首次加载性能

## Design Decisions Summary

### 关键设计决策及理由

1. **模态框尺寸策略** (Requirement 11)
   - 决策：web-search 模式使用 95vw/95vh 而非 100vw/100vh
   - 理由：保持适当的视觉边距，体现政府系统的专业美学，避免过于拥挤的界面

2. **术语标准化** (Requirements 13, 14)
   - 决策：使用"互联网检索"而非"联网搜索"或其他非正式用语
   - 理由：符合政务系统的正式用语规范，体现专业性和权威性

3. **懒加载策略**
   - 决策：仅在切换到 web-search 标签时才渲染 iframe
   - 理由：优化性能，避免不必要的资源消耗，提升初始加载速度

4. **错误处理方式** (Requirement 8)
   - 决策：提供详细的错误类型分类和针对性指导
   - 理由：帮助用户理解问题并采取正确的解决措施，提升用户体验

5. **图标选择** (Requirement 15.3)
   - 决策：推荐使用 Language 图标，可选 Wifi 图标体现无线电监测特色
   - 理由：清晰表达"互联网"概念，同时可通过自定义图标体现行业特色

6. **资源清理机制** (Requirement 9.5)
   - 决策：使用 useEffect cleanup 和 isMounted ref 模式
   - 理由：防止内存泄漏，确保组件卸载时正确清理 iframe 资源

7. **过渡动画** (Requirements 2.4, 11.4)
   - 决策：使用 300ms 的 CSS transition
   - 理由：提供流畅的视觉反馈，符合现代 UI 设计标准，提升用户体验

8. **可访问性优先** (Requirement 15.5)
   - 决策：完整的 ARIA 标签和键盘导航支持
   - 理由：满足政府系统的可访问性要求，确保所有用户都能使用该功能

## Conclusion

本设计文档提供了在 QaModal 组件中添加"互联网检索"功能的完整技术方案。设计全面覆盖了需求文档中的所有 15 个需求和 75 个验收标准，遵循现有代码结构和设计模式，确保与现有功能的一致性和兼容性。

通过模块化设计、完善的错误处理、全面的测试策略、以及对政府系统专业性和可访问性的重视，该功能将为上海无线电监测站用户提供可靠、专业、易用的联网搜索体验。设计特别注重：

- **政务规范**: 使用正式、专业的用语和视觉设计
- **用户体验**: 平滑的过渡动画、清晰的状态反馈、友好的错误处理
- **技术质量**: 类型安全、资源管理、性能优化
- **可维护性**: 遵循现有代码结构、模块化设计、完整的文档

所有设计决策都有明确的理由支撑，并与具体的需求条款对应，确保实现的完整性和可追溯性。
