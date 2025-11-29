# Requirements Document

## Introduction

本需求文档描述了在现有的 QaModal 组件中添加"联网搜索"功能的需求。该功能将作为第三个标签页与"智能问答"和"仅搜索文档"并列，通过嵌入 iframe 的方式集成外部搜索服务，为上海无线电监测站用户提供联网搜索能力。界面设计将融入政府机构的专业、严谨风格，确保符合政务系统的视觉规范和用户体验标准。

## Glossary

- **QaModal**: 问答模态框组件，包含智能问答和文档搜索功能的主要交互界面
- **Tab**: 标签页，用于在不同搜索模式之间切换的导航元素
- **WebSearchContent**: 联网搜索内容组件，负责渲染 iframe 并管理外部搜索服务
- **SearchMode**: 搜索模式类型，包括 'chat'（智能问答）、'search'（仅搜索文档）和 'web-search'（联网搜索）
- **iframe**: 内联框架，用于在当前页面中嵌入外部网页内容
- **StyledTab**: 样式化的标签组件，遵循现有设计系统的视觉规范
- **Mobile**: 移动端设备标识，用于响应式布局适配

## Requirements

### Requirement 1

**User Story:** 作为用户，我希望在问答模态框中看到"联网搜索"选项，以便我可以选择使用联网搜索功能

#### Acceptance Criteria

1. WHEN the QaModal opens THEN the system SHALL display three tabs: "智能问答", "仅搜索文档", and "联网搜索"
2. WHEN displaying tabs on desktop THEN the system SHALL show both icon and text label for each tab
3. WHEN displaying tabs on mobile THEN the system SHALL show only icons for each tab to save space
4. WHEN the user hovers over a tab THEN the system SHALL provide visual feedback with color transition
5. WHEN tabs are rendered THEN the system SHALL maintain consistent spacing and alignment with existing tabs

### Requirement 2

**User Story:** 作为用户，我希望点击"联网搜索"标签后能看到搜索界面，以便我可以进行联网搜索

#### Acceptance Criteria

1. WHEN the user clicks the "联网搜索" tab THEN the system SHALL switch the searchMode state to 'web-search'
2. WHEN searchMode is 'web-search' THEN the system SHALL hide the "智能问答" and "仅搜索文档" content areas
3. WHEN searchMode is 'web-search' THEN the system SHALL display the WebSearchContent component
4. WHEN switching between tabs THEN the system SHALL maintain smooth visual transitions
5. WHEN the modal closes THEN the system SHALL reset searchMode to 'chat' after animation completes

### Requirement 3

**User Story:** 作为用户，我希望联网搜索界面能够加载外部搜索服务，以便我可以使用完整的搜索功能

#### Acceptance Criteria

1. WHEN WebSearchContent renders THEN the system SHALL create an iframe element with the specified URL
2. WHEN the iframe loads THEN the system SHALL display the URL http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat
3. WHEN the iframe is displayed THEN the system SHALL fill the available content area with proper dimensions
4. WHEN the iframe loads THEN the system SHALL apply appropriate styling to match the modal design
5. WHEN the iframe fails to load THEN the system SHALL display an error message to the user

### Requirement 4

**User Story:** 作为用户，我希望联网搜索界面的样式与现有界面保持一致，以便获得统一的用户体验

#### Acceptance Criteria

1. WHEN WebSearchContent renders THEN the system SHALL apply the same padding and spacing as other content areas
2. WHEN the iframe is displayed THEN the system SHALL use rounded corners matching the modal design
3. WHEN the iframe is displayed THEN the system SHALL apply a subtle border consistent with the design system
4. WHEN the content area resizes THEN the system SHALL maintain the iframe's aspect ratio and responsiveness
5. WHEN displaying on mobile devices THEN the system SHALL adjust iframe dimensions for optimal viewing

### Requirement 5

**User Story:** 作为用户，我希望能够使用合适的图标来识别联网搜索功能，以便快速理解其用途

#### Acceptance Criteria

1. WHEN the "联网搜索" tab renders THEN the system SHALL display an appropriate icon representing web search
2. WHEN no custom icon is available THEN the system SHALL use a suitable Material-UI icon as fallback
3. WHEN the icon is displayed THEN the system SHALL maintain consistent size (16px) with other tab icons
4. WHEN the tab is selected THEN the system SHALL apply the same color scheme to the icon as the text
5. WHEN hovering over the tab THEN the system SHALL apply hover effects to both icon and text

### Requirement 6

**User Story:** 作为开发者，我希望新增的组件遵循现有代码结构，以便保持代码的可维护性

#### Acceptance Criteria

1. WHEN creating WebSearchContent THEN the system SHALL place it in the same directory as AiQaContent and SearchDocContent
2. WHEN implementing WebSearchContent THEN the system SHALL follow the same component structure and patterns
3. WHEN adding the new tab THEN the system SHALL extend the SearchMode type definition to include 'web-search'
4. WHEN modifying QaModal THEN the system SHALL maintain existing functionality for other tabs
5. WHEN implementing the feature THEN the system SHALL use TypeScript for type safety

### Requirement 7

**User Story:** 作为用户，我希望联网搜索功能能够正确处理加载状态，以便了解内容是否正在加载

#### Acceptance Criteria

1. WHEN the iframe starts loading THEN the system SHALL display a loading indicator
2. WHEN the iframe finishes loading THEN the system SHALL hide the loading indicator
3. WHEN the iframe takes longer than expected THEN the system SHALL continue showing the loading state
4. WHEN the iframe content is ready THEN the system SHALL ensure smooth transition from loading to loaded state
5. WHEN switching away from web-search tab THEN the system SHALL properly cleanup loading states

### Requirement 8

**User Story:** 作为用户，我希望联网搜索功能能够处理错误情况，以便在出现问题时得到明确的反馈

#### Acceptance Criteria

1. WHEN the iframe fails to load THEN the system SHALL display a user-friendly error message
2. WHEN a network error occurs THEN the system SHALL provide guidance on how to resolve the issue
3. WHEN the external service is unavailable THEN the system SHALL suggest alternative actions
4. WHEN an error is displayed THEN the system SHALL provide a retry button for the user
5. WHEN the user clicks retry THEN the system SHALL attempt to reload the iframe

### Requirement 9

**User Story:** 作为用户，我希望在使用联网搜索时能够方便地关闭模态框，以便返回主界面

#### Acceptance Criteria

1. WHEN the user is on the web-search tab THEN the system SHALL continue displaying the Esc button
2. WHEN the user clicks the Esc button THEN the system SHALL close the modal regardless of active tab
3. WHEN the user presses the Esc key THEN the system SHALL close the modal from any tab
4. WHEN the user clicks outside the modal THEN the system SHALL close the modal
5. WHEN the modal closes THEN the system SHALL properly cleanup iframe resources

### Requirement 10

**User Story:** 作为用户，我希望联网搜索功能在移动设备上也能正常工作，以便在不同设备上使用

#### Acceptance Criteria

1. WHEN accessing on mobile devices THEN the system SHALL display the web-search tab with icon only
2. WHEN the iframe renders on mobile THEN the system SHALL adjust dimensions for mobile viewport
3. WHEN interacting with iframe content on mobile THEN the system SHALL support touch gestures
4. WHEN the mobile keyboard appears THEN the system SHALL adjust modal layout appropriately
5. WHEN rotating the device THEN the system SHALL maintain proper iframe dimensions and layout

### Requirement 11

**User Story:** 作为用户，我希望联网搜索模态框能够尽可能大地显示内容，以便获得更好的浏览体验

#### Acceptance Criteria

1. WHEN the web-search tab is active THEN the system SHALL expand the modal to maximize available viewport space
2. WHEN the modal expands THEN the system SHALL maintain appropriate margins for visual breathing room
3. WHEN the modal is maximized THEN the system SHALL ensure the content area fills most of the viewport height
4. WHEN switching to web-search tab THEN the system SHALL smoothly transition the modal size
5. WHEN switching away from web-search tab THEN the system SHALL restore the original modal dimensions

### Requirement 12

**User Story:** 作为用户，我希望 iframe 能够完整显示外部网站的所有内容，包括导航栏和其他 UI 元素

#### Acceptance Criteria

1. WHEN the iframe loads external content THEN the system SHALL allow the iframe to display all embedded navigation elements
2. WHEN the external site has a header or navigation bar THEN the system SHALL ensure these elements are fully visible
3. WHEN the iframe content has scrollable areas THEN the system SHALL enable proper scroll behavior within the iframe
4. WHEN the external site uses fixed positioning THEN the system SHALL ensure these elements render correctly
5. WHEN the iframe content requires full viewport THEN the system SHALL provide sufficient height to avoid double scrollbars

### Requirement 13

**User Story:** 作为上海无线电监测站的用户，我希望界面体现政府机构的专业形象，以便获得符合政务系统标准的使用体验

#### Acceptance Criteria

1. WHEN displaying the modal THEN the system SHALL use professional color schemes appropriate for government applications
2. WHEN rendering text labels THEN the system SHALL use formal, professional terminology consistent with government standards
3. WHEN displaying the web-search tab THEN the system SHALL use the label "互联网检索" instead of casual terms
4. WHEN showing UI elements THEN the system SHALL maintain a clean, authoritative visual hierarchy
5. WHEN displaying icons THEN the system SHALL use professional iconography suitable for government interfaces

### Requirement 14

**User Story:** 作为系统管理员，我希望界面文案符合政务规范，以便满足上海无线电监测站的专业要求

#### Acceptance Criteria

1. WHEN displaying tab labels THEN the system SHALL use "智能问答" for AI chat functionality
2. WHEN displaying tab labels THEN the system SHALL use "文档检索" for document search functionality
3. WHEN displaying tab labels THEN the system SHALL use "互联网检索" for web search functionality
4. WHEN showing error messages THEN the system SHALL use professional, clear language appropriate for government users
5. WHEN displaying loading states THEN the system SHALL use formal status messages

### Requirement 15

**User Story:** 作为用户，我希望界面设计体现无线电监测的专业特色，以便增强系统的行业识别度

#### Acceptance Criteria

1. WHEN the modal renders THEN the system SHALL incorporate subtle design elements reflecting radio monitoring themes
2. WHEN displaying the interface THEN the system SHALL use color accents that align with technical/scientific aesthetics
3. WHEN showing the web-search tab icon THEN the system SHALL use an icon that represents network connectivity or signal
4. WHEN rendering the modal THEN the system SHALL maintain visual consistency with government portal design standards
5. WHEN displaying content THEN the system SHALL ensure readability and accessibility meet government requirements
