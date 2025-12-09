# Landing Page - 无线一点通

这是从 `/web/app/public/preview-index.html` 转换而来的 React 落地页组件，完全保持了原始设计的所有功能和样式。

## 功能特性

- 🎨 完全复刻蓝湖设计稿的 UI 设计
- 🔍 问题输入框（支持回车键提交）
- 🤖 AI智能问答按钮
- 🌐 互联网检索按钮
- 🏷️ 快速问题标签（可点击）
- 📱 响应式设计
- 🖼️ 使用原始图片资源

## 访问路径

开发环境访问：`http://localhost:3000/landing`

## 组件结构

```
landing/
├── index.tsx          # 主组件
├── index.module.css   # 样式文件（完全匹配 preview-index.html）
└── README.md         # 说明文档
```

## 功能说明

### 1. 顶部导航栏

- Logo 图片
- "问问AI吧" 搜索框（点击跳转到 `/home?open=true&mode=chat`）
- "智能问答" 按钮（点击跳转到 `/home?open=true&mode=chat`）

### 2. Hero 区域

- 标题："无线一点通"
- 描述文字

### 3. 主交互区域

- 快速问题标签："民用无人航天器无线电相关要求"（点击直接提问）
- 问题输入框（默认值："民用无人航天器无线电相关要求"）
- "AI智能问答" 按钮（跳转到 `/home?open=true&answer={问题}&mode=chat`）
- "互联网检索" 按钮（跳转到 `/home?open=true&answer={问题}&mode=web-search`）

### 4. 页脚

- 版权信息
- 技术支持标识

## 路由参数说明

组件使用以下 URL 参数与主应用交互：

- `open=true`: 打开问答模态框
- `answer={问题}`: 预填充的问题内容
- `mode=chat`: AI智能问答模式
- `mode=web-search`: 互联网检索模式

## 图片资源

所有图片资源位于 `/web/app/public/img/` 目录：

- `SketchPng4bd058e493ad33e266b577550a3a7f02786c07cfa7ba304aaab0e8f606b23707.png` - Logo
- `SketchPng130af4e6afeb35309844a32c09801e290c073d5baec6dcb33677fb44adf7d0c9.png` - 搜索图标
- `a2daabc00bb94d34aeedc20b96c9f4dd_mergeImage.png` - Hero 背景
- `fb69af71505d4bd4ba1c04fc07d4f8c7_mergeImage.png` - 主区域背景
- 其他装饰性图片

## 样式说明

样式完全复刻自 `preview-index.html` 和 `index.css`，包括：

- 精确的尺寸和间距
- 原始的颜色方案
- 相同的字体设置
- 一致的布局结构

## 使用方式

### 在路由中使用（已配置）

访问 `/landing` 路径即可查看页面。

### 在其他页面中使用

```tsx
import Landing from '@/views/landing';

export default function MyPage() {
  return <Landing />;
}
```

## 交互逻辑

1. **输入问题并按回车**：触发 AI 智能问答
2. **点击"AI智能问答"按钮**：使用输入框中的问题进行 AI 问答
3. **点击"互联网检索"按钮**：使用输入框中的问题进行网络检索
4. **点击快速问题标签**：直接使用预设问题进行 AI 问答
5. **点击顶部"问问AI吧"或"智能问答"**：打开问答界面

## 技术栈

- React 18
- TypeScript
- Next.js App Router
- CSS Modules
- Next.js Navigation (useRouter)

## 注意事项

- 组件使用 `'use client'` 指令，因为包含客户端交互
- 图片使用 `<img>` 标签而非 Next.js `<Image>` 组件，以保持与原始 HTML 完全一致
- 所有样式类名和结构都与原始设计保持一致
