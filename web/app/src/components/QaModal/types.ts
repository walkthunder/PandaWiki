import { ChunkResultItem } from '@/assets/type';

// 搜索模式类型 - 扩展以支持 web-search
export type SearchMode = 'chat' | 'search' | 'web-search';

export interface ConversationItem {
  q: string;
  a: string;
  score: number;
  update_time: string;
  message_id: string;
  source: 'history' | 'chat';
  chunk_result: ChunkResultItem[];
  thinking_content: string;
}

export interface UploadedImage {
  id: string;
  url: string;
  file: File;
}

export interface SSEMessageData {
  type: string;
  content: string;
  chunk_result: ChunkResultItem;
}

export interface ChatRequestData {
  message: string;
  nonce: string;
  conversation_id: string;
  app_type: number;
  captcha_token: string;
}

// WebSearchContent 组件的 Props 接口
export interface WebSearchContentProps {
  url?: string; // iframe URL，默认为指定的搜索服务地址
  onLoad?: () => void; // 加载完成回调
  onError?: (error: Error) => void; // 错误回调
  isMobile?: boolean; // 移动设备标识，用于响应式调整
}

// iframe 状态接口
export interface IframeState {
  loading: boolean; // 加载状态
  error: string | null; // 错误消息
  loaded: boolean; // 加载完成标识
  errorType?: 'network' | 'unavailable' | 'timeout' | 'default'; // 错误类型
}

// 模态框尺寸配置接口
export interface ModalSizeConfig {
  maxWidth: string | number; // 最大宽度，web-search 模式下为 95vw
  maxHeight: string | number; // 最大高度，web-search 模式下为 95vh
  padding: number; // 内边距，保持视觉呼吸空间
  transition: string; // CSS 过渡效果
}
