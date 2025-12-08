'use client';

import { ITreeItem, KBDetail, NodeListItem, WidgetInfo } from '@/assets/type';
import { useMediaQuery } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import {
  createContext,
  useContext,
  useEffect,
  useState,
  Dispatch,
  SetStateAction,
} from 'react';
import { GithubComChaitinPandaWikiProApiShareV1AuthInfoResp } from '@/request/pro/types';

interface StoreContextType {
  authInfo?: GithubComChaitinPandaWikiProApiShareV1AuthInfoResp;
  widget?: WidgetInfo;
  kbDetail?: KBDetail;
  catalogShow?: boolean;
  tree?: ITreeItem[];
  themeMode?: 'light' | 'dark';
  mobile?: boolean;
  nodeList?: NodeListItem[];
  setNodeList?: (list: NodeListItem[]) => void;
  setTree?: Dispatch<SetStateAction<ITreeItem[] | undefined>>;
  setCatalogShow?: (value: boolean) => void;
  catalogWidth?: number;
  setCatalogWidth?: (value: number) => void;
  qaModalOpen?: boolean;
  setQaModalOpen?: (value: boolean) => void;
}

export const StoreContext = createContext<StoreContextType | undefined>(
  undefined,
);

export const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) {
    throw new Error('useStore must be used within a StoreProvider');
  }
  return context;
};

export default function StoreProvider({
  children,
  ...props
}: StoreContextType & { children: React.ReactNode }) {
  const context = useContext(StoreContext) || {};
  const {
    widget = context.widget,
    kbDetail = context.kbDetail,
    themeMode = context.themeMode,
    nodeList: initialNodeList = context.nodeList || [],
    mobile = context.mobile,
    authInfo = context.authInfo,
    tree: initialTree = context.tree || [],
  } = props;

  const catalogSettings = kbDetail?.settings?.catalog_settings;

  const [catalogWidth, setCatalogWidth] = useState<number>(() => {
    return catalogSettings?.catalog_width || 260;
  });
  const [nodeList, setNodeList] = useState<NodeListItem[] | undefined>(
    initialNodeList,
  );
  const [tree, setTree] = useState<ITreeItem[] | undefined>(initialTree);

  // 根据 URL 参数初始化 qaModalOpen 状态，避免延迟打开
  const [qaModalOpen, setQaModalOpen] = useState(() => {
    // 只在客户端执行
    if (typeof window === 'undefined') return false;

    try {
      const urlParams = new URLSearchParams(window.location.search);
      const open = urlParams.get('open');

      // 默认打开问答弹窗
      let shouldOpen = true;

      // 如果 URL 中明确指定 open=false 或 open=0，则不打开
      if (open === 'false' || open === '0') {
        shouldOpen = false;
      }

      // 如果需要打开，提前保存 mode 和 answer 到 sessionStorage
      if (shouldOpen) {
        const mode = urlParams.get('mode');
        const answer = urlParams.get('answer');

        if (mode && ['chat', 'search', 'web-search'].includes(mode)) {
          sessionStorage.setItem('qa_modal_mode', mode);
        }
        if (answer) {
          sessionStorage.setItem('chat_search_query', answer);
        }
      }

      return shouldOpen;
    } catch (e) {
      return false;
    }
  });

  const [catalogShow, setCatalogShow] = useState(
    catalogSettings?.catalog_visible !== 2,
  );
  const [isMobile, setIsMobile] = useState(mobile);
  const theme = useTheme();
  const mediaQueryResult = useMediaQuery(theme.breakpoints.down('lg'), {
    noSsr: true,
  });

  useEffect(() => {
    if (kbDetail) setCatalogShow(catalogSettings?.catalog_visible !== 2);
  }, [kbDetail]);

  useEffect(() => {
    const savedWidth = window.localStorage.getItem('CATALOG_WIDTH');
    if (Number(savedWidth) > 0) {
      setCatalogWidth(Number(savedWidth));
    }
  }, []);

  useEffect(() => {
    setIsMobile(mediaQueryResult);
  }, [mediaQueryResult]);

  return (
    <StoreContext.Provider
      value={{
        widget,
        kbDetail,
        themeMode,
        nodeList,
        catalogShow,
        setCatalogShow,
        mobile: isMobile,
        authInfo,
        setNodeList,
        catalogWidth,
        tree,
        setTree,
        setCatalogWidth: value => {
          setCatalogWidth(value);
          window.localStorage.setItem('CATALOG_WIDTH', value.toString());
        },
        qaModalOpen,
        setQaModalOpen,
      }}
    >
      {children}
    </StoreContext.Provider>
  );
}
