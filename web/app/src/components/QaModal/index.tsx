'use client';
import React, { useState, useEffect, useRef, useMemo } from 'react';
import { IconZhinengwenda, IconJinsousuo } from '@panda-wiki/icons';
import { useSearchParams } from 'next/navigation';
import {
  Box,
  Button,
  Typography,
  Modal,
  Stack,
  lighten,
  alpha,
  styled,
  Tabs,
  Tab,
} from '@mui/material';
import LanguageIcon from '@mui/icons-material/Language';
import AiQaContent from './AiQaContent';
import SearchDocContent from './SearchDocContent';
import WebSearchContent from './WebSearchContent';
import { useStore } from '@/provider';
import { SearchMode } from './types';

interface SearchSuggestion {
  id: string;
  title: string;
  description?: string;
  type?: 'recent' | 'suggestion' | 'trending';
}

interface QaModalProps {
  placeholder?: string;
  initialValue?: string;
  onSearch?: (value?: string, type?: 'search' | 'chat') => void;
  onSearchSuggestions?: (query: string) => Promise<SearchSuggestion[]>;
  defaultSuggestions?: SearchSuggestion[];
}

const StyledTabs = styled(Tabs)(({ theme }) => ({
  minHeight: 'auto',
  position: 'relative',
  borderRadius: '10px',
  padding: theme.spacing(0.5),
  border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
  '& .MuiTabs-indicator': {
    height: '100%',
    borderRadius: '8px',
    backgroundColor: theme.palette.primary.main,
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    zIndex: 0,
  },
  '& .MuiTabs-flexContainer': {
    gap: theme.spacing(0.5),
    position: 'relative',
    zIndex: 1,
  },
}));

// 样式化的 Tab 组件 - 白色背景，圆角，深灰色文字
const StyledTab = styled(Tab)(({ theme }) => ({
  minHeight: 'auto',
  padding: theme.spacing(0.75, 2),
  borderRadius: '6px',
  backgroundColor: 'transparent',
  fontSize: 12,
  fontWeight: 400,
  textTransform: 'none',
  transition: 'color 0.3s ease-in-out',
  position: 'relative',
  zIndex: 1,
  lineHeight: 1,
  '&:hover': {
    color: theme.palette.text.primary,
  },
  '&.Mui-selected': {
    color: theme.palette.primary.contrastText,
    fontWeight: 500,
  },
}));

const QaModal: React.FC<QaModalProps> = () => {
  const { qaModalOpen, setQaModalOpen, kbDetail, mobile } = useStore();
  const [searchMode, setSearchMode] = useState<SearchMode>('chat');
  const [isTransitioning, setIsTransitioning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const aiQaInputRef = useRef<HTMLInputElement>(null);
  const searchParams = useSearchParams();
  const onClose = () => {
    setQaModalOpen?.(false);
  };

  // 处理标签切换，确保平滑过渡
  const handleTabChange = (newMode: SearchMode) => {
    setIsTransitioning(true);
    setSearchMode(newMode);
    setTimeout(() => setIsTransitioning(false), 300);
  };

  // 弹窗铺满整个屏幕
  const modalWidth = '100vw';
  const modalHeight = '100vh';

  const placeholder = useMemo(() => {
    return (
      kbDetail?.settings?.web_app_custom_style?.header_search_placeholder ||
      '搜索...'
    );
  }, [kbDetail]);

  const hotSearch = useMemo(() => {
    const bannerConfig = kbDetail?.settings?.web_app_landing_configs?.find(
      item => item.type === 'banner',
    );
    return bannerConfig?.banner_config?.hot_search || [];
  }, [kbDetail]);

  // 处理 URL 参数中的 mode，设置默认打开的问答类型
  useEffect(() => {
    if (qaModalOpen) {
      const savedMode = sessionStorage.getItem('qa_modal_mode') as SearchMode;
      if (savedMode && ['chat', 'search', 'web-search'].includes(savedMode)) {
        setSearchMode(savedMode);
        // 清除 sessionStorage 中的 mode，避免影响下次打开
        sessionStorage.removeItem('qa_modal_mode');
      }
    }
  }, [qaModalOpen]);

  // modal打开时自动聚焦
  useEffect(() => {
    if (qaModalOpen) {
      setTimeout(() => {
        if (searchMode === 'chat') {
          aiQaInputRef.current?.querySelector('textarea')?.focus();
        } else {
          inputRef.current?.querySelector('input')?.focus();
        }
      }, 100);
    }
  }, [qaModalOpen, searchMode]);

  // 只在弹窗关闭且没有 sessionStorage 中的 mode 时才重置为 chat
  useEffect(() => {
    if (!qaModalOpen) {
      setTimeout(() => {
        // 检查是否有待恢复的 mode，如果有则不重置
        const savedMode = sessionStorage.getItem('qa_modal_mode');
        if (!savedMode) {
          setSearchMode('chat');
        }
      }, 300);
    }
  }, [qaModalOpen]);

  useEffect(() => {
    const cid = searchParams.get('cid');
    const ask = searchParams.get('ask');
    if (cid || ask) {
      setQaModalOpen?.(true);
    }
  }, [searchParams, setQaModalOpen]);

  return (
    <Modal
      open={qaModalOpen as boolean}
      onClose={onClose}
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        p: 0,
      }}
    >
      <Box
        sx={theme => ({
          display: 'flex',
          flexDirection: 'column',
          width: modalWidth,
          height: modalHeight,
          backgroundColor: lighten(theme.palette.background.default, 0.05),
          overflow: 'hidden',
          outline: 'none',
        })}
        onClick={e => e.stopPropagation()}
      >
        {/* 顶部标签栏 */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 2,
            pt: 2,
            pb: 2.5,
          }}
        >
          <StyledTabs
            value={searchMode}
            onChange={(_, value) => {
              handleTabChange(value as SearchMode);
            }}
            variant='scrollable'
            scrollButtons={false}
          >
            <StyledTab
              label={
                <Stack direction='row' gap={0.5} alignItems='center'>
                  <IconZhinengwenda sx={{ fontSize: 16 }} />
                  {!mobile && <span>智能问答</span>}
                </Stack>
              }
              value='chat'
            />
            <StyledTab
              label={
                <Stack direction='row' gap={0.5} alignItems='center'>
                  <IconJinsousuo sx={{ fontSize: 16 }} />
                  {!mobile && <span>文档检索</span>}
                </Stack>
              }
              value='search'
            />
            <StyledTab
              label={
                <Stack direction='row' gap={0.5} alignItems='center'>
                  <LanguageIcon sx={{ fontSize: 16 }} />
                  {!mobile && <span>互联网检索</span>}
                </Stack>
              }
              value='web-search'
            />
          </StyledTabs>

          {/* Esc按钮 */}
          {!mobile && (
            <Button
              variant='outlined'
              color='primary'
              onClick={onClose}
              size='small'
              sx={theme => ({
                minWidth: 'auto',
                px: 1,
                py: '1px',
                fontSize: 12,
                fontWeight: 500,
                textTransform: 'none',
                color: 'text.secondary',
                borderColor: alpha(theme.palette.text.primary, 0.1),
              })}
            >
              Esc
            </Button>
          )}
        </Box>

        {/* 主内容区域 - 根据模式切换 */}
        <Box
          sx={{
            px: 3,
            flex: 1,
            display: searchMode === 'chat' ? 'flex' : 'none',
            flexDirection: 'column',
            opacity: isTransitioning ? 0.5 : 1,
            transition: 'opacity 0.3s ease-in-out',
          }}
        >
          <AiQaContent
            hotSearch={hotSearch}
            placeholder={placeholder}
            inputRef={aiQaInputRef}
          />
        </Box>
        <Box
          sx={{
            px: 3,
            flex: 1,
            display: searchMode === 'search' ? 'flex' : 'none',
            flexDirection: 'column',
            opacity: isTransitioning ? 0.5 : 1,
            transition: 'opacity 0.3s ease-in-out',
          }}
        >
          <SearchDocContent inputRef={inputRef} placeholder={placeholder} />
        </Box>
        <Box
          sx={{
            px: 3,
            flex: 1,
            display: searchMode === 'web-search' ? 'flex' : 'none',
            flexDirection: 'column',
            opacity: isTransitioning ? 0.5 : 1,
            transition: 'opacity 0.3s ease-in-out',
          }}
        >
          <WebSearchContent isMobile={mobile} />
        </Box>

        {/* 底部AI生成提示 */}
        <Box
          sx={{
            px: 3,
            pt: kbDetail?.settings?.disclaimer_settings?.content ? 2 : 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Typography
            variant='caption'
            sx={{
              color: 'text.disabled',
              fontSize: 12,
              display: 'flex',
              alignItems: 'center',
              gap: 1,
            }}
          >
            <Box>{kbDetail?.settings?.disclaimer_settings?.content}</Box>
          </Typography>
        </Box>
      </Box>
    </Modal>
  );
};

export default QaModal;
