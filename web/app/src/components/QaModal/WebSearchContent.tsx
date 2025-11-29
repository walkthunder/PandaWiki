'use client';
import React, { useRef, useState, useEffect } from 'react';
import {
  Box,
  Button,
  CircularProgress,
  Stack,
  Typography,
  alpha,
} from '@mui/material';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import RefreshIcon from '@mui/icons-material/Refresh';
import { WebSearchContentProps } from './types';

const WebSearchContent: React.FC<WebSearchContentProps> = ({
  url = process.env.WEB_SEARCH_URL ||
    'http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat',
  onLoad,
  onError,
  isMobile = false,
}) => {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const isMountedRef = useRef(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorType, setErrorType] = useState<
    'network' | 'unavailable' | 'timeout' | 'default'
  >('default');

  // 处理 iframe 加载完成
  const handleLoad = () => {
    if (!isMountedRef.current) return;
    setLoading(false);
    setError(null);
    onLoad?.();
  };

  // 处理 iframe 加载错误
  const handleError = () => {
    if (!isMountedRef.current) return;
    setLoading(false);
    const errorMsg = '无法加载互联网检索服务，请稍后重试';
    setError(errorMsg);
    setErrorType('default');
    const errorObj = new Error(errorMsg);
    onError?.(errorObj);
  };

  // 重试加载
  const handleRetry = () => {
    setLoading(true);
    setError(null);
    if (iframeRef.current) {
      iframeRef.current.src = url;
    }
  };

  // 获取错误提示信息
  const getErrorGuidance = () => {
    const errorMessages = {
      network: '网络连接失败，请检查您的网络设置后重试',
      unavailable: '互联网检索服务暂时不可用，请稍后重试或联系系统管理员',
      timeout: '服务加载超时，请检查网络连接状态后重试',
      default: '无法加载互联网检索服务，请稍后重试',
    };
    return errorMessages[errorType];
  };

  // 处理设备旋转和尺寸变化
  useEffect(() => {
    const handleResize = () => {
      // iframe 会自动适应容器尺寸
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // 资源清理
  useEffect(() => {
    const iframe = iframeRef.current;
    return () => {
      isMountedRef.current = false;
      // 清理 iframe 资源
      if (iframe) {
        iframe.src = 'about:blank';
      }
    };
  }, []);

  return (
    <Box
      sx={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        // 移动端特定样式
        ...(isMobile && {
          minHeight: '70vh',
        }),
      }}
    >
      {/* 加载指示器 */}
      {loading && !error && (
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'background.paper',
            borderRadius: '8px',
            zIndex: 1,
          }}
        >
          <Stack alignItems='center' gap={2}>
            <CircularProgress size={40} />
            <Typography
              variant='body2'
              sx={theme => ({
                fontSize: 14,
                color: alpha(theme.palette.text.primary, 0.6),
              })}
            >
              正在加载互联网检索服务...
            </Typography>
          </Stack>
        </Box>
      )}

      {/* 错误显示 */}
      {error && (
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'background.paper',
            borderRadius: '8px',
            zIndex: 1,
          }}
        >
          <Stack alignItems='center' gap={3} sx={{ maxWidth: 400, px: 3 }}>
            <ErrorOutlineIcon
              sx={theme => ({
                fontSize: 64,
                color: alpha(theme.palette.error.main, 0.6),
              })}
            />
            <Stack alignItems='center' gap={1}>
              <Typography
                variant='h6'
                sx={{
                  fontSize: 16,
                  fontWeight: 500,
                  color: 'text.primary',
                  textAlign: 'center',
                }}
              >
                加载失败
              </Typography>
              <Typography
                variant='body2'
                sx={theme => ({
                  fontSize: 14,
                  color: alpha(theme.palette.text.primary, 0.6),
                  textAlign: 'center',
                  lineHeight: 1.6,
                })}
              >
                {getErrorGuidance()}
              </Typography>
            </Stack>
            <Button
              variant='contained'
              startIcon={<RefreshIcon />}
              onClick={handleRetry}
              sx={{
                textTransform: 'none',
                px: 3,
                py: 1,
              }}
            >
              重试
            </Button>
          </Stack>
        </Box>
      )}

      <iframe
        ref={iframeRef}
        src={url}
        title='互联网检索服务'
        aria-label='互联网检索界面，用于访问外部搜索服务'
        onLoad={handleLoad}
        onError={handleError}
        style={{
          width: '100%',
          height: '100%',
          border: 'none',
          borderRadius: '8px',
          display: loading || error ? 'none' : 'block',
        }}
        allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture'
      />
    </Box>
  );
};

export default WebSearchContent;
