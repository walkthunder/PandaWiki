import { useCallback, useEffect, useRef, useState } from 'react';

export interface UseSmartScrollOptions {
  /**
   * 容器的选择器（支持 CSS 选择器字符串或直接传入 HTMLElement）
   * @default '.conversation-container'
   */
  container?: string | HTMLElement | (() => HTMLElement | null);

  /**
   * 距离底部的阈值（像素），在此范围内认为用户在底部
   * 流式输出时内容持续增高，过小的阈值会误判为「已离开底部」
   * @default 80
   */
  threshold?: number;

  /**
   * 滚动行为。流式问答应使用 instant，smooth 跟不上 token 增长速度
   * @default 'auto'
   */
  behavior?: ScrollBehavior;

  /**
   * 是否启用智能滚动
   * @default true
   */
  enabled?: boolean;

  /**
   * 用户交互后恢复自动滚动的防抖时间（毫秒）
   * @default 150
   */
  resumeDebounceMs?: number;
}

export interface UseSmartScrollReturn {
  /**
   * 当前是否应该自动滚动
   */
  shouldAutoScroll: boolean;

  /**
   * 滚动到底部（会根据 shouldAutoScroll 判断是否执行）
   */
  scrollToBottom: () => void;

  /**
   * 强制滚动到底部（忽略 shouldAutoScroll 状态）
   */
  forceScrollToBottom: () => void;

  /**
   * 手动设置是否应该自动滚动
   */
  setShouldAutoScroll: (value: boolean) => void;

  /**
   * 检查当前是否在底部
   */
  checkIfAtBottom: () => boolean;

  /**
   * 获取容器元素
   */
  getContainer: () => HTMLElement | null;
}

/**
 * 智能滚动 Hook
 */
export function useSmartScroll(
  options: UseSmartScrollOptions = {},
): UseSmartScrollReturn {
  const {
    container = '.conversation-container',
    threshold = 80,
    behavior = 'auto',
    enabled = true,
    resumeDebounceMs = 150,
  } = options;

  const [shouldAutoScroll, setShouldAutoScroll] = useState(true);
  /**
   * 使用 ref 存储同步的自动滚动标志，避免异步状态更新导致的竞争条件
   *
   * 场景说明：
   * 1. SSE 流式输出内容，触发 scrollToBottom()
   * 2. 用户向上滚动，触发用户交互事件
   * 3. 交互事件调用 setShouldAutoScroll(false) - 这是异步的
   * 4. 但在状态更新前，又有新的 SSE 内容到达，再次触发 scrollToBottom()
   * 5. 此时 shouldAutoScroll 状态可能还是 true，导致意外滚动
   *
   * 解决方案：
   * - ref 的更新是同步的，用户交互事件会立即更新 ref
   * - scrollToBottom() 检查 ref 而不是 state，确保获取最新值
   * - state 仍然保留，用于可能需要响应式更新的场景
   */
  const shouldAutoScrollRef = useRef(true);
  const containerRef = useRef<HTMLElement | null>(null);
  const userInteractingRef = useRef(false);
  const resumeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // 程序化滚动态期间忽略 wheel/scroll，避免把自动贴底当成用户离底
  const isProgrammaticScrollRef = useRef(false);

  const getDistanceFromBottom = (element: HTMLElement): number => {
    return element.scrollHeight - element.scrollTop - element.clientHeight;
  };

  /**
   * 获取容器元素
   */
  const getContainer = useCallback((): HTMLElement | null => {
    if (!enabled) return null;

    // 如果已经缓存了容器，直接返回（前提是容器仍在 DOM 中）
    if (containerRef.current && document.contains(containerRef.current)) {
      return containerRef.current;
    }

    // 根据不同的 container 类型获取元素
    let element: HTMLElement | null = null;

    if (typeof container === 'string') {
      element = document.querySelector<HTMLElement>(container);
    } else if (typeof container === 'function') {
      element = container();
    } else if (container instanceof HTMLElement) {
      element = container;
    }

    // 缓存容器引用
    if (element) {
      containerRef.current = element;
    }

    return element;
  }, [container, enabled]);

  /**
   * 检查用户是否在底部（只读检查，不修改状态）
   */
  const checkIfAtBottom = useCallback((): boolean => {
    const element = getContainer();
    if (!element) return false;

    return getDistanceFromBottom(element) <= threshold;
  }, [getContainer, threshold]);

  const pauseAutoScroll = useCallback(() => {
    userInteractingRef.current = true;
    shouldAutoScrollRef.current = false;
    setShouldAutoScroll(false);

    if (resumeTimerRef.current) {
      clearTimeout(resumeTimerRef.current);
      resumeTimerRef.current = null;
    }
  }, []);

  /**
   * 处理滚轮事件
   * 只有「向上滚」且已经离开底部时，才暂停自动跟随。
   * 触控板在底部附近的微小回弹、以及向下滚去追内容，都不能打断跟随。
   */
  const handleWheel = useCallback(
    (event: WheelEvent) => {
      if (!enabled || isProgrammaticScrollRef.current) return;

      const element = getContainer();
      if (!element) return;

      const isScrollingUp = event.deltaY < 0;
      if (!isScrollingUp) return;

      if (getDistanceFromBottom(element) > threshold) {
        pauseAutoScroll();
      }
    },
    [enabled, getContainer, threshold, pauseAutoScroll],
  );

  /**
   * 处理触摸事件 - 不在底部时的触摸视为用户主动离开
   */
  const handleUserInteraction = useCallback(() => {
    if (!enabled || isProgrammaticScrollRef.current) return;

    const element = getContainer();
    if (!element) return;

    if (getDistanceFromBottom(element) > threshold) {
      pauseAutoScroll();
    }
  }, [enabled, threshold, getContainer, pauseAutoScroll]);

  /**
   * 处理滚动事件
   * 仅用于检测用户是否滚回底部，以便恢复自动滚动
   */
  const handleScrollEvent = useCallback(() => {
    if (!enabled || isProgrammaticScrollRef.current) return;

    if (resumeTimerRef.current) {
      clearTimeout(resumeTimerRef.current);
      resumeTimerRef.current = null;
    }

    resumeTimerRef.current = setTimeout(() => {
      const element = getContainer();
      if (!element) return;

      if (
        getDistanceFromBottom(element) <= threshold &&
        !shouldAutoScrollRef.current
      ) {
        userInteractingRef.current = false;
        shouldAutoScrollRef.current = true;
        setShouldAutoScroll(true);
      }
    }, resumeDebounceMs);
  }, [enabled, threshold, resumeDebounceMs, getContainer]);

  const performScrollToBottom = useCallback(
    (element: HTMLElement) => {
      isProgrammaticScrollRef.current = true;

      if (behavior === 'smooth') {
        element.scrollTo({
          top: element.scrollHeight,
          behavior: 'smooth',
        });
      } else {
        // 直接写 scrollTop，避免 smooth 动画被下一帧内容增高打断后永远贴不齐
        element.scrollTop = element.scrollHeight;
      }

      requestAnimationFrame(() => {
        isProgrammaticScrollRef.current = false;
      });
    },
    [behavior],
  );

  /**
   * 强制滚动到底部（忽略 shouldAutoScroll 状态，并重置为允许自动滚动）
   */
  const forceScrollToBottom = useCallback(() => {
    if (!enabled) return;

    const element = getContainer();
    if (!element) return;

    userInteractingRef.current = false;
    shouldAutoScrollRef.current = true;
    setShouldAutoScroll(true);

    if (resumeTimerRef.current) {
      clearTimeout(resumeTimerRef.current);
      resumeTimerRef.current = null;
    }

    performScrollToBottom(element);
  }, [getContainer, enabled, performScrollToBottom]);

  /**
   * 滚动到底部（会根据 shouldAutoScroll 判断）
   * 注意：这里使用 ref 而不是 state，确保检查的是最新的同步值
   */
  const scrollToBottom = useCallback(() => {
    if (!shouldAutoScrollRef.current || !enabled) return;

    const element = getContainer();
    if (!element) return;

    performScrollToBottom(element);
  }, [enabled, getContainer, performScrollToBottom]);

  /**
   * 监听用户交互事件和滚动事件
   */
  useEffect(() => {
    if (!enabled) return;

    const element = getContainer();
    if (!element) return;

    element.addEventListener('wheel', handleWheel, { passive: true });
    element.addEventListener('touchstart', handleUserInteraction, {
      passive: true,
    });
    element.addEventListener('scroll', handleScrollEvent, { passive: true });

    return () => {
      element.removeEventListener('wheel', handleWheel);
      element.removeEventListener('touchstart', handleUserInteraction);
      element.removeEventListener('scroll', handleScrollEvent);

      if (resumeTimerRef.current) {
        clearTimeout(resumeTimerRef.current);
        resumeTimerRef.current = null;
      }
    };
  }, [
    getContainer,
    handleScrollEvent,
    handleWheel,
    handleUserInteraction,
    enabled,
  ]);

  /**
   * 监听容器内容高度变化。
   * 内容节点未就绪时用 MutationObserver 等待，避免首问 display:none → flex 时漏挂观察。
   */
  useEffect(() => {
    if (!enabled) return;

    let resizeObserver: ResizeObserver | null = null;
    let mutationObserver: MutationObserver | null = null;

    const observeContent = (): boolean => {
      const element = getContainer();
      if (!element) return false;

      const contentElement = element.firstElementChild as HTMLElement | null;
      if (!contentElement) return false;

      if (resizeObserver) {
        resizeObserver.disconnect();
      }

      resizeObserver = new ResizeObserver(() => {
        if (!shouldAutoScrollRef.current) return;
        requestAnimationFrame(() => {
          scrollToBottom();
        });
      });
      resizeObserver.observe(contentElement);
      return true;
    };

    if (!observeContent()) {
      mutationObserver = new MutationObserver(() => {
        if (observeContent()) {
          mutationObserver?.disconnect();
          mutationObserver = null;
        }
      });
      mutationObserver.observe(document.body, {
        childList: true,
        subtree: true,
      });
    }

    return () => {
      resizeObserver?.disconnect();
      mutationObserver?.disconnect();
    };
  }, [enabled, getContainer, scrollToBottom]);

  /**
   * 手动设置是否应该自动滚动（包装函数，同时更新 state 和 ref）
   */
  const setShouldAutoScrollWrapper = useCallback((value: boolean) => {
    shouldAutoScrollRef.current = value;
    setShouldAutoScroll(value);

    if (value) {
      userInteractingRef.current = false;

      if (resumeTimerRef.current) {
        clearTimeout(resumeTimerRef.current);
        resumeTimerRef.current = null;
      }
    }
  }, []);

  return {
    shouldAutoScroll,
    scrollToBottom,
    forceScrollToBottom,
    setShouldAutoScroll: setShouldAutoScrollWrapper,
    checkIfAtBottom,
    getContainer,
  };
}
