'use client';

import type Mermaid from 'mermaid';
import React from 'react';

const MERMAID_CONFIG = {
  startOnLoad: false,
  theme: 'default' as const,
  securityLevel: 'loose' as const,
  fontFamily: 'inherit',
  suppressErrorRendering: true,
};

// mermaid 体积大且内含旧内核（iOS<16.4 / 老微信）不兼容的 lookbehind 正则，
// 不走打包器，改为运行时注入 public 目录下的独立构建
let mermaidPromise: Promise<typeof Mermaid> | null = null;
const loadMermaid = (): Promise<typeof Mermaid> => {
  if (!mermaidPromise) {
    mermaidPromise = new Promise<typeof Mermaid>((resolve, reject) => {
      const w = window as any;
      if (w.mermaid) {
        resolve(w.mermaid as typeof Mermaid);
        return;
      }
      const base = w._BASE_PATH_ || '';
      const script = document.createElement('script');
      script.src = `${base}/mermaid/mermaid.min.js`;
      script.onload = () =>
        w.mermaid
          ? resolve(w.mermaid as typeof Mermaid)
          : reject(new Error('mermaid global not found'));
      script.onerror = () => reject(new Error('mermaid load failed'));
      document.head.appendChild(script);
    });
  }
  return mermaidPromise;
};

// ==================== 全局状态 ====================
let isMermaidInitialized = false;

/**
 * 初始化 Mermaid
 */
export const initializeMermaid = async (): Promise<boolean> => {
  try {
    const mermaid = await loadMermaid();
    if (!isMermaidInitialized) {
      mermaid.initialize(MERMAID_CONFIG);
      isMermaidInitialized = true;
    }
    return true;
  } catch (error) {
    console.error('Mermaid initialization error:', error);
    return false;
  }
};

/**
 * 创建 Mermaid 渲染器
 */
export const createMermaidRenderer = (
  mermaidSuccessIdRef: React.RefObject<Map<number, string>>,
) => {
  return (code: string, mermaidCount: number): string => {
    const svg = mermaidSuccessIdRef.current?.get(mermaidCount) || '';
    const className = `mermaid-container-${mermaidCount}`;
    setTimeout(async () => {
      const ok = await initializeMermaid();
      if (!ok) return;
      try {
        const mermaid = await loadMermaid();
        const id = `mermaid-${Date.now()}-${Math.random()
          .toString(36)
          .slice(2, 9)}`;
        const renderResult = await mermaid.render(id, code);
        mermaidSuccessIdRef.current?.set(mermaidCount, renderResult.svg);
        const mermaidContainer = document.querySelector(`.${className}`);
        mermaidContainer!.innerHTML = renderResult.svg;
      } catch (renderError) {}
    });

    return `<pre><div class="mermaid-container ${className}">${svg}</div></pre>`;
  };
};
