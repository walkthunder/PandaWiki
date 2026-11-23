// components/MermaidDiagram.jsx
'use client'; // 必须在客户端组件中使用

import { useEffect, useRef } from 'react';
import type Mermaid from 'mermaid';

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

const MermaidDiagram = ({ chart }: { chart: string }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const isMermaidInitialized = useRef(false);

  useEffect(() => {
    if (!containerRef.current || !chart) return;
    let cancelled = false;

    const renderDiagram = async () => {
      try {
        const mermaid = await loadMermaid();
        if (cancelled || !containerRef.current) return;

        // 初始化 Mermaid
        if (!isMermaidInitialized.current) {
          mermaid.initialize(MERMAID_CONFIG);
          isMermaidInitialized.current = true;
        }

        // 清理容器
        containerRef.current.innerHTML = '';

        const id = `mermaid-${Date.now()}`;
        const { svg } = await mermaid.render(id, chart);
        if (!cancelled && svg && containerRef.current) {
          containerRef.current.innerHTML = svg;
        }
      } catch (error: any) {
        // 在渲染错误时显示简单文本表示
        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = `<div>流程图渲染错误: ${error?.message}</div>`;
        }
      }
    };
    renderDiagram();

    return () => {
      cancelled = true;
    };
  }, [chart]);

  return <div ref={containerRef} className='mermaid-container' />;
};

export default MermaidDiagram;
