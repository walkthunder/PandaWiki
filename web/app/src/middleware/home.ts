import { parsePathname } from '@/utils';
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { postShareV1StatPage } from '@/request/ShareStat';
import { getShareV1NodeList } from '@/request/ShareNode';
import { getShareV1AppWebInfo } from '@/request/ShareApp';
import { filterEmptyFolders, convertToTree } from '@/utils/drag';
import { deepSearchFirstNode } from '@/utils';

const StatPage = {
  welcome: 1,
  node: 2,
  chat: 3,
  auth: 4,
} as const;

const getFirstNode = async () => {
  const nodeListResult: any = await getShareV1NodeList();
  const tree = filterEmptyFolders(convertToTree(nodeListResult || []));
  return deepSearchFirstNode(tree);
};

const getHomePath = async () => {
  const info = await getShareV1AppWebInfo();
  return info?.settings?.home_page_setting;
};

export async function middleware(
  request: NextRequest,
  headers: Record<string, string>,
  session: string,
) {
  const url = request.nextUrl.clone();
  const { page, id } = parsePathname(url.pathname);
  try {
    // 获取节点列表
    if (url.pathname === '/') {
      const homePath = await getHomePath();
      if (homePath === 'custom') {
        return NextResponse.rewrite(new URL('/landing', request.url));
      } else {
        const [firstNode] = await Promise.all([getFirstNode(), getHomePath()]);
        if (firstNode) {
          return NextResponse.rewrite(
            new URL(`/node/${firstNode.id}`, request.url),
          );
        }
        return NextResponse.rewrite(new URL('/node', request.url));
      }
    }

    // 页面上报
    const pages = Object.keys(StatPage);
    if (pages.includes(page) || pages.includes(id)) {
      postShareV1StatPage(
        {
          scene: StatPage[page as keyof typeof StatPage],
          node_id: id || '',
        },
        {
          headers: {
            'x-pw-session-id': session,
            ...headers,
          },
        },
      );
    }

    return NextResponse.next();
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'message' in error &&
      error.message === 'NEXT_REDIRECT'
    ) {
      return NextResponse.redirect(
        new URL(
          `/auth/login?redirect=${encodeURIComponent(url.pathname + url.search)}`,
          request.url,
        ),
      );
    }
  }

  return NextResponse.next();
}
