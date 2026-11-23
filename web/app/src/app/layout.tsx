import ErrorComponent from '@/components/error';
import StoreProvider from '@/provider';
import { ThemeStoreProvider } from '@/provider/themeStore';
import { getShareV1AppWebInfo } from '@/request/ShareApp';
import { getShareProV1AuthInfo } from '@/request/pro/ShareAuth';
import Script from 'next/script';
import { Box } from '@mui/material';
import { AppRouterCacheProvider } from '@mui/material-nextjs/v16-appRouter';
import type { Metadata, Viewport } from 'next';
import localFont from 'next/font/local';
import { headers, cookies } from 'next/headers';
import { getSelectorsByUserAgent } from 'react-device-detect';
import { getBasePath, getImagePath } from '@/utils';
import './globals.css';

const gilory = localFont({
  variable: '--font-gilory',
  src: [
    {
      path: '../assets/fonts/gilroy-bold-700.otf',
      weight: '700',
    },
    {
      path: '../assets/fonts/gilroy-medium-500.otf',
      weight: '400',
    },
    {
      path: '../assets/fonts/gilroy-regular-400.otf',
      weight: '300',
    },
  ],
});

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
};

export async function generateMetadata(): Promise<Metadata> {
  const kbDetail: any = await getShareV1AppWebInfo();
  const basePath = getBasePath(kbDetail?.base_url || '');
  const icon = getImagePath(kbDetail?.settings?.icon || '', basePath);
  return {
    metadataBase: new URL(process.env.TARGET || ''),
    title: kbDetail?.settings?.title || 'Panda-Wiki',
    description: kbDetail?.settings?.desc || '',
    keywords: kbDetail?.settings?.keyword || '',
    icons: {
      icon: icon || `${basePath}/favicon.png`,
    },
    openGraph: {
      title: kbDetail?.settings?.title || 'Panda-Wiki',
      description: kbDetail?.settings?.desc || '',
      images: icon ? [icon] : [],
    },
  };
}

const Layout = async ({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) => {
  const headersList = await headers();
  const userAgent = headersList.get('user-agent');
  const cookieStore = await cookies();
  const themeMode = (cookieStore.get('theme_mode')?.value || 'light') as
    | 'light'
    | 'dark';

  let error: any = null;

  const [kbDetailResolve, authInfoResolve] = await Promise.allSettled([
    getShareV1AppWebInfo(),
    getShareProV1AuthInfo({}),
  ]);

  const authInfo: any =
    authInfoResolve.status === 'fulfilled' ? authInfoResolve.value : undefined;
  const kbDetail: any =
    kbDetailResolve.status === 'fulfilled' ? kbDetailResolve.value : undefined;

  if (
    authInfoResolve.status === 'rejected' &&
    authInfoResolve.reason.code === 403
  ) {
    error = authInfoResolve.reason;
  }

  const { isMobile } = getSelectorsByUserAgent(userAgent || '') || {
    isMobile: false,
  };

  const basePath = getBasePath(kbDetail?.base_url || '');

  return (
    <html lang='en'>
      <Script
        id='base-path'
        dangerouslySetInnerHTML={{
          __html: `window._BASE_PATH_ = '${basePath}';`,
        }}
      />
      <Script
        id='legacy-browser-polyfill'
        strategy='beforeInteractive'
        dangerouslySetInnerHTML={{
          __html: `(function () {
  try {
    if (typeof window.structuredClone !== 'function') {
      (function () {
        function cloneValue(value, seen) {
          if (value === null || typeof value !== 'object') return value;
          if (value instanceof Date) return new Date(value.getTime());
          if (value instanceof RegExp)
            return new RegExp(value.source, value.flags);
          if (seen.has(value)) return seen.get(value);
          var out;
          if (value instanceof Map) {
            out = new Map();
            seen.set(value, out);
            value.forEach(function (v, k) {
              out.set(cloneValue(k, seen), cloneValue(v, seen));
            });
            return out;
          }
          if (value instanceof Set) {
            out = new Set();
            seen.set(value, out);
            value.forEach(function (v) {
              out.add(cloneValue(v, seen));
            });
            return out;
          }
          if (Array.isArray(value)) {
            out = new Array(value.length);
            seen.set(value, out);
            for (var i = 0; i < value.length; i++) {
              out[i] = cloneValue(value[i], seen);
            }
            return out;
          }
          out = {};
          seen.set(value, out);
          for (var key in value) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
              out[key] = cloneValue(value[key], seen);
            }
          }
          return out;
        }
        window.structuredClone = function (value) {
          return cloneValue(value, new Map());
        };
      })();
    }
    if (!Array.prototype.at) {
      Array.prototype.at = function (n) {
        n = Math.trunc(n) || 0;
        if (n < 0) n += this.length;
        return n < 0 || n >= this.length ? undefined : this[n];
      };
    }
    if (!Object.hasOwn) {
      Object.hasOwn = function (obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key);
      };
    }
    if (!String.prototype.replaceAll) {
      String.prototype.replaceAll = function (search, replacement) {
        return this.split(search).join(replacement);
      };
    }
  } catch (e) {}
})();`,
        }}
      />
      <body
        className={`${gilory.variable} ${themeMode === 'dark' ? 'dark' : 'light'}`}
      >
        <AppRouterCacheProvider>
          <ThemeStoreProvider themeMode={themeMode}>
            <StoreProvider
              kbDetail={kbDetail}
              themeMode={themeMode || 'light'}
              mobile={isMobile}
              authInfo={authInfo}
            >
              <Box
                sx={{
                  bgcolor: 'background.paper',
                  height: error ? '100vh' : 'auto',
                }}
                id='app-theme-root'
              >
                {error ? <ErrorComponent error={error} /> : children}
              </Box>
            </StoreProvider>
          </ThemeStoreProvider>
        </AppRouterCacheProvider>
      </body>
    </html>
  );
};

export default Layout;
