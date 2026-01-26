# 环境变量配置说明

## 问题说明

Next.js 应用的环境变量分为两类：

1. **构建时变量** (`NEXT_PUBLIC_*`): 在 `pnpm run build` 时被嵌入到 JavaScript 代码中
2. **运行时变量**: 在服务器端运行时读取（如 `TARGET`）

## 关键点

⚠️ **`NEXT_PUBLIC_*` 变量必须在构建时就存在，不能在运行时动态修改！**

这意味着：
- Docker 镜像构建时就已经确定了 `NEXT_PUBLIC_WEB_SEARCH_URL` 的值
- 在 `docker-compose.yml` 中传递环境变量对已构建的镜像无效
- 必须在本地构建时就使用正确的生产环境变量

## 解决方案

### 方案 1: 使用 `.env.production` 文件（推荐）

在 `web/app/.env.production` 中配置生产环境变量：

```bash
# 生产环境构建配置
NEXT_PUBLIC_WEB_SEARCH_URL=https://llm.webinfra.cloud/c/new?endpoint=Deepseek&model=deepseek-chat&sidebar=hidden&navbar=hidden
TARGET=http://panda-wiki-api:8000
```

Next.js 会在执行 `NODE_ENV=production pnpm run build` 时自动加载此文件。

### 方案 2: 在构建时显式传递环境变量

修改 `Makefile` 或构建脚本：

```makefile
build:
	NEXT_PUBLIC_WEB_SEARCH_URL=https://llm.webinfra.cloud/... pnpm run build
```

## 环境变量文件优先级

Next.js 按以下顺序加载环境变量文件：

1. `.env.production.local` (生产环境本地覆盖，不应提交到 Git)
2. `.env.production` (生产环境配置)
3. `.env.local` (本地覆盖，不应提交到 Git)
4. `.env` (默认配置)

## 当前配置

- `web/app/.env`: 生产环境默认配置
- `web/app/.env.dev`: 本地开发环境配置
- `web/app/.env.production`: 生产环境构建配置（新增）

## 部署流程

1. 确保 `web/app/.env.production` 包含正确的生产环境变量
2. 运行 `deploy/local-deploy-app.sh` 进行构建和部署
3. 构建过程会自动读取 `.env.production` 文件
4. 生成的 Docker 镜像已包含正确的环境变量值

## 验证

部署后，可以通过以下方式验证：

1. 在浏览器控制台检查：
   ```javascript
   console.log(process.env.NEXT_PUBLIC_WEB_SEARCH_URL)
   ```

2. 查看页面源代码，搜索 `NEXT_PUBLIC_WEB_SEARCH_URL`

## 注意事项

- ⚠️ 修改 `NEXT_PUBLIC_*` 变量后必须重新构建镜像
- ⚠️ 不要在 `.env.production` 中存储敏感信息（如密码、密钥）
- ⚠️ 服务器端变量（如 `TARGET`）可以在运行时通过 `docker-compose.yml` 传递
