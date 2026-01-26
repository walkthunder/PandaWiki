# 环境变量问题修复总结

## 问题描述

线上部署的版本没有获取到 `NEXT_PUBLIC_WEB_SEARCH_URL` 环境变量，导致使用了代码中的默认值：
```
http://124.221.46.229:6080/c/new?endpoint=Deepseek&model=deepseek-chat
```

而不是期望的生产环境值：
```
https://llm.webinfra.cloud/c/new?endpoint=Deepseek&model=deepseek-chat&sidebar=hidden&navbar=hidden
```

## 根本原因

Next.js 的 `NEXT_PUBLIC_*` 环境变量是在**构建时**（build time）嵌入到 JavaScript 代码中的，而不是在运行时读取。

当前的部署流程：
1. 在本地机器上执行 `pnpm run build` 构建代码
2. 构建时读取本地的环境变量（或没有读取到）
3. 将构建好的代码打包成 Docker 镜像
4. 传输到服务器并运行

问题在于：
- `docker-compose.yml` 中虽然传递了 `NEXT_PUBLIC_WEB_SEARCH_URL` 环境变量
- 但这个变量传递给容器时，代码已经构建完成，变量值已经固化在 JavaScript 文件中
- 运行时传递环境变量对已构建的前端代码无效

## 解决方案

### 1. 创建 `.env.production` 文件 ✅

在 `web/app/.env.production` 中配置生产环境变量：

```bash
# 生产环境构建配置
NEXT_PUBLIC_WEB_SEARCH_URL=https://llm.webinfra.cloud/c/new?endpoint=Deepseek&model=deepseek-chat&sidebar=hidden&navbar=hidden
TARGET=http://panda-wiki-api:8000
```

Next.js 会在执行 `NODE_ENV=production pnpm run build` 时自动加载此文件。

### 2. 更新 Makefile ✅

确保构建时使用生产环境：

```makefile
build:
	NODE_ENV=production pnpm run build
```

### 3. 更新部署脚本 ✅

在 `deploy/local-deploy-app.sh` 中添加提示信息，提醒开发者检查环境变量配置。

### 4. 添加文档 ✅

创建 `deploy/ENVIRONMENT_VARIABLES.md` 详细说明环境变量的工作原理和配置方法。

## 修改的文件

1. ✅ `web/app/.env.production` - 新建，包含生产环境变量
2. ✅ `web/app/Makefile` - 更新构建命令，显式设置 NODE_ENV
3. ✅ `deploy/local-deploy-app.sh` - 添加环境变量检查提示
4. ✅ `deploy/ENVIRONMENT_VARIABLES.md` - 新建，详细说明文档
5. ✅ `deploy/README.md` - 更新，添加环境变量文档链接

## 下一步操作

要使修复生效，需要：

1. 确认 `web/app/.env.production` 中的配置正确
2. 重新构建并部署前端应用：
   ```bash
   cd deploy
   ./local-deploy-app.sh
   ```
3. 部署完成后，在浏览器控制台验证：
   ```javascript
   console.log(process.env.NEXT_PUBLIC_WEB_SEARCH_URL)
   ```

## 关键要点

⚠️ **记住**：
- `NEXT_PUBLIC_*` 变量 = 构建时变量（需要重新构建才能更新）
- 普通环境变量（如 `TARGET`）= 运行时变量（可以通过 docker-compose.yml 动态传递）
- 修改 `NEXT_PUBLIC_*` 变量后，必须重新构建和部署镜像
