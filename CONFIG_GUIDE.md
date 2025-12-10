# 配置文件使用指南

本项目区分开发环境和生产环境的配置文件，避免配置混淆和敏感信息泄露。

## 配置文件说明

### 后端配置

- **`backend/config.yml`** - 生产环境配置（包含敏感信息，不提交到 Git）
- **`backend/config.dev.yml`** - 开发环境配置（可以提交到 Git，不包含敏感信息）

### 前端配置

- **`web/app/.env`** - 生产环境配置（包含生产环境 API 地址，不提交到 Git）
- **`web/app/.env.dev`** - 开发环境配置（可以提交到 Git，包含本地开发配置）
- **`web/app/.env.local`** - Next.js 运行时使用的配置（自动生成，不提交到 Git）

## 本地开发

### 启动开发环境

```bash
./start-local-dev.sh
```

启动脚本会自动：
1. 使用 `backend/config.dev.yml` 作为后端配置
2. 将 `web/app/.env.dev` 复制为 `web/app/.env.local` 供 Next.js 使用

### 检查开发环境状态

```bash
./check-local-dev.sh
```

### 停止开发环境

```bash
./stop-local-dev.sh
```

## 生产环境部署

生产环境部署时：
1. 后端使用 `backend/config.yml`（默认配置文件）
2. 前端使用 `web/app/.env`（Docker 构建时会复制到镜像中）

## 配置文件优先级

### 后端

1. 环境变量 `CONFIG_FILE` 指定的配置文件
2. `./config.yml`（默认）
3. `./config/config.yml`

### 前端（Next.js）

1. `.env.local`（本地开发，优先级最高）
2. `.env.production` 或 `.env.development`（根据 NODE_ENV）
3. `.env`（默认）

## 注意事项

1. **不要将生产环境配置提交到 Git**
   - `backend/config.yml` 已在 `.gitignore` 中
   - `web/app/.env` 已在 `.gitignore` 中

2. **开发环境配置可以提交**
   - `backend/config.dev.yml` 可以提交
   - `web/app/.env.dev` 可以提交
   - 这些文件不包含生产环境敏感信息

3. **首次设置**
   - 开发环境：运行 `./start-local-dev.sh` 会自动配置
   - 生产环境：需要手动创建 `backend/config.yml` 和 `web/app/.env`

4. **环境变量覆盖**
   - 后端支持通过环境变量覆盖配置文件中的敏感信息
   - 前端的 `NEXT_PUBLIC_*` 变量会暴露到客户端，注意不要包含敏感信息

## 示例

### 本地开发配置示例

`backend/config.dev.yml`:
```yaml
log:
  level: 0  # debug

http:
  port: 8000

pg:
  dsn: "host=localhost user=panda-wiki password=admin123 dbname=panda-wiki port=5432"
```

`web/app/.env.dev`:
```env
TARGET=http://localhost:8000
STATIC_FILE_TARGET=http://localhost:8000
```

### 生产环境配置示例

`backend/config.yml`:
```yaml
log:
  level: 2  # info

http:
  port: 8000

pg:
  dsn: "host=postgres user=prod_user password=<SECURE_PASSWORD> dbname=prod_db"
```

`web/app/.env`:
```env
TARGET=http://panda-wiki-api:8000
```
