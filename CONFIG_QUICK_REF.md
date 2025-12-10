# 配置文件快速参考

## 📁 配置文件位置

```
backend/
├── config.yml          # 🔴 生产环境（不提交）
└── config.dev.yml      # 🟢 开发环境（可提交）

web/app/
├── .env                # 🔴 生产环境（不提交）
├── .env.dev            # 🟢 开发环境（可提交）
└── .env.local          # ⚪ 运行时生成（不提交）
```

## 🚀 本地开发

```bash
# 启动（自动使用开发配置）
./start-local-dev.sh

# 检查状态
./check-local-dev.sh

# 停止
./stop-local-dev.sh
```

**使用的配置**：
- 后端：`backend/config.dev.yml`
- 前端：`web/app/.env.dev` → 自动复制为 `.env.local`

## 🌐 生产部署

**使用的配置**：
- 后端：`backend/config.yml`（默认）
- 前端：`web/app/.env`（Docker 构建时使用）

## 🔑 关键差异

| 配置项 | 开发环境 | 生产环境 |
|--------|----------|----------|
| 后端 API | `localhost:8000` | `panda-wiki-api:8000` |
| 前端 TARGET | `http://localhost:8000` | `http://panda-wiki-api:8000` |
| 密码 | `admin123` | 生产密码（需修改） |
| 日志级别 | `0` (debug) | `2` (info) |

## ⚠️ 注意事项

1. ✅ **可以提交**：`*.dev.yml` 和 `.env.dev`
2. ❌ **不要提交**：`config.yml` 和 `.env`（已在 `.gitignore`）
3. 🔒 **生产配置**：需手动创建，参考开发配置格式

## 🔧 环境变量覆盖

后端支持通过环境变量指定配置文件：

```bash
# 使用自定义配置文件
CONFIG_FILE=config.custom.yml go run ./cmd/api

# 启动脚本中已配置
CONFIG_FILE=config.dev.yml go run ./cmd/api
```

## 📚 详细文档

查看 [CONFIG_GUIDE.md](CONFIG_GUIDE.md) 了解更多详情。
