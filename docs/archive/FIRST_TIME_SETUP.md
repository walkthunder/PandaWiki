# 首次使用指南

## 🎯 正确的启动顺序

### 第一步：启动依赖服务

```bash
docker compose -f docker-compose.local.yml up -d
```

等待约 10-15 秒，确保所有服务启动完成。

### 第二步：启动后端 API

```bash
./run-api.sh
```

看到 `Starting server on port 8000` 表示启动成功。

### 第三步：启动管理后台

```bash
./run-admin.sh
```

管理后台将在 `http://localhost:5173` 启动。

### 第四步：初始化系统

1. 打开浏览器访问：`http://localhost:5173`

2. 使用默认账号登录：
   - 用户名：`admin`
   - 密码：`panda-wiki`

3. 创建第一个知识库：
   - 点击"创建知识库"
   - 填写知识库名称（例如：我的知识库）
   - 选择知识库类型
   - 点击"创建"

4. 现在你可以：
   - 在管理后台管理知识库、添加文档
   - 配置 AI 模型
   - 管理用户权限

### 第五步：启动前端应用（可选）

如果你需要测试前端应用：

```bash
cd web/app
pnpm dev
```

前端应用将在 `http://localhost:3010` 启动。

**注意**：前端应用需要知识库 ID，所以必须先在管理后台创建知识库。

## 📋 完整的服务列表

启动后，你将拥有以下服务：

| 服务 | 地址 | 说明 |
|------|------|------|
| 管理后台 | http://localhost:5173 | 管理知识库、文档、用户 |
| 前端应用 | http://localhost:3010 | 用户访问的知识库界面 |
| 后端 API | http://localhost:8000 | API 服务 |
| MinIO Console | http://localhost:9001 | 对象存储管理界面 |

## 🔑 默认账号密码

### 管理后台
- 用户名：`admin`
- 密码：`panda-wiki`

### MinIO Console
- 用户名：`s3panda-wiki`
- 密码：`panda-wiki`

### 数据库
- PostgreSQL：`panda-wiki` / `panda-wiki`
- Redis：密码 `panda-wiki`

## ❓ 常见问题

### Q: 为什么前端应用报错 "kb_id is required"？

**A**: 这是正常的！因为前端应用需要知识库 ID 才能工作。你需要：
1. 先访问管理后台 `http://localhost:5173`
2. 登录并创建一个知识库
3. 然后前端应用才能正常使用

### Q: 管理后台无法连接后端？

**A**: 检查：
1. 后端 API 是否正在运行：`curl http://localhost:8000`
2. 查看后端日志是否有错误
3. 确认 `web/admin/.env` 中的 `TARGET=http://localhost:8000`

### Q: 创建知识库时报错 "failed to sync kb access settings to caddy"？

**A**: 这是正常的！本地开发环境不需要 Caddy 反向代理。这个错误不影响功能，知识库已经成功创建。你可以忽略这个错误继续使用。

### Q: 前端应用报错 "kb_id is required"？

**A**: 这是正常的！前端应用需要知道要显示哪个知识库。解决方案：

1. **推荐**：在管理后台操作即可，无需访问前端应用
2. 如果需要测试前端：访问 `http://localhost:3010?kb_id=你的知识库ID`
3. 详细说明请查看：[LOCAL_DEV_PROXY_GUIDE.md](LOCAL_DEV_PROXY_GUIDE.md)

### Q: 如何停止所有服务？

**A**: 
```bash
# 停止后端（Ctrl+C）
# 停止管理后台（Ctrl+C）
# 停止前端应用（Ctrl+C）

# 停止依赖服务
docker compose -f docker-compose.local.yml down
```

### Q: 如何重置所有数据？

**A**:
```bash
# 停止并删除所有数据
docker compose -f docker-compose.local.yml down -v
rm -rf data/
rm -rf backend/data/

# 重新启动
docker compose -f docker-compose.local.yml up -d
./run-api.sh
./run-admin.sh
```

## 🎉 下一步

现在你已经完成了初始化，可以：

1. 📚 在管理后台添加文档
2. 🤖 配置 AI 模型（如 OpenAI、Gemini 等）
3. 👥 添加团队成员
4. 🎨 自定义知识库外观
5. 🔗 获取分享链接

开始使用 PandaWiki 吧！🚀
