# 本地开发环境测试清单

## ✅ 环境检查

### 1. 检查依赖服务

```bash
docker compose -f docker-compose.local.yml ps
```

应该看到以下服务正在运行：
- ✅ panda-wiki-postgres
- ✅ panda-wiki-redis
- ✅ panda-wiki-minio
- ✅ panda-wiki-nats
- ✅ panda-wiki-qdrant
- ✅ panda-wiki-raglite
- ⚠️ panda-wiki-caddy (可能在重启，可以忽略)
- ✅ panda-wiki-crawler

### 2. 检查后端 API

```bash
curl http://localhost:8000
```

应该返回：`{"message":"Not Found"}` （这是正常的）

### 3. 检查管理后台

浏览器访问：http://localhost:5173

应该看到登录页面。

---

## 🧪 功能测试

### 测试 1: 登录管理后台

1. 访问 http://localhost:5173
2. 输入用户名：`admin`
3. 输入密码：`panda-wiki`
4. 点击登录

**预期结果**：✅ 成功登录，进入管理后台首页

---

### 测试 2: 创建知识库

1. 点击"创建知识库"按钮
2. 填写知识库信息：
   - 名称：测试知识库
   - 描述：这是一个测试知识库
   - 选择知识库类型
3. 点击"创建"

**预期结果**：
- ✅ 知识库创建成功
- ✅ 后端日志显示：`skipping caddy sync: socket path is empty`
- ✅ 没有错误日志
- ✅ 可以在列表中看到新创建的知识库

**如果看到错误**：
- ❌ 如果还看到 Caddy 错误，说明 API 没有重启成功
- 解决方案：停止并重新运行 `./run-api.sh`

---

### 测试 3: 添加文档

1. 进入刚创建的知识库
2. 点击"添加文档"
3. 输入文档内容
4. 保存

**预期结果**：✅ 文档创建成功

---

### 测试 4: 配置 AI 模型（可选）

1. 进入"设置" -> "AI 模型"
2. 配置你的 AI 模型（如 OpenAI、Gemini 等）
3. 保存配置

**预期结果**：✅ 配置保存成功

---

## 🐛 调试技巧

### 查看后端日志

后端日志会实时显示在运行 `./run-api.sh` 的终端中。

关键日志：
- ✅ `Starting server on port 8000` - API 启动成功
- ✅ `skipping caddy sync: socket path is empty` - 正确跳过 Caddy 同步
- ❌ `failed to sync kb access settings to caddy` - 说明代码没有生效，需要重启

### 查看数据库

```bash
# 连接到 PostgreSQL
docker exec -it panda-wiki-postgres psql -U panda-wiki -d panda-wiki

# 查看知识库列表
SELECT id, name, created_at FROM knowledge_bases;

# 退出
\q
```

### 查看 Redis

```bash
# 连接到 Redis
docker exec -it panda-wiki-redis redis-cli -a panda-wiki

# 查看所有 key
KEYS *

# 退出
exit
```

### 查看 MinIO

浏览器访问：http://localhost:9001
- 用户名：`s3panda-wiki`
- 密码：`panda-wiki`

---

## 📊 测试结果

完成测试后，填写结果：

- [ ] 依赖服务正常运行
- [ ] 后端 API 正常响应
- [ ] 管理后台可以访问
- [ ] 可以成功登录
- [ ] 可以创建知识库（无 Caddy 错误）
- [ ] 可以添加文档
- [ ] 可以配置 AI 模型

---

## 🎉 全部通过？

恭喜！你的本地开发环境已经完全配置好了。

现在你可以：
- 📝 开始开发新功能
- 🐛 调试现有代码
- 🧪 运行测试
- 📚 阅读代码学习

祝开发愉快！🚀
