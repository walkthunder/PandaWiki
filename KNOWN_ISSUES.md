# 已知问题和解决方案

## 本地开发环境

### 1. Caddy 同步错误（已解决）

**问题**：创建知识库时看到错误日志：
```
failed to sync kb access settings to caddy: failed to send request: Post "http://unix/load": dial unix ./data/caddy/run/caddy-admin.sock: connect: no such file or directory
```

**原因**：
- Caddy 在 macOS 上使用 `network_mode: host` 和 Unix socket 有兼容性问题
- Docker Desktop for Mac 不完全支持 host 网络模式

**解决方案**：
- 本地开发环境已配置为跳过 Caddy 同步（设置 `CADDY_API=""`)
- 这不影响功能，知识库可以正常创建和使用
- 生产环境使用 Docker 部署时 Caddy 会正常工作

**状态**：✅ 已解决 - 本地开发环境会自动跳过 Caddy 同步

---

### 2. 前端应用报错 "kb_id is required"

**问题**：访问前端应用 `http://localhost:3010` 时报错。

**原因**：前端应用需要知识库 ID 才能工作。

**解决方案**：
1. 先访问管理后台 `http://localhost:5173`
2. 使用 `admin` / `panda-wiki` 登录
3. 创建一个知识库
4. 然后前端应用才能正常使用

**状态**：✅ 这是预期行为，不是 bug

---

### 3. Caddy 容器不断重启

**问题**：`docker ps` 显示 Caddy 容器状态为 "Restarting"。

**原因**：Caddy 在 macOS 上使用 Unix socket 时会失败。

**解决方案**：
- 本地开发不需要 Caddy，可以忽略这个问题
- 或者停止 Caddy 容器：
  ```bash
  docker stop panda-wiki-caddy
  ```

**状态**：⚠️ 已知限制 - macOS Docker Desktop 的限制

---

## 生产环境

### 无已知问题

生产环境使用完整的 Docker Compose 部署，所有服务都在容器内运行，不存在本地开发的兼容性问题。

---

## 报告问题

如果你遇到其他问题，请：

1. 检查日志：
   ```bash
   # 后端日志
   ./run-api.sh
   
   # Docker 服务日志
   docker compose -f docker-compose.local.yml logs [service_name]
   ```

2. 查看文档：
   - [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md)
   - [LOCAL_DEV_QUICK_START.md](LOCAL_DEV_QUICK_START.md)
   - [LOCAL_DEV_GUIDE.md](LOCAL_DEV_GUIDE.md)

3. 提交 Issue 到 GitHub
