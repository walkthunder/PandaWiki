# Wiki 前台打包、部署与回退

> 适用：现网已用 Docker Compose 跑整套服务，**只改了 `web/app`（Wiki 前台）**，需要重打镜像并替换容器。  
> 完整首次上线、改 backend 见 [生产环境部署](./生产环境部署.md)。

本文整理自一次前台滚动修复后的发布沟通：如何判断打哪个镜像、本机打包、服务器覆盖启动、发布前备份、以及镜像名与回退的关系。

---

## 1. 先判断：这次要替换哪个容器

原则：**只替换变更相关的镜像，不动数据卷 `data/`，禁止 `docker compose down -v`。**

| 改动路径 | 打哪个镜像 | 现网容器名 |
|----------|------------|------------|
| `web/app/**` | `panda-wiki-app/frontend:<tag>` | `panda-wiki-app` |
| `web/admin/**` | `panda-wiki-admin/frontend:<tag>` | `panda-wiki-nginx`（管理台静态 + 反代） |
| `backend` API | `panda-wiki-api` | `panda-wiki-api` |
| MQ / 向量 / 定时任务 | `panda-wiki-consumer` | `panda-wiki-consumer` |

只改问答滚动、QaModal、Markdown 等前台代码时，**只需重打并替换 `panda-wiki-app`**。管理台、API、Consumer、Postgres / Redis / NATS / MinIO / Caddy / RAG 等都不用动。

用 `docker ps` 对照现网（示例，以实际为准）：

| 容器 | 镜像 | 要不要为本次前台改动重建 |
|------|------|--------------------------|
| `panda-wiki-app` | `panda-wiki-app/frontend:main` | **要** |
| `panda-wiki-nginx` | `panda-wiki-admin/frontend:main` | 否（管理台） |
| `panda-wiki-api` | `.../panda-wiki-api:latest` | 否 |
| `panda-wiki-consumer` | `.../panda-wiki-consumer:v3.34.2` | 否 |
| 其它中间件 | postgres / redis / nats / minio / caddy / raglite / qdrant / crawler | 否 |

用户访问 Wiki 站点走 **Caddy → panda-wiki-app**；`app` 容器通常不直接映射宿主机端口。

---

## 2. 镜像名必须和 compose 一致

`docker compose up` 只会使用 yml 里写死的 `image:`。现网前台是：

```text
panda-wiki-app/frontend:main
```

因此本机 `make image` 打出来的名字（含 tag）必须相同，`docker load` 之后 `:main` 才会指到新镜像。仓库 `web/app/Makefile` 默认就是：

```text
PLATFORM=linux/amd64
TAG=main
REGISTRY=panda-wiki-app
# 产出：panda-wiki-app/frontend:main
```

### 覆盖的是「名字指向」，不是原地改文件

| 操作 | 结果 |
|------|------|
| `docker load` 同名同 tag | `:main` 改指向新镜像 ID |
| 旧镜像 | 还在磁盘上，只是不再叫 `:main`（变成 `<none>`，除非事先打了 backup tag） |
| 已在跑的容器 | **不会自动变**，必须 `compose up --force-recreate` 才会用新层 |

### 名字不一样会怎样

若 load 的是 `panda-wiki-app/frontend:v2`，而 compose 仍写 `:main`：

- 新镜像会进本地，启动还是旧的 `:main`
- 要么改 compose 的 `image:`，要么再执行：

```bash
docker tag panda-wiki-app/frontend:v2 panda-wiki-app/frontend:main
docker compose up -d --no-deps --force-recreate --pull never app
```

结论：保持 `panda-wiki-app/frontend:main` 最省事，和现网一致。回退用另一个 tag（如 `:backup-20260821`）留着，不要和 `:main` 抢名字。

---

## 3. 发布前：先备份正在跑的镜像

**先给正在跑的镜像打备份 tag，再 `docker load` 新包。**  
同名 `:main` 一导入，旧镜像容易变成 `<none>`，不好找。

在**服务器**上执行：

```bash
# 看当前容器实际用的镜像 ID（比只看 tag 更准）
docker inspect panda-wiki-app --format '{{.Image}}'
docker inspect panda-wiki-app --format '{{.Config.Image}}'

# 打一个不会被覆盖的备份 tag（日期可改）
docker tag panda-wiki-app/frontend:main panda-wiki-app/frontend:backup-20260821

# 可选：再导出一份 tar，拷走或留在磁盘
docker save panda-wiki-app/frontend:backup-20260821 \
  | gzip > /root/panda-wiki-app-frontend-backup-20260821.tar.gz
```

确认备份还在：

```bash
docker images | grep panda-wiki-app
```

应能看到 `:main` 和 `:backup-20260821` 指向**同一个 IMAGE ID**。

没先打 backup tag 时，可用 `docker images -a | grep panda-wiki-app` 找悬空镜像，再 `docker tag <旧IMAGE_ID> panda-wiki-app/frontend:main`。先打 tag 更稳妥。

---

## 4. 本机构建（开发机 / Mac）

### 4.1 构建时 env（不要和服务器 `.env` 混）

生产构建读的是仓库里的 `web/app/.env.production`，**不是**客户机 compose 目录的 `.env`（那是 `POSTGRES_PASSWORD`、`ADMIN_PORT` 等运行时变量）。

| 项 | 要求 |
|----|------|
| `TARGET` | `http://panda-wiki-api:8000`（Docker 内网，已在 `.env.production`） |
| `NEXT_PUBLIC_WEB_SEARCH_URL` | 互联网检索 iframe 地址；内网访问不到默认域名时先改再 build |
| `DEV_KB_ID` | **不要**打进生产包 |
| `web/app/.env.local` | 若存在且把 `TARGET` 写成 `127.0.0.1`，**先移走**，避免盖掉 `.env.production` |

```bash
# 如有本地联调 env，先移走
# mv web/app/.env.local /tmp/app.env.local.bak
```

服务器是 x86_64 时，务必用 `linux/amd64`（Makefile 已默认）。本机是 Apple Silicon 也没问题，`docker buildx` 会交叉构建。

### 4.2 打包命令

```bash
cd /path/to/PandaWiki

cd web
pnpm install

cd app
# 产出镜像：panda-wiki-app/frontend:main
make image

# 导出 tar（路径由 Makefile 写死）
make save
# 生成：/tmp/panda-wiki-app_frontend.tar
```

`make save` 依赖 `make image`，且写死保存 `panda-wiki-app/frontend:main`。若改了 `TAG`，需自行：

```bash
docker save panda-wiki-app/frontend:<版本号> | gzip > panda-wiki-app-<版本号>.tar.gz
```

---

## 5. 传到服务器并替换容器

```bash
scp /tmp/panda-wiki-app_frontend.tar root@<服务器IP>:/tmp/
```

SSH 登录后，**进入有 `docker-compose.yml` 的目录**（常见 `/opt/panda-wiki` 或 `/root`，以机器为准）：

```bash
cd <compose所在目录>

# 导入新镜像（同名 :main 会改指向）
docker load -i /tmp/panda-wiki-app_frontend.tar

# 只重建前台，不动数据卷、不拉远程镜像
docker compose up -d --no-deps --force-recreate --pull never app

# 确认
docker ps --filter name=panda-wiki-app
docker compose logs -f --tail=80 app
```

`docker ps` 里 `panda-wiki-app` 的 CREATED 应是刚才，而不是几个月前。

---

## 6. 仓库一键脚本（可选）

`deploy/local-deploy-app.sh` / `deploy/remote-deploy-app.sh` 按 `panda-wiki-app/frontend:main` 编写。用之前先改：

| 文件 | 变量 | 说明 |
|------|------|------|
| `deploy/local-deploy-app.sh` | `SERVER_IP` / `SERVER_USER` | 目标机；脚本里可能留有旧 IP，以现网为准 |
| `deploy/remote-deploy-app.sh` | `PROJECT_PATH` | **compose 所在目录**（不是任意 `/root`） |

确认后在本机：

```bash
cd /path/to/PandaWiki
bash deploy/local-deploy-app.sh
```

流程：本机构建 → scp 到 `/tmp` → SSH 执行 `docker load` + 重建 `app`。

远程脚本会 `stop` → `rm` → `up -d --no-deps --no-recreate --pull never app`。手动发布用 `--force-recreate` 更直观，效果都是用刚 load 的本地 `:main` 起新容器。

---

## 7. 发布后检查

1. `docker inspect panda-wiki-app --format '{{.Image}}'` 与 `docker images panda-wiki-app/frontend:main` 的 ID 一致  
2. 浏览器对 Wiki 前台 **强制刷新**（Cmd+Shift+R / Ctrl+Shift+R），避免旧 JS 缓存  
3. 打开 AI 智能问答：连问两轮；流式输出时用鼠标滚动，确认结束后能看到最新内容  

---

## 8. 回退

**方式 A：用备份 tag（最快）**

```bash
docker tag panda-wiki-app/frontend:backup-20260821 panda-wiki-app/frontend:main

cd <compose所在目录>
docker compose up -d --no-deps --force-recreate --pull never app
```

**方式 B：从 tar 恢复**

```bash
gunzip -c /root/panda-wiki-app-frontend-backup-20260821.tar.gz | docker load
docker tag panda-wiki-app/frontend:backup-20260821 panda-wiki-app/frontend:main

cd <compose所在目录>
docker compose up -d --no-deps --force-recreate --pull never app
```

回退后核对：

```bash
docker ps --filter name=panda-wiki-app
docker inspect panda-wiki-app --format '{{.Image}}'
```

IMAGE ID 应和备份那份一致。再强制刷新浏览器验收。

---

## 9. 推荐顺序（小结）

```text
服务器：给 :main 打 backup-日期 tag（可选再 docker save）
  → 开发机：移走 .env.local → cd web/app && make image && make save
  → scp tar 到服务器 /tmp
  → 服务器：docker load（同名覆盖 :main 指向）
  → compose up -d --force-recreate --pull never app
  → 冒烟（强制刷新 + 问答滚动）
  → 有问题：tag 回 backup，再 force-recreate
```

---

## 相关文档

- [生产环境部署](./生产环境部署.md)（首次上线、backend 增量、备份 `data/`）  
- [本地开发启动](./本地开发启动.md)（本机 pnpm，不打生产镜像）  
- [前台问答流程](./前台问答流程.md)  
- [前端启动流程](./前端启动流程.md)  

仓库脚本：`deploy/local-deploy-app.sh`、`deploy/remote-deploy-app.sh`；构建：`web/app/Makefile`、`web/app/Dockerfile`。
