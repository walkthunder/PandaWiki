# 🚀 从这里开始

欢迎使用 PandaWiki 本地开发环境！

## 第一步：启动服务

```bash
./dev.sh start
```

这个命令会自动启动所有需要的服务。

## 第二步：访问管理后台

打开浏览器访问：http://localhost:5173

- 用户名：`admin`
- 密码：`panda-wiki`

## 第三步：开始开发

### 启动前端（可选）

```bash
# 管理后台
cd web/admin && pnpm dev

# 用户应用
cd web/app && pnpm dev
```

## 📚 需要帮助？

- **快速开始**：[README_DEV.md](README_DEV.md)
- **详细指南**：[LOCAL_DEV_README.md](LOCAL_DEV_README.md)
- **快速参考**：[QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- **完整文档**：[DEVELOPMENT.md](DEVELOPMENT.md)

## 🔧 常用命令

```bash
./dev.sh status     # 查看服务状态
./dev.sh logs api   # 查看日志
./dev.sh stop       # 停止服务
./dev.sh restart    # 重启服务
```

## 💡 提示

1. 首次启动可能需要几分钟下载 Docker 镜像
2. 发布文档后需要等待向量化完成才能搜索
3. 查看文档列表中的 RAG 状态，`ENHANCE_SUCCEEDED` 表示可以搜索

祝开发愉快！🎉
