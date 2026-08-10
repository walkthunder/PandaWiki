# PandaWiki 项目文档

本目录存放对 PandaWiki 代码仓库的结构梳理与技术架构说明，便于独立开发者快速理解项目全貌。

## 文档索引

| 文档 | 说明 |
|------|------|
| [目录结构说明](./目录结构说明.md) | 各目录职责、前后端子模块划分 |
| [技术架构](./技术架构.md) | 整体架构、技术选型、分层与数据流 |
| [服务端启动流程](./服务端启动流程.md) | 从 `cmd/*` 入口梳理 API / Consumer / Migrate 启动与 Wire 装配顺序 |
| [前端启动流程](./前端启动流程.md) | 管理后台（Vite SPA）与 Wiki 前台（Next.js）的开发/运行时启动链路 |
| [服务端请求调用链路](./服务端请求调用链路.md) | 请求经中间件/Handler/Usecase 到存储与 MQ 的完整链路，含发布向量化与 AI 问答 |
| [前台问答流程](./前台问答流程.md) | Wiki 前台问答：入口/SSE、RAG 检索与 Prompt/LLM 生成、反馈与旁路 |
| [服务端数据库设计](./服务端数据库设计.md) | PostgreSQL 业务表清单、逻辑外键关系、与 RAG 的 dataset_id/doc_id 桥接 |
| [本地开发启动](./本地开发启动.md) | 基于 **test** 分支；Compose 跑后端；pnpm 跑前端；含互联网检索 env |
| [生产环境部署](./生产环境部署.md) | 基于 **test** 分支；内网首次部署与增量发布（含 WEB_SEARCH_URL） |

## 项目一句话

PandaWiki 是由 AI 大模型驱动的开源知识库系统，支持产品文档、技术文档、FAQ、博客等场景，提供 AI 创作、AI 问答、AI 搜索能力。

## 仓库三大块

```
PandaWiki/
├── backend/     # Go 后端（API + MQ Consumer + 迁移）
├── web/         # 前端 Monorepo（管理台 + Wiki 前台 + 共享包）
└── sdk/         # RAG SDK（Go 客户端）
```

更完整的产品介绍与安装步骤见根目录 [README.md](../README.md)。
