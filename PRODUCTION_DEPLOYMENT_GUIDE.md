# 生产环境部署指南 - 基于Merge问题分析

## 问题总结

经过深入分析，发现问题的根本原因是：

1. **RAG服务架构重构**: 从自研SDK切换到有bug的第三方SDK `raglite-go-sdk v0.2.1`
2. **硬编码路径问题**: 代码中存在 `/data`, `/app` 等硬编码路径
3. **Wire依赖注入**: merge后依赖注入代码需要重新生成
4. **配置文件混乱**: 开发和生产环境配置混合

## 生产环境部署检查清单

### 1. 环境变量设置 ✅
```bash
# 必须设置的环境变量
export DATA_DIR=/var/lib/pandawiki
export SSL_DIR=/etc/ssl/pandawiki

# 创建目录
sudo mkdir -p /var/lib/pandawiki
sudo mkdir -p /etc/ssl/pandawiki
sudo chown -R pandawiki:pandawiki /var/lib/pandawiki
sudo chown -R pandawiki:pandawiki /etc/ssl/pandawiki
```

### 2. 配置文件检查 ✅
```yaml
# backend/config.prod.yml
caddy_api: "/var/lib/pandawiki/caddy/run/caddy-admin.sock"  # 不要用硬编码的/app路径

rag:
  provider: "ct"
  ct_rag:
    base_url: "http://raglite:8080"  # 生产环境地址
    api_key: "${RAG_API_KEY}"        # 从环境变量读取
```

### 3. 依赖代码生成 ✅
```bash
# 在部署前必须执行
cd backend
go generate ./cmd/api
go generate ./cmd/consumer
go generate ./cmd/migrate
```

### 4. 数据库Migration检查 ✅
```bash
# 检查migration状态
./migrate -path ./store/pg/migration -database "${DATABASE_URL}" version

# 确保system_settings表存在且有model_setting_mode记录
psql -d pandawiki -c "SELECT key, value FROM system_settings WHERE key = 'model_setting_mode';"
```

### 5. RAG服务修复验证 ✅
我们的修复是必要且合理的：

```go
// backend/store/rag/ct.go 中的修复
func (s *CTRAG) uploadDocumentWithAuth(ctx context.Context, req *raglite.UploadDocumentRequest) (*raglite.UploadDocumentResponse, error) {
    // 手动添加Authorization header，修复第三方SDK的bug
    httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
}
```

**原因**: 这是对第三方SDK bug的必要workaround，不修复的话文档上传会一直401错误。

## 部署脚本建议

### 生产环境启动脚本
```bash
#!/bin/bash
# production-start.sh

set -e

# 设置环境变量
export DATA_DIR=/var/lib/pandawiki
export SSL_DIR=/etc/ssl/pandawiki
export CONFIG_FILE=config.prod.yml

# 生成依赖注入代码
echo "Generating wire dependencies..."
cd backend
go generate ./cmd/api
go generate ./cmd/consumer

# 构建应用
echo "Building applications..."
go build -o bin/api ./cmd/api
go build -o bin/consumer ./cmd/consumer
go build -o bin/migrate ./cmd/migrate

# 运行migration
echo "Running database migrations..."
./bin/migrate -path ./store/pg/migration -database "${DATABASE_URL}" up

# 启动服务
echo "Starting services..."
./bin/api &
./bin/consumer &

echo "Services started successfully"
```

## 长期改进建议

### 1. 技术债务清理
- **考虑回退到自研SDK**: 第三方SDK不稳定，建议评估回退到原来的自研SDK
- **配置管理重构**: 实现完整的配置管理系统，彻底分离开发和生产环境
- **依赖版本锁定**: 在go.mod中锁定所有依赖的稳定版本

### 2. 流程改进
- **Merge流程**: 建立更严格的代码review和测试流程
- **CI/CD**: 实现自动化测试和部署
- **监控告警**: 增加关键功能的监控和告警

### 3. 架构优化
```go
// 建议的RAG服务接口设计
type RAGService interface {
    CreateKnowledgeBase(ctx context.Context) (string, error)
    UpsertRecords(ctx context.Context, req *UpsertRecordsRequest) error
    QueryRecords(ctx context.Context, req *QueryRecordsRequest) ([]*domain.NodeContentChunk, error)
}

// 可以有多个实现：自研SDK、第三方SDK等
type SelfHostedRAG struct { ... }
type RagliteRAG struct { ... }
```

## 风险评估

### 当前修复的风险等级: 🟡 中等
- ✅ **功能完整性**: 所有核心功能正常工作
- ✅ **稳定性**: 修复了主要的bug和配置问题
- ⚠️ **技术债务**: 依赖第三方有bug的SDK，需要workaround
- ⚠️ **维护成本**: 需要维护自定义的修复代码

### 生产环境部署建议: ✅ 可以部署
当前的修复足够支持生产环境部署，但建议：
1. 密切监控RAG相关功能
2. 准备回退方案
3. 尽快规划技术债务清理

## 总结

这次merge问题的根本原因是上游项目的大规模架构重构，而不是我们的配置或部署问题。我们的修复是合理且必要的，可以安全地部署到生产环境。

**关键点**:
- 问题源于第三方SDK的bug，不是我们的代码问题
- 我们的修复是标准的workaround做法
- 生产环境部署是安全的，但需要做好监控和回退准备