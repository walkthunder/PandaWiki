# RAG检索功能问题分析

## 问题现象

用户提问"如何接入AI模型"时，系统没有返回知识库中的参考文档，而是直接使用大模型回答。

## 日志分析

```
time=2026-03-18T16:34:36.017+08:00 level=WARN msg="get rank nodes failed, falling back to basic chat mode" 
module=usecase.llm error="get records from raglite failed: API error (status 404): 404 page not found"
```

**关键信息**:
- RAG检索失败，返回404错误
- 系统回退到基础聊天模式（直接调用大模型，不使用知识库）
- 这就是为什么没有显示参考文档的原因

## 根本原因

### 代码位置
`backend/store/rag/ct.go` 第92行:
```go
res, err := s.client.Search.Retrieve(ctx, data)
```

### 问题分析
第三方SDK `raglite-go-sdk v0.2.1` 的 `Search.Retrieve()` 方法使用的API路径与Raglite服务不匹配：

- **SDK期望的路径**: `POST /api/v1/search/retrieve`
- **Raglite实际路径**: 可能是不同的路径结构

这与之前发现的 `Documents.Upload()` bug类似，都是SDK与服务端API不匹配的问题。

## 影响范围

### ✅ 正常工作的功能
1. 文档上传: 已通过自定义 `uploadDocumentWithAuth()` 修复
2. 文档处理: RAG向量化和存储正常
3. 模型配置: 模型管理功能正常

### ❌ 不工作的功能
1. **RAG检索**: `Search.Retrieve()` 返回404
2. **知识库问答**: 无法检索相关文档，回退到基础模式
3. **参考文档显示**: 因为检索失败，无法显示来源

## 解决方案

### 方案1: 自定义Retrieve实现（推荐）
类似 `uploadDocumentWithAuth()` 的做法，实现自定义的检索方法：

```go
func (s *CTRAG) retrieveWithAuth(ctx context.Context, req *raglite.RetrieveRequest) (*raglite.RetrieveResponse, error) {
    // 1. 构建正确的API路径
    // 2. 手动添加Authorization header
    // 3. 发送HTTP请求
    // 4. 解析响应
}
```

### 方案2: 调试SDK路径
1. 检查Raglite服务的实际API路径
2. 查看SDK源码确认路径配置
3. 如果可能，修改SDK或配置

### 方案3: 回退到自研SDK
考虑回退到之前稳定的自研SDK `github.com/chaitin/pandawiki/sdk/rag`

## 临时workaround

在修复之前，系统会：
1. 尝试RAG检索
2. 如果失败（404），回退到基础聊天模式
3. 直接使用大模型回答，不提供参考文档

**用户体验**: 可以得到答案，但没有知识库来源引用

## 下一步行动

1. **立即**: 检查Raglite服务的API文档，确认正确的检索路径
2. **短期**: 实现自定义 `retrieveWithAuth()` 方法修复检索功能
3. **长期**: 评估是否回退到自研SDK或升级到稳定的第三方SDK版本

## 结论

这是第三方SDK的第二个bug（第一个是Upload的Authorization header问题）。建议：
- 短期内实现workaround修复
- 长期考虑更换更稳定的RAG解决方案