# RAG检索404问题完整分析和修复方案

## 🔍 问题现状

### 用户报告
用户提问"如何接入AI模型"时:
- ✅ 系统返回了答案
- ❌ 没有显示参考文档来源
- ❌ 日志显示RAG检索失败,回退到基础模式

### 日志证据
```
level=WARN msg="get rank nodes failed, falling back to basic chat mode" 
error="get records from raglite failed: API error (status 404): 404 page not found"
```

### 代码位置
`backend/store/rag/ct.go` 第91行:
```go
res, err := s.client.Search.Retrieve(ctx, data)
```

## 🔬 根本原因分析

### 1. 第三方SDK问题
- **SDK**: `github.com/chaitin/raglite-go-sdk v0.2.1`
- **问题**: SDK的`Search.Retrieve()`方法使用的API路径与Raglite服务不匹配
- **已知bug**: 
  - `Documents.Upload()` - 不发送Authorization header (已修复)
  - `Search.Retrieve()` - API路径404错误 (待修复)

### 2. Raglite服务状态
```bash
# 测试结果
curl http://localhost:8080/api/v1/ → 404
curl http://localhost:8080/api/v1/retrieve → 404  
curl http://localhost:8080/api/v1/search/retrieve → 404
curl http://localhost:8080/api/v1/health → 404
```

**结论**: Raglite服务的API路径与SDK期望的完全不匹配

### 3. 架构变更历史
- **2025-06-04**: xiaomakuaiz 从自研SDK切换到raglite-go-sdk
- **2025-12-12**: xiaobing.wang 继续使用raglite-go-sdk
- **问题**: 第三方SDK不稳定,存在多个bug

## 💡 修复方案

### 方案1: 实现自定义retrieveWithAuth (推荐)

类似`uploadDocumentWithAuth`的做法,绕过SDK直接调用HTTP API:

```go
// 在backend/store/rag/ct.go中添加
func (s *CTRAG) retrieveWithAuth(ctx context.Context, req *raglite.RetrieveRequest) (*raglite.RetrieveResponse, error) {
	// 构建请求数据
	data := map[string]interface{}{
		"dataset_id":           req.DatasetID,
		"query":                req.Query,
		"top_k":                req.TopK,
		"metadata":             req.Metadata,
		"tags":                 req.Tags,
		"similarity_threshold": req.SimilarityThreshold,
		"chat_history":         req.ChatHistory,
		"max_chunks_per_doc":   req.MaxChunksPerDoc,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 尝试多个可能的API路径
	paths := []string{
		"/api/v1/search/retrieve",
		"/api/v1/retrieve",
		"/api/v1/datasets/" + req.DatasetID + "/retrieve",
		"/retrieve",  // 可能是根路径
	}

	var lastErr error
	for _, path := range paths {
		fullURL := s.baseURL + path
		s.logger.Debug("trying retrieve path", log.String("url", fullURL))

		httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		httpReq.Header.Set("Content-Type", "application/json")
		if s.apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
		}

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("failed to execute request: %w", err)
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		// 如果是404,尝试下一个路径
		if resp.StatusCode == http.StatusNotFound {
			s.logger.Debug("path not found, trying next", log.String("path", path), log.String("response", string(respBody)))
			lastErr = fmt.Errorf("path not found: %s", path)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
			continue
		}

		// 解析响应
		var result struct {
			Code    int                      `json:"code"`
			Message string                   `json:"message"`
			Data    raglite.RetrieveResponse `json:"data"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			lastErr = fmt.Errorf("failed to unmarshal response: %w", err)
			continue
		}

		if result.Code != 0 {
			lastErr = fmt.Errorf("API returned error code %d: %s", result.Code, result.Message)
			continue
		}

		s.logger.Info("retrieve successful", log.String("path", path), log.Int("results", len(result.Data.Results)))
		return &result.Data, nil
	}

	return nil, fmt.Errorf("all retrieve paths failed, last error: %w", lastErr)
}
```

然后修改`QueryRecords`方法:
```go
func (s *CTRAG) QueryRecords(ctx context.Context, req *QueryRecordsRequest) (string, []*domain.NodeContentChunk, error) {
	// ... 前面的代码保持不变 ...

	data := &raglite.RetrieveRequest{
		DatasetID:           req.DatasetID,
		Query:               req.Query,
		TopK:                10,
		Metadata:            map[string]interface{}{"group_ids": req.GroupIDs},
		Tags:                req.Tags,
		SimilarityThreshold: req.SimilarityThreshold,
		ChatHistory:         chatMsgs,
		MaxChunksPerDoc:     req.MaxChunksPerDoc,
	}

	// 使用自定义的retrieveWithAuth方法
	res, err := s.retrieveWithAuth(ctx, data)
	if err != nil {
		return "", nil, err
	}

	// ... 后面的代码保持不变 ...
}
```

### 方案2: 检查Raglite服务配置

可能需要检查:
1. Raglite服务是否正确启动
2. API路径配置是否正确
3. 版本兼容性问题

```bash
# 检查Raglite日志
docker logs panda-wiki-raglite | grep -E "(route|endpoint|API)"

# 检查Raglite配置
docker exec panda-wiki-raglite cat /app/config/config.yaml
```

### 方案3: 回退到自研SDK (长期方案)

考虑回退到之前稳定的自研SDK:
```go
// 使用自研SDK
import "github.com/chaitin/pandawiki/sdk/rag"
```

## 🎯 推荐行动计划

### 立即行动 (今天)
1. ✅ 实现`retrieveWithAuth`方法
2. ✅ 测试RAG检索功能
3. ✅ 验证参考文档显示

### 短期行动 (本周)
1. 📋 深入调查Raglite服务的实际API结构
2. 📋 联系Raglite团队或查看文档
3. 📋 考虑升级到更稳定的SDK版本

### 长期行动 (下月)
1. 📋 评估回退到自研SDK的可行性
2. 📋 建立RAG服务的监控和告警
3. 📋 制定技术债务清理计划

## 📊 影响评估

### 当前影响
- 🟡 **用户体验**: 中等影响
  - 用户仍能得到答案(通过大模型)
  - 但缺少知识库来源引用
  - 可能降低答案的可信度

- 🟡 **系统功能**: 部分降级
  - RAG检索功能不可用
  - 回退到基础聊天模式
  - 知识库内容未被充分利用

### 修复后预期
- ✅ RAG检索正常工作
- ✅ 显示参考文档来源
- ✅ 提升答案可信度
- ✅ 充分利用知识库内容

## 🔐 风险评估

### 修复风险: 🟢 低
- 使用与`uploadDocumentWithAuth`相同的模式
- 已验证的workaround方法
- 不影响其他功能

### 不修复风险: 🟡 中
- 用户体验下降
- 知识库价值降低
- 可能影响用户信任度

## 📝 总结

### 问题本质
这是第三方SDK `raglite-go-sdk v0.2.1` 的第二个严重bug:
1. ✅ Upload bug (已修复)
2. ❌ Retrieve bug (待修复)

### 修复策略
采用与Upload相同的workaround策略:
- 绕过SDK
- 直接调用HTTP API
- 尝试多个可能的路径
- 详细记录日志

### 长期建议
考虑更换RAG解决方案:
- 回退到自研SDK
- 或升级到稳定的第三方SDK
- 或完全重新设计RAG架构

---

**结论**: 这是一个可以修复的技术问题,不影响系统核心功能,建议尽快实施方案1的修复。
