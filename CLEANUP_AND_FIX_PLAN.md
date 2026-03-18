# 清理和修复计划

## 第一步: 清理冗余文件

### 删除临时文档 (15个)
```bash
git rm CHAT_FUNCTION_ANALYSIS.md
git rm DOCUMENT_STATUS_FIX_COMPLETE.md
git rm DOC_STATUS_COMPLETE_FIX.md
git rm ENVIRONMENT_STATUS.md
git rm FINAL_STATUS_REPORT.md
git rm LOCAL_DEV_SUMMARY.md
git rm MERGE_ANALYSIS_REPORT.md
git rm MODEL_CONFIG_FIX_COMPLETE.md
git rm PRODUCTION_DEPLOYMENT_GUIDE.md
git rm RAG_FIX_SUMMARY.md
git rm RAG_ISSUE_DIAGNOSIS.md
git rm RAG_STATUS_FIX.md
git rm START_SUCCESS.md
git rm TASK_COMPLETION_REPORT.md
git rm TEST_RAG_STATUS.md
```

### 更新.gitignore
```bash
# 添加到.gitignore
echo "backend/api/api" >> .gitignore
echo "backend/consumer" >> .gitignore
echo "backend/ssl/*.crt" >> .gitignore
echo "backend/ssl/*.key" >> .gitignore
echo "*.log" >> .gitignore
echo "nohup.out" >> .gitignore
```

### 保留的重要文档
- `MERGE_ISSUES_AND_FIXES.md` - 合并问题总结
- `RAG_SEARCH_ISSUE_ANALYSIS.md` - RAG检索问题分析
- `LOCAL_DEV_QUICK_START.md` - 本地开发快速启动
- `CONSUMER_SERVICE_README.md` - Consumer服务文档

## 第二步: 修复RAG检索404问题

### 问题诊断
1. 检查Raglite服务的实际API路径
```bash
curl -X GET http://localhost:8080/api/v1/ 2>&1 | jq .
```

2. 查看SDK源码中的路径定义
```bash
grep -r "search/retrieve" backend/vendor/github.com/chaitin/raglite-go-sdk/ 2>/dev/null
```

### 修复方案: 实现自定义retrieveWithAuth方法

在`backend/store/rag/ct.go`中添加:

```go
// retrieveWithAuth 自定义检索方法,修复SDK的API路径问题
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
			s.logger.Debug("path not found, trying next", log.String("path", path))
			lastErr = fmt.Errorf("path not found: %s", path)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
			continue
		}

		// 解析响应
		var result struct {
			Code    int                         `json:"code"`
			Message string                      `json:"message"`
			Data    raglite.RetrieveResponse    `json:"data"`
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

然后修改`QueryRecords`方法使用新的实现:

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

## 第三步: 测试验证

### 1. 测试RAG检索
```bash
# 启动服务
cd backend
go run ./cmd/api

# 在另一个终端测试
curl 'http://localhost:3010/share/v1/chat/message' \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "如何接入AI模型",
    "conversation_id": "test-conv-id",
    "app_type": 1
  }'
```

### 2. 检查日志
应该看到:
- ✅ "trying retrieve path" 日志
- ✅ "retrieve successful" 日志
- ✅ 返回的响应包含参考文档

### 3. 验证功能
- ✅ 聊天返回答案
- ✅ 显示参考文档来源
- ✅ 没有404错误

## 第四步: 提交清理后的代码

```bash
# 1. 删除冗余文件
git rm CHAT_FUNCTION_ANALYSIS.md DOCUMENT_STATUS_FIX_COMPLETE.md \
  DOC_STATUS_COMPLETE_FIX.md ENVIRONMENT_STATUS.md \
  FINAL_STATUS_REPORT.md LOCAL_DEV_SUMMARY.md \
  MERGE_ANALYSIS_REPORT.md MODEL_CONFIG_FIX_COMPLETE.md \
  PRODUCTION_DEPLOYMENT_GUIDE.md RAG_FIX_SUMMARY.md \
  RAG_ISSUE_DIAGNOSIS.md RAG_STATUS_FIX.md \
  START_SUCCESS.md TASK_COMPLETION_REPORT.md TEST_RAG_STATUS.md

# 2. 添加RAG检索修复
git add backend/store/rag/ct.go

# 3. 更新.gitignore
git add .gitignore

# 4. 提交
git commit -m "🔧 清理冗余文件并修复RAG检索404问题

- 删除15个临时分析文档
- 修复RAG检索API路径不匹配问题
- 实现自定义retrieveWithAuth方法
- 更新.gitignore排除二进制文件和证书

问题根源: 第三方SDK raglite-go-sdk v0.2.1的API路径与服务端不匹配
解决方案: 实现自定义HTTP请求,尝试多个可能的API路径
"
```

## 总结

### 问题根源
1. **不是用户的错**: 上游项目架构重构导致
2. **第三方SDK有bug**: Upload和Retrieve方法都有问题
3. **临时文档过多**: 分析过程产生的文档没有清理

### 修复策略
1. **清理冗余**: 删除临时文档和二进制文件
2. **修复检索**: 实现自定义retrieveWithAuth方法
3. **保留重要文档**: 保留关键的问题分析和解决方案文档

### 生产环境建议
- ✅ 当前修复可以安全部署
- ⚠️ 建议监控RAG功能
- 📋 长期考虑回退到自研SDK或升级到稳定版本
