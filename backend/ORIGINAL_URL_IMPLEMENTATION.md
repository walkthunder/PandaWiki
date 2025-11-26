# Original URL 实现指南

## 概述

本文档说明如何实现将问答引用链接从内部 `/node/node-id` 替换为三方网站原始 URL 的功能。

## 实现方案

### 1. 数据库层面

已在 `nodes` 和 `node_releases` 表中添加 `original_url` 字段：

```sql
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';
ALTER TABLE node_releases ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';
```

迁移文件：`backend/migration/fns/0003_add_original_url_to_nodes.go`

### 2. 领域模型更新

#### Node 结构体
```go
type Node struct {
    // ... 其他字段
    OriginalURL string `json:"original_url"` // 三方网站的原始链接
    // ...
}
```

#### RankedNodeChunks 结构体
```go
type RankedNodeChunks struct {
    NodeID        string
    NodeName      string
    NodeSummary   string
    NodeEmoji     string
    NodePathNames []string
    OriginalURL   string // 三方网站的原始链接
    Chunks        []*NodeContentChunk
}

// GetURL 优先返回原始 URL
func (n *RankedNodeChunks) GetURL(baseURL string) string {
    if n.OriginalURL != "" {
        return n.OriginalURL
    }
    return fmt.Sprintf("%s/node/%s", baseURL, n.NodeID)
}
```

### 3. 链接替换工具函数

在 `backend/domain/llm.go` 中添加了两个工具函数：

#### BuildNodeURLMap
从检索结果构建 Node-ID 到 URL 的映射表：

```go
func BuildNodeURLMap(rankedNodes []*RankedNodeChunks) map[string]string {
    nodeURLMap := make(map[string]string)
    for _, node := range rankedNodes {
        if node.OriginalURL != "" {
            nodeURLMap[node.NodeID] = node.OriginalURL
        }
    }
    return nodeURLMap
}
```

#### ReplaceNodeLinks
替换回答中的 `[xxx](/node/node-id)` 为 `[xxx](三方URL)`：

```go
func ReplaceNodeLinks(answer string, nodeURLMap map[string]string) string {
    if len(nodeURLMap) == 0 {
        return answer
    }
    
    pattern := regexp.MustCompile(`\[(.*?)\]\(/node/(.*?)\)`)
    
    return pattern.ReplaceAllStringFunc(answer, func(match string) string {
        matches := pattern.FindStringSubmatch(match)
        if len(matches) != 3 {
            return match
        }
        
        title := matches[1]
        nodeID := matches[2]
        
        // 如果有映射的 URL，则替换；否则保留原链接
        if url, ok := nodeURLMap[nodeID]; ok && url != "" {
            return fmt.Sprintf("[%s](%s)", title, url)
        }
        
        return match
    })
}
```

### 4. Chat 流程集成

在 `backend/usecase/chat.go` 的 `Chat` 方法中，LLM 生成回答后添加链接替换：

```go
// LLM 生成回答
chatErr := u.llmUsecase.ChatWithAgent(ctx, chatModel, messages, &usage, onChunkAC)

// 处理缓冲区中剩余的内容
if flushBuffer != nil {
    flushBuffer(ctx, "data")
}

// 后处理：替换回答中的 /node/node-id 链接为三方原始 URL
nodeURLMap := domain.BuildNodeURLMap(rankedNodes)
answer = domain.ReplaceNodeLinks(answer, nodeURLMap)
```

### 5. 检索时填充 OriginalURL

在 `backend/usecase/llm.go` 的 `GetRankNodes` 方法中，从数据库查询结果填充 `OriginalURL`：

```go
rankNodeChunk := &domain.RankedNodeChunks{
    NodeID:        docNode.NodeID,
    NodeName:      docNode.Name,
    NodeSummary:   docNode.Meta.Summary,
    NodeEmoji:     docNode.Meta.Emoji,
    NodePathNames: docNode.PathNames,
    OriginalURL:   docNode.OriginalURL, // 填充原始 URL
    Chunks:        []*domain.NodeContentChunk{record},
}
```

## 爬虫集成

### 在爬取时保存 original_url

在爬取三方网站内容时，需要保存原始 URL。以下是需要修改的地方：

#### 1. 创建节点时保存 URL

在 `backend/usecase/creation.go` 或相关的节点创建逻辑中，添加 `OriginalURL` 字段：

```go
// 示例：创建从 URL 爬取的节点
node := &domain.Node{
    // ... 其他字段
    OriginalURL: crawledURL, // 保存爬取的原始 URL
    // ...
}
```

#### 2. 爬虫数据结构

确保爬虫返回的数据结构包含原始 URL：

```go
type CrawledDoc struct {
    Title       string
    Content     string
    OriginalURL string // 三方网站的原始链接
    // ... 其他字段
}
```

#### 3. URL 格式校验

在保存 URL 前进行校验：

```go
func isValidURL(urlStr string) bool {
    if urlStr == "" {
        return false
    }
    // 检查是否以 http:// 或 https:// 开头
    return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}

// 使用示例
if isValidURL(crawledURL) {
    node.OriginalURL = crawledURL
}
```

## 异常处理与边界情况

### 1. 无三方 URL 的 Node

对于手动创建的文档或没有爬取到 `original_url` 的节点：
- `GetURL()` 方法会自动降级为内部链接 `/node/node-id`
- `ReplaceNodeLinks()` 不会替换这些链接

### 2. URL 格式校验

- 入库时校验 `original_url` 的合法性
- 确保以 `http://` 或 `https://` 开头
- 防止无效链接

### 3. 性能考量

- 正则匹配性能：使用简洁的正则表达式，性能影响可忽略
- 映射表构建：O(n) 时间复杂度，n 为检索结果数量
- 内存占用：映射表大小与检索结果数量成正比

## 测试建议

### 1. 单元测试

测试 `ReplaceNodeLinks` 函数：

```go
func TestReplaceNodeLinks(t *testing.T) {
    tests := []struct {
        name       string
        answer     string
        nodeURLMap map[string]string
        expected   string
    }{
        {
            name:   "替换单个链接",
            answer: "参考文档：[管理规范](/node/node-123)",
            nodeURLMap: map[string]string{
                "node-123": "https://example.com/doc/123",
            },
            expected: "参考文档：[管理规范](https://example.com/doc/123)",
        },
        {
            name:   "替换多个链接",
            answer: "参考：[文档1](/node/node-1) 和 [文档2](/node/node-2)",
            nodeURLMap: map[string]string{
                "node-1": "https://example.com/doc/1",
                "node-2": "https://example.com/doc/2",
            },
            expected: "参考：[文档1](https://example.com/doc/1) 和 [文档2](https://example.com/doc/2)",
        },
        {
            name:       "无映射时保留原链接",
            answer:     "参考：[文档](/node/node-999)",
            nodeURLMap: map[string]string{},
            expected:   "参考：[文档](/node/node-999)",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := domain.ReplaceNodeLinks(tt.answer, tt.nodeURLMap)
            if result != tt.expected {
                t.Errorf("expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

### 2. 集成测试

1. 爬取一个三方网站
2. 验证 `original_url` 是否正确保存到数据库
3. 进行问答测试
4. 验证返回的引用链接是否为三方 URL

## 部署步骤

1. **运行数据库迁移**：启动应用时会自动执行迁移
2. **更新爬虫逻辑**：确保在爬取时保存 `original_url`
3. **测试验证**：在测试环境验证功能正常
4. **生产部署**：部署到生产环境

## 注意事项

1. **向后兼容**：现有的没有 `original_url` 的节点会自动使用内部链接
2. **数据一致性**：确保 `nodes` 和 `node_releases` 表的 `original_url` 保持同步
3. **URL 有效性**：定期检查 URL 是否失效（可选功能）
4. **隐私安全**：确保不会泄露内部敏感 URL

## 总结

这个实现方案：
- ✅ 简单清晰，易于维护
- ✅ 性能良好，对现有流程影响小
- ✅ 向后兼容，不影响现有数据
- ✅ 职责分离，符合最佳实践
- ✅ 易于测试和调试
