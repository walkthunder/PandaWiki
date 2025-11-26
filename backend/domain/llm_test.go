package domain

import (
	"testing"
)

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
		{
			name:   "部分映射",
			answer: "参考：[文档1](/node/node-1) 和 [文档2](/node/node-2)",
			nodeURLMap: map[string]string{
				"node-1": "https://example.com/doc/1",
			},
			expected: "参考：[文档1](https://example.com/doc/1) 和 [文档2](/node/node-2)",
		},
		{
			name:   "包含引用列表",
			answer: "这是回答内容\n---\n### 引用列表\n> [1]. [文档标题1](/node/node-1)\n> [2]. [文档标题2](/node/node-2)",
			nodeURLMap: map[string]string{
				"node-1": "https://example.com/doc/1",
				"node-2": "https://example.com/doc/2",
			},
			expected: "这是回答内容\n---\n### 引用列表\n> [1]. [文档标题1](https://example.com/doc/1)\n> [2]. [文档标题2](https://example.com/doc/2)",
		},
		{
			name:       "空映射表",
			answer:     "参考：[文档](/node/node-1)",
			nodeURLMap: nil,
			expected:   "参考：[文档](/node/node-1)",
		},
		{
			name:       "无链接的文本",
			answer:     "这是一段没有链接的文本",
			nodeURLMap: map[string]string{"node-1": "https://example.com/doc/1"},
			expected:   "这是一段没有链接的文本",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReplaceNodeLinks(tt.answer, tt.nodeURLMap)
			if result != tt.expected {
				t.Errorf("ReplaceNodeLinks() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildNodeURLMap(t *testing.T) {
	tests := []struct {
		name        string
		rankedNodes []*RankedNodeChunks
		expected    map[string]string
	}{
		{
			name: "构建映射表",
			rankedNodes: []*RankedNodeChunks{
				{NodeID: "node-1", OriginalURL: "https://example.com/doc/1"},
				{NodeID: "node-2", OriginalURL: "https://example.com/doc/2"},
			},
			expected: map[string]string{
				"node-1": "https://example.com/doc/1",
				"node-2": "https://example.com/doc/2",
			},
		},
		{
			name: "过滤空 URL",
			rankedNodes: []*RankedNodeChunks{
				{NodeID: "node-1", OriginalURL: "https://example.com/doc/1"},
				{NodeID: "node-2", OriginalURL: ""},
				{NodeID: "node-3", OriginalURL: "https://example.com/doc/3"},
			},
			expected: map[string]string{
				"node-1": "https://example.com/doc/1",
				"node-3": "https://example.com/doc/3",
			},
		},
		{
			name:        "空列表",
			rankedNodes: []*RankedNodeChunks{},
			expected:    map[string]string{},
		},
		{
			name:        "nil 列表",
			rankedNodes: nil,
			expected:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildNodeURLMap(tt.rankedNodes)
			if len(result) != len(tt.expected) {
				t.Errorf("BuildNodeURLMap() length = %v, want %v", len(result), len(tt.expected))
				return
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("BuildNodeURLMap()[%s] = %v, want %v", k, result[k], v)
				}
			}
		})
	}
}

func TestRankedNodeChunks_GetURL(t *testing.T) {
	tests := []struct {
		name        string
		node        *RankedNodeChunks
		baseURL     string
		expectedURL string
	}{
		{
			name: "使用原始 URL",
			node: &RankedNodeChunks{
				NodeID:      "node-123",
				OriginalURL: "https://example.com/doc/123",
			},
			baseURL:     "https://wiki.example.com",
			expectedURL: "https://example.com/doc/123",
		},
		{
			name: "降级到内部链接",
			node: &RankedNodeChunks{
				NodeID:      "node-123",
				OriginalURL: "",
			},
			baseURL:     "https://wiki.example.com",
			expectedURL: "https://wiki.example.com/node/node-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.GetURL(tt.baseURL)
			if result != tt.expectedURL {
				t.Errorf("GetURL() = %v, want %v", result, tt.expectedURL)
			}
		})
	}
}
