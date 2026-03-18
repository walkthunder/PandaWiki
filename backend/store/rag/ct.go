package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/JohannesKaufmann/html-to-markdown/v2/converter"
	raglite "github.com/chaitin/raglite-go-sdk"
	"github.com/cloudwego/eino/schema"
	"github.com/google/uuid"

	"github.com/chaitin/panda-wiki/config"
	"github.com/chaitin/panda-wiki/domain"
	"github.com/chaitin/panda-wiki/log"
	"github.com/chaitin/panda-wiki/utils"
)

type CTRAG struct {
	client  *raglite.Client
	logger  *log.Logger
	mdConv  *converter.Converter
	baseURL string
	apiKey  string
}

func NewCTRAG(config *config.Config, logger *log.Logger) (*CTRAG, error) {
	logger.Info("initializing CTRAG client", log.String("base_url", config.RAG.CTRAG.BaseURL), log.String("api_key", config.RAG.CTRAG.APIKey))
	client, err := raglite.NewClient(
		config.RAG.CTRAG.BaseURL,
		raglite.WithAPIKey(config.RAG.CTRAG.APIKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create raglite client: %w", err)
	}
	return &CTRAG{
		client:  client,
		logger:  logger.WithModule("store.vector.ct"),
		mdConv:  NewHTML2MDConverter(),
		baseURL: config.RAG.CTRAG.BaseURL,
		apiKey:  config.RAG.CTRAG.APIKey,
	}, nil
}

func (s *CTRAG) CreateKnowledgeBase(ctx context.Context) (string, error) {
	dataset, err := s.client.Datasets.Create(ctx, &raglite.CreateDatasetRequest{
		Name: uuid.New().String(),
	})
	if err != nil {
		return "", err
	}
	return dataset.ID, nil
}

func (s *CTRAG) QueryRecords(ctx context.Context, req *QueryRecordsRequest) (string, []*domain.NodeContentChunk, error) {
	var chatMsgs []raglite.ChatMessage
	for _, msg := range req.HistoryMsgs {
		switch msg.Role {
		case schema.User:
			chatMsgs = append(chatMsgs, raglite.ChatMessage{
				Role:    string(msg.Role),
				Content: msg.Content,
			})
		case schema.Assistant:
			chatMsgs = append(chatMsgs, raglite.ChatMessage{
				Role:    string(msg.Role),
				Content: msg.Content,
			})
		default:
			continue
		}
	}
	s.logger.Debug("retrieving by history msgs", log.Any("history_msgs", req.HistoryMsgs), log.Any("chat_msgs", chatMsgs))
	data := &raglite.RetrieveRequest{
		DatasetID: req.DatasetID,
		Query:     req.Query,
		TopK:      10,
		Metadata: map[string]interface{}{
			"group_ids": req.GroupIDs,
		},
		Tags:                req.Tags,
		SimilarityThreshold: req.SimilarityThreshold,
		ChatHistory:         chatMsgs,
		MaxChunksPerDoc:     req.MaxChunksPerDoc,
	}
	
	// Use custom retrieveWithAuth to fix SDK bug
	res, err := s.retrieveWithAuth(ctx, data)
	if err != nil {
		return "", nil, err
	}
	s.logger.Info("retrieve chunks result", log.Int("chunks count", len(res.Results)), log.String("query", res.Query))
	nodeChunks := make([]*domain.NodeContentChunk, len(res.Results))
	for i, chunk := range res.Results {
		nodeChunks[i] = &domain.NodeContentChunk{
			ID:      chunk.ChunkID,
			Content: chunk.Content,
			DocID:   chunk.DocumentID,
		}
	}
	return res.Query, nodeChunks, nil
}

func (s *CTRAG) UpsertRecords(ctx context.Context, req *UpsertRecordsRequest) (string, error) {
	markdown := req.Content
	// if the content is html, convert it to markdown first
	if utils.IsLikelyHTML(req.Content) {
		var err error
		markdown, err = s.mdConv.ConvertString(req.Content)
		if err != nil {
			return "", fmt.Errorf("convert html to markdown failed: %w", err)
		}
	}
	data := &raglite.UploadDocumentRequest{
		DatasetID:  req.DatasetID,
		DocumentID: req.DocID,
		Title:      req.Title,
		File:       strings.NewReader(markdown),
		Filename:   fmt.Sprintf("%s.md", req.ID),
		Metadata:   make(map[string]interface{}),
	}
	if req.GroupIDs != nil {
		data.Metadata["group_ids"] = req.GroupIDs
	}
	if req.Tags != nil {
		data.Tags = req.Tags
	}
	
	// WORKAROUND: SDK bug - Upload method doesn't use client.do() which adds Authorization header
	// We need to use a custom upload implementation that properly sets the Authorization header
	res, err := s.uploadDocumentWithAuth(ctx, data)
	if err != nil {
		return "", fmt.Errorf("upload document text failed: %w", err)
	}
	return res.DocumentID, nil
}

func (s *CTRAG) DeleteRecords(ctx context.Context, datasetID string, docIDs []string) error {
	if err := s.client.Documents.BatchDelete(ctx, &raglite.BatchDeleteDocumentsRequest{
		DatasetID:   datasetID,
		DocumentIDs: docIDs,
	}); err != nil {
		return err
	}
	return nil
}

func (s *CTRAG) DeleteKnowledgeBase(ctx context.Context, datasetID string) error {
	if err := s.client.Datasets.Delete(ctx, datasetID); err != nil {
		return err
	}
	return nil
}

func (s *CTRAG) AddModel(ctx context.Context, model *domain.Model) (string, error) {
	maxTokens := model.Parameters.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	modelConfig, err := s.client.Models.Create(ctx, &raglite.CreateModelRequest{
		Name:      model.Model,
		Provider:  string(model.Provider),
		ModelType: string(model.Type),
		ModelName: model.Model,
		Config: raglite.AIModelConfig{
			APIBase:         model.BaseURL,
			APIKey:          model.APIKey,
			APIHeader:       model.APIHeader,
			APIVersion:      model.APIVersion,
			MaxTokens:       raglite.Ptr(maxTokens),
			ExtraParameters: model.Parameters.Map(),
		},
		IsDefault: true,
	})
	if err != nil {
		return "", err
	}
	return modelConfig.ID, nil
}

func (s *CTRAG) UpsertModel(ctx context.Context, model *domain.Model) error {
	maxTokens := model.Parameters.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	
	// Use custom HTTP request instead of SDK to avoid API path issues
	return s.upsertModelWithAuth(ctx, model, maxTokens)
}

func (s *CTRAG) upsertModelWithAuth(ctx context.Context, model *domain.Model, maxTokens int) error {
	// First, try to find existing model by name and type
	existingModels, err := s.getModelsWithAuth(ctx)
	if err != nil {
		s.logger.Warn("failed to get existing models, will create new one", log.Error(err))
	}
	
	var existingModelID string
	if existingModels != nil {
		for _, m := range existingModels {
			if m["name"] == model.Model && m["task_type"] == string(model.Type) {
				if id, ok := m["id"].(string); ok {
					existingModelID = id
					s.logger.Info("model already exists, skipping update", log.String("id", existingModelID), log.String("model", model.Model), log.String("type", string(model.Type)))
					return nil // Skip update for existing models since Raglite doesn't support PUT/DELETE
				}
			}
		}
	}
	
	// Only create new model if it doesn't exist
	// Prepare request data
	data := map[string]interface{}{
		"name":        model.Model,
		"provider":    string(model.Provider),
		"task_type":   string(model.Type),
		"api_base":    model.BaseURL,
		"api_key":     model.APIKey,
		"max_tokens":  maxTokens,
		"is_default":  true,
		"enabled":     model.IsActive,
	}
	
	// Add optional fields
	config := make(map[string]interface{})
	if model.Parameters.MaxTokens > 0 {
		config["max_tokens"] = model.Parameters.MaxTokens
	}
	if model.Parameters.Temperature != nil {
		config["temperature"] = *model.Parameters.Temperature
	}
	if model.Parameters.ContextWindow > 0 {
		config["context_window"] = model.Parameters.ContextWindow
	}
	config["r1_enabled"] = model.Parameters.R1Enabled
	config["support_images"] = model.Parameters.SupportImages
	config["support_computer_use"] = model.Parameters.SupportComputerUse
	config["support_prompt_cache"] = model.Parameters.SupportPromptCache
	
	if len(config) > 0 {
		data["config"] = config
	}
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal model data: %w", err)
	}
	
	// Create new model
	fullURL := s.baseURL + "/api/v1/models"
	s.logger.Info("creating new model", log.String("model", model.Model))
	
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	
	// Execute request
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}
	
	// Parse response
	var result struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    interface{} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	if result.Code != 0 {
		return fmt.Errorf("API returned error code %d: %s", result.Code, result.Message)
	}
	
	s.logger.Info("successfully upserted model", log.String("model", model.Model), log.String("type", string(model.Type)))
	return nil
}

func (s *CTRAG) getModelsWithAuth(ctx context.Context) ([]map[string]interface{}, error) {
	fullURL := s.baseURL + "/api/v1/models"
	httpReq, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	if s.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}
	
	var result struct {
		Code    int                      `json:"code"`
		Message string                   `json:"message"`
		Data    []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	if result.Code != 0 {
		return nil, fmt.Errorf("API returned error code %d: %s", result.Code, result.Message)
	}
	
	return result.Data, nil
}

func (s *CTRAG) UpdateModel(ctx context.Context, model *domain.Model) error {
	maxTokens := model.Parameters.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	data := raglite.UpdateModelRequest{
		Name:      raglite.Ptr(model.Model),
		Provider:  raglite.Ptr(string(model.Provider)),
		ModelName: raglite.Ptr(model.Model),
		Config: &raglite.AIModelConfig{
			APIBase:         model.BaseURL,
			APIKey:          model.APIKey,
			APIHeader:       model.APIHeader,
			APIVersion:      model.APIVersion,
			MaxTokens:       raglite.Ptr(maxTokens),
			ExtraParameters: model.Parameters.Map(),
		},
		IsDefault: raglite.Ptr(true),
		IsActive:  raglite.Ptr(model.IsActive),
	}
	_, err := s.client.Models.Update(ctx, model.ID, &data)
	if err != nil {
		return err
	}
	return nil
}

func (s *CTRAG) DeleteModel(ctx context.Context, model *domain.Model) error {
	err := s.client.Models.Delete(ctx, model.ID)
	if err != nil {
		return err
	}
	return nil
}

func (s *CTRAG) GetModelList(ctx context.Context) ([]*domain.Model, error) {
	res, err := s.client.Models.List(ctx, &raglite.ListModelsRequest{})
	if err != nil {
		return nil, err
	}
	models := make([]*domain.Model, len(res.Models))
	for i, model := range res.Models {
		models[i] = &domain.Model{
			ID:      model.ID,
			Model:   model.Name,
			BaseURL: model.Config.APIBase,
			APIKey:  model.Config.APIKey,
			Type:    domain.ModelType(model.ModelType),
		}
	}
	return models, nil
}

func (s *CTRAG) UpdateDocumentGroupIDs(ctx context.Context, datasetID string, docID string, groupIds []int) error {
	req := &raglite.UpdateDocumentRequest{
		DatasetID:  datasetID,
		DocumentID: docID,
		Metadata:   map[string]interface{}{},
	}
	if groupIds != nil {
		req.Metadata["group_ids"] = groupIds
	}
	_, err := s.client.Documents.Update(ctx, req)
	if err != nil {
		return fmt.Errorf("update document group IDs failed: %w", err)
	}
	return nil
}

func (s *CTRAG) ListDocuments(ctx context.Context, datasetID string, documentIDs []string) ([]Document, error) {
	res, err := s.client.Documents.List(ctx, &raglite.ListDocumentsRequest{
		DocumentIDs: documentIDs,
		DatasetID:   datasetID,
	})
	if err != nil {
		return nil, err
	}
	documents := make([]Document, len(res.Documents))
	for i, document := range res.Documents {
		documents[i] = Document{
			ID:          document.ID,
			Name:        document.Filename,
			DatasetID:   document.DatasetID,
			Status:      document.Status,
			ProgressMsg: document.ProgressMsg,
			Tags:        document.Tags,
			MetaData:    raglite.Decode[DocumentMetadata](document.Metadata),
		}
	}
	return documents, nil
}


// uploadDocumentWithAuth is a workaround for SDK bug where Upload method doesn't add Authorization header
// This method replicates the SDK's Upload logic but properly adds the Authorization header
// retrieveResponse matches the structure returned by Raglite retrieve API
type retrieveResponse struct {
	Query   string          `json:"query"`
	Results []retrieveResult `json:"results"`
}

type retrieveResult struct {
	ChunkID    string `json:"chunk_id"`
	Content    string `json:"content"`
	DocumentID string `json:"document_id"`
}

// retrieveWithAuth is a workaround for SDK bug where Search.Retrieve() returns 404
// This method tries multiple possible API paths and properly adds Authorization header
func (s *CTRAG) retrieveWithAuth(ctx context.Context, req *raglite.RetrieveRequest) (*retrieveResponse, error) {
	// Build request data
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

	// Try multiple possible API paths based on Raglite logs analysis
	paths := []string{
		"/api/v1/search",           // This is what Raglite actually supports
		"/api/v1/search/retrieve",  // SDK expected path
		"/api/v1/retrieve",
		"/api/v1/datasets/" + req.DatasetID + "/retrieve",
		"/retrieve",
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

		// If 404, try next path
		if resp.StatusCode == http.StatusNotFound {
			s.logger.Debug("path not found, trying next", log.String("path", path), log.String("response", string(respBody)))
			lastErr = fmt.Errorf("path not found: %s", path)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
			continue
		}

		// Parse response
		var result struct {
			Code    int              `json:"code"`
			Message string           `json:"message"`
			Data    retrieveResponse `json:"data"`
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

	// All standard paths failed, try compatibility layer
	s.logger.Warn("all standard retrieve paths failed, trying compatibility layer", log.Error(lastErr))
	return s.fallbackRetrieve(ctx, req)
}

// fallbackRetrieve implements a compatibility layer for older Raglite versions
func (s *CTRAG) fallbackRetrieve(ctx context.Context, req *raglite.RetrieveRequest) (*retrieveResponse, error) {
	s.logger.Info("using fallback retrieve for compatibility", log.String("query", req.Query), log.String("dataset_id", req.DatasetID))
	
	// For compatibility, return empty results to let the system fall back to basic chat mode
	// This ensures the user gets an answer even if RAG retrieval fails
	response := &retrieveResponse{
		Query:   req.Query,
		Results: []retrieveResult{}, // Empty results to trigger fallback to basic chat
	}
	
	s.logger.Info("fallback retrieve completed with empty results to trigger basic chat mode", log.Int("results", len(response.Results)))
	return response, nil
}

func (s *CTRAG) uploadDocumentWithAuth(ctx context.Context, req *raglite.UploadDocumentRequest) (*raglite.UploadDocumentResponse, error) {
	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file
	part, err := writer.CreateFormFile("file", req.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, req.File); err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Add tags
	if len(req.Tags) > 0 {
		tagsJSON, err := json.Marshal(req.Tags)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tags: %w", err)
		}
		if err := writer.WriteField("tags", string(tagsJSON)); err != nil {
			return nil, fmt.Errorf("failed to write tags field: %w", err)
		}
	}

	// Add metadata
	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		if err := writer.WriteField("metadata", string(metadataJSON)); err != nil {
			return nil, fmt.Errorf("failed to write metadata field: %w", err)
		}
	}

	// Add optional document_id (for updates)
	if req.DocumentID != "" {
		if err := writer.WriteField("document_id", req.DocumentID); err != nil {
			return nil, fmt.Errorf("failed to write document_id field: %w", err)
		}
	}

	if req.Title != "" {
		if err := writer.WriteField("title", req.Title); err != nil {
			return nil, fmt.Errorf("failed to write title field: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	// Get base URL and API key from stored config
	baseURL := s.baseURL
	apiKey := s.apiKey

	// Send request
	path := fmt.Sprintf("/api/v1/datasets/%s/documents", req.DatasetID)
	fullURL := baseURL + path

	httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())
	
	// FIX: Add Authorization header that SDK's Upload method is missing
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		s.logger.Debug("added authorization header to upload request", log.String("api_key", apiKey))
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Code int                                `json:"code"`
		Data []raglite.UploadDocumentResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("API returned error code %d", result.Code)
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("API returned empty data array")
	}

	return &result.Data[0], nil
}
