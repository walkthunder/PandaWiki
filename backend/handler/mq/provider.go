package mq

import (
	"github.com/google/wire"

	"github.com/chaitin/panda-wiki/repo/ipdb"
	"github.com/chaitin/panda-wiki/repo/mq"
	"github.com/chaitin/panda-wiki/repo/pg"
	"github.com/chaitin/panda-wiki/store/rag"
	"github.com/chaitin/panda-wiki/store/s3"
	"github.com/chaitin/panda-wiki/usecase"
)

type MQHandlers struct {
	RAGMQHandler        *RAGMQHandler
	RagDocUpdateHandler *RagDocUpdateHandler  // 重新启用，已添加对应的NATS流
	StatCronHandler     *CronHandler
}

var ProviderSet = wire.NewSet(
	pg.ProviderSet,
	rag.ProviderSet,
	mq.ProviderSet,
	ipdb.ProviderSet,
	s3.ProviderSet,

	usecase.NewLLMUsecase,
	usecase.NewStatUseCase,
	usecase.NewNodeUsecase,
	usecase.NewModelUsecase,

	NewRAGMQHandler,
	NewRagDocUpdateHandler,  // 重新启用，已添加对应的NATS流
	NewCronHandler,

	wire.Struct(new(MQHandlers), "*"),
)
