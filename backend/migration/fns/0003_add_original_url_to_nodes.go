package fns

import (
	"context"

	"gorm.io/gorm"

	"github.com/chaitin/panda-wiki/log"
)

type MigrationAddOriginalURLToNodes struct {
	Name   string
	logger *log.Logger
}

func NewMigrationAddOriginalURLToNodes(logger *log.Logger) *MigrationAddOriginalURLToNodes {
	return &MigrationAddOriginalURLToNodes{
		Name:   "0003_add_original_url_to_nodes",
		logger: logger,
	}
}

func (m *MigrationAddOriginalURLToNodes) Execute(tx *gorm.DB) error {
	ctx := context.Background()

	// 为 nodes 表添加 original_url 字段
	if !tx.Migrator().HasColumn(&struct {
		TableName string `gorm:"table:nodes"`
	}{}, "original_url") {
		if err := tx.WithContext(ctx).Exec(`
			ALTER TABLE nodes ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';
		`).Error; err != nil {
			m.logger.Error("failed to add original_url column to nodes table", log.Error(err))
			return err
		}
		m.logger.Info("added original_url column to nodes table")
	}

	// 为 node_releases 表添加 original_url 字段
	if !tx.Migrator().HasColumn(&struct {
		TableName string `gorm:"table:node_releases"`
	}{}, "original_url") {
		if err := tx.WithContext(ctx).Exec(`
			ALTER TABLE node_releases ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';
		`).Error; err != nil {
			m.logger.Error("failed to add original_url column to node_releases table", log.Error(err))
			return err
		}
		m.logger.Info("added original_url column to node_releases table")
	}

	m.logger.Info("original_url migration completed successfully")
	return nil
}
