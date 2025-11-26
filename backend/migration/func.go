package migration

import (
	"github.com/chaitin/panda-wiki/migration/fns"
)

type MigrationFuncs struct {
	NodeMigration        *fns.MigrationNodeVersion
	BotAuthMigration     *fns.MigrationCreateBotAuth
	OriginalURLMigration *fns.MigrationAddOriginalURLToNodes
}

func (mf *MigrationFuncs) GetMigrationFuncs() []MigrationFunc {
	funcs := []MigrationFunc{}
	funcs = append(funcs, MigrationFunc{
		Name: mf.NodeMigration.Name,
		Fn:   mf.NodeMigration.Execute,
	})
	funcs = append(funcs, MigrationFunc{
		Name: mf.BotAuthMigration.Name,
		Fn:   mf.BotAuthMigration.Execute,
	})
	funcs = append(funcs, MigrationFunc{
		Name: mf.OriginalURLMigration.Name,
		Fn:   mf.OriginalURLMigration.Execute,
	})
	return funcs
}
