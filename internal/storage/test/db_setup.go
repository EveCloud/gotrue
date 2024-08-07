package test

import (
	"github.com/evecloud/auth/internal/conf"
	"github.com/evecloud/auth/internal/storage"
)

func SetupDBConnection(globalConfig *conf.GlobalConfiguration) (*storage.Connection, error) {
	return storage.Dial(globalConfig)
}
