package database

import (
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

type Database struct {
	DB *gorm.DB
}

func (d *Database) RunMigrations() error {
	return d.DB.AutoMigrate(
		&types.User{},
		&types.Verification{},
		&types.RecoveryCode{},
		&types.UserGoogle{},
		&types.UserDiscord{},
		&types.UserGitHub{},
		&types.UserTOTP{},
	)
}
