package database

import (
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

type Database struct {
	DB           *gorm.DB // The database connection.
	ServerSecret string   // A 32-byte (256-bit) secret used for encryption/decryption.
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
		&types.UserSession{},
	)
}
