package database

import (
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

type Database struct {
	DB           *gorm.DB // The database connection.
	ServerSecret string   // A 32-byte (256-bit) secret used for encryption/decryption.
	Cache        *types.DBCache
}
