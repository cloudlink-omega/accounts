package database

import (
	"gorm.io/gorm"
)

type Database struct {
	DB           *gorm.DB // The database connection.
	ServerSecret string   // A 32-byte (256-bit) secret used for encryption/decryption.
}
