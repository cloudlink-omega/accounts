package database

import "github.com/cloudlink-omega/accounts/pkg/types"

type Database types.Database

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
