package database

import (
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm/clause"
)

func (d *Database) store_secret(user string, secret string) error {
	totp := types.UserTOTP{
		UserID: user,
		Secret: secret,
	}
	// insert or update
	return d.DB.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&totp).Error
}

func (d *Database) get_secret(user string) (string, error) {
	var totp types.UserTOTP
	err := d.DB.First(&totp, "user_id = ?", user).Error
	if err != nil {
		return "", err
	}
	return totp.Secret, nil
}

// Encrypts and stores the user's TOTP secret using AES-GCM encryption and the user's password hash.
func (d *Database) StoreTotpSecret(ulid string, key string) {

	// Encrypt secret
	secret, err := d.Encrypt(ulid, key)
	if err != nil {
		panic(err)
	}

	// Store encrypted secret in the database
	if err := d.store_secret(ulid, secret); err != nil {
		panic(err)
	}
}

// Decrypts and returns the user's TOTP secret based on AES-GCM encryptuion using the user's password hash
func (d *Database) GetTotpSecret(ulid string) string {

	// Get ecrypted secret
	encrypted_secret, err := d.get_secret(ulid)
	if err != nil {
		panic(err)
	}

	// Decrypt
	secret, err := d.Decrypt(ulid, encrypted_secret)
	if err != nil {
		panic(err)
	}

	return string(secret)
}
