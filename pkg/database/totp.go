package database

import (
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm/clause"
)

func (d *Database) store_secret(id string, secret string) error {
	totp := types.UserTOTP{
		UserID: id,
		Secret: secret,
	}
	// insert or update
	return d.DB.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&totp).Error
}

func (d *Database) get_secret(id string) (string, error) {
	var totp types.UserTOTP
	err := d.DB.First(&totp, "user_id = ?", id).Error
	if err != nil {
		return "", err
	}
	return totp.Secret, nil
}

// Encrypts and stores the user's TOTP secret using AES-GCM encryption and the user's password hash.
func (d *Database) StoreTotpSecret(user *types.User, key string) {
	if user == nil {
		panic("user nil while trying to store totp secret")
	}

	// Encrypt secret
	secret, err := d.Encrypt(user, key)
	if err != nil {
		panic(err)
	}

	// Store encrypted secret in the database
	if err := d.store_secret(user.ID, secret); err != nil {
		panic(err)
	}
}

// Decrypts and returns the user's TOTP secret based on AES-GCM encryptuion using the user's password hash
func (d *Database) GetTotpSecret(user *types.User) string {
	if user == nil {
		panic("user nil while trying to retrieve totp secret")
	}

	// Get ecrypted secret
	encrypted_secret, err := d.get_secret(user.ID)
	if err != nil {
		panic(err)
	}

	// Decrypt
	secret, err := d.Decrypt(user, encrypted_secret)
	if err != nil {
		panic(err)
	}

	return string(secret)
}
