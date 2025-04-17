package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

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

	// Read the user's password hash
	user := d.GetUser(ulid)
	if user == nil {
		panic("user not found while trying to retrieve password hash")
	}

	// Make sure the user has a password hash
	if len(user.Password) == 0 {
		panic("user has no password hash (is the user using OAuth?)")
	}

	// Truncate the hash to first 32 bytes (256 bits)
	hash_trunc := []byte(user.Password[:32])

	// Convert bytes into a AES cipher
	block, err := aes.NewCipher(hash_trunc)
	if err != nil {
		panic(err)
	}

	// Set up GCM for encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Finally, encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(key), nil)
	secret := base64.StdEncoding.EncodeToString(ciphertext)

	// Store encrypted secret in the database
	if err := d.store_secret(ulid, secret); err != nil {
		panic(err)
	}
}

// Decrypts and returns the user's TOTP secret based on AES-GCM encryptuion using the user's password hash
func (d *Database) GetTotpSecret(ulid string) string {

	// Get secret
	encrypted_secret, err := d.get_secret(ulid)
	if err != nil {
		panic(err)
	}

	// Decode the encrypted secret
	secret_decoded, err := base64.StdEncoding.DecodeString(encrypted_secret)
	if err != nil {
		panic(err)
	}

	// Read the user's password hash
	user := d.GetUser(ulid)
	if user == nil {
		panic("user not found while trying to retrieve password hash")
	}

	// Make sure the user has a password hash
	if len(user.Password) == 0 {
		panic("user has no password hash (is the user using OAuth?)")
	}

	// Truncate the hash to first 32 bytes (256 bits)
	hash_trunc := []byte(user.Password[:32])

	// Convert bytes into a AES cipher
	block, err := aes.NewCipher(hash_trunc)
	if err != nil {
		panic(err)
	}

	// Set up GCM for decryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Extract the nonce from the beginning of the ciphertext (12 bytes for AES-GCM)
	nonceSize := gcm.NonceSize()
	if len(secret_decoded) < nonceSize {
		panic("ciphertext is too short to contain a valid nonce")
	}
	nonce, ciphertext := secret_decoded[:nonceSize], secret_decoded[nonceSize:]

	// Decrypt the secret
	secret, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	return string(secret)
}
