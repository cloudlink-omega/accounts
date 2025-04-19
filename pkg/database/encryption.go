package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Encrypt encrypts the given plaintext using AES-GCM with a key derived from the user's password hash.
// It retrieves the user's password hash based on the provided ULID, truncates it to the first 32 bytes,
// and uses it to create an AES cipher. The plaintext is encrypted with a randomly generated nonce, and
// the resulting ciphertext is base64 encoded.
//
// Parameters:
//   - ulid: The unique user identifier used to retrieve the user's password hash.
//   - plaintext: The text to be encrypted.
//
// Returns:
//   - A base64 encoded string of the encrypted data.
//   - An error if any issue arises during encryption.
func (d *Database) Encrypt(ulid string, plaintext string) (string, error) {

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
		return "", err
	}

	// Set up GCM for encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Finally, encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encrypted_secret := base64.StdEncoding.EncodeToString(ciphertext)

	return encrypted_secret, nil
}

// Decrypts a given encrypted secret using AES-GCM encryption and the user's password hash.
//
// Parameters:
//   - ulid: The unique user identifier used to retrieve the user's password hash.
//   - encrypted_secret: The text to be decrypted.
//
// Returns:
//   - A plaintext string of the decrypted data.
//   - An error if any issue arises during decryption.
func (d *Database) Decrypt(ulid string, encrypted_secret string) (string, error) {

	// Decode the encrypted secret
	secret_decoded, err := base64.StdEncoding.DecodeString(encrypted_secret)
	if err != nil {
		return "", err
	}

	// Read the user's password hash
	user := d.GetUser(ulid)
	if user == nil {
		return "", errors.New("user not found while trying to retrieve password hash")
	}

	// Make sure the user has a password hash
	if len(user.Password) == 0 {
		return "", errors.New("user has no password hash (is the user using OAuth?)")
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
		return "", err
	}

	return string(secret), nil
}
