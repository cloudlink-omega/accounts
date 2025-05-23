package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/cloudlink-omega/storage/pkg/types"
	"golang.org/x/crypto/argon2"
)

const (
	argon2Iterations  = 2
	argon2Memory      = 64 * 1024
	argon2Parallelism = 4
	argon2KeySize     = 32
)

// deriveKey generates a 256-bit key using the Argon2ID key derivation function.
// It combines the user's secret and the server's secret to produce a secure key.
//
// Parameters:
//   - userSecret: The user's secret in byte slice form.
//
// Returns:
//   - A binary slice representing a derived 256-bit key suitable for AES-256 encryption.
func (d *Database) deriveKey(userSecret []byte) []byte {
	return argon2.IDKey(userSecret, []byte(d.ServerSecret), argon2Iterations, argon2Memory, argon2Parallelism, argon2KeySize)
}

// CreateUserSecret generates a new 256-bit random secret for a user,
// encrypts it using AES-GCM with the server's secret, and returns
// the encrypted secret as a base64 encoded string. Returns an error
// if there is an issue generating the random secret.
func (d *Database) CreateUserSecret() (string, error) {
	// Generate a 256-bit random secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	// Read the server's secret
	server_secret_decoded, err := base64.StdEncoding.DecodeString(d.ServerSecret)
	if err != nil {
		return "", err
	}

	// Encrypt the user secret with the server's secret
	return MustEncrypt(string(secret), server_secret_decoded), nil
}

// Encrypt encrypts the given plaintext using AES-GCM with a key derived from the user's secret.
// It retrieves the user's secret based on the provided ULID, truncates it to the first 32 bytes,
// and uses it to create an AES cipher. The plaintext is encrypted with a randomly generated nonce, and
// the resulting ciphertext is base64 encoded.
//
// Parameters:
//   - ulid: The unique user identifier used to retrieve the user's secret.
//   - plaintext: The text to be encrypted.
//
// Returns:
//   - A base64 encoded string of the encrypted data.
//   - An error if any issue arises during encryption.
func (d *Database) Encrypt(user *types.User, plaintext string) (string, error) {

	// Read the user's secret
	if user == nil {
		panic("user nil while trying to retrieve secret")
	}

	// Make sure the user has a secret
	if len(user.Secret) == 0 {
		panic("user has no secret")
	}

	server_secret_decoded, err := base64.StdEncoding.DecodeString(d.ServerSecret)
	if err != nil {
		panic(err)
	}
	decodedSecret := MustDecrypt(user.Secret, server_secret_decoded)
	key := d.deriveKey([]byte(decodedSecret))

	return MustEncrypt(plaintext, key), nil
}

// MustEncrypt encrypts the given plaintext using AES-GCM encryption with a key derived from the
// encoded key. The key is expected to be the base64 encoded server secret key, or a Argon2ID derived key.
//
// This function panics if there is an issue with the key, or if there is an issue with the
// encryption process.
//
// Parameters:
//   - plaintext: The text to be encrypted.
//   - encoded_key: The base64 encoded server secret key.
//
// Returns:
//   - A base64 encoded string of the encrypted data.
func MustEncrypt(plaintext string, key []byte) string {

	// Convert bytes into a AES cipher
	block, err := aes.NewCipher(key)
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

	// Finally, encrypt and encode
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypts a given encrypted secret using AES-GCM encryption and the user's secret.
//
// Parameters:
//   - ulid: The unique user identifier used to retrieve the user's secret.
//   - encrypted_secret: The text to be decrypted.
//
// Returns:
//   - A plaintext string of the decrypted data.
//   - An error if any issue arises during decryption.
func (d *Database) Decrypt(user *types.User, encrypted_secret string) (string, error) {

	// Read the user's secret
	if user == nil {
		panic("user nil while trying to retrieve secret")
	}

	// Make sure the user has a secret
	if len(user.Secret) == 0 {
		return "", errors.New("user has no secret")
	}

	server_secret_decoded, err := base64.StdEncoding.DecodeString(d.ServerSecret)
	if err != nil {
		panic(err)
	}
	decodedSecret := MustDecrypt(user.Secret, server_secret_decoded)
	key := d.deriveKey([]byte(decodedSecret))

	return MustDecrypt(encrypted_secret, key), nil
}

// MustDecrypt decrypts an encrypted secret using AES-GCM with a key derived from
// the server's secret or an Argon2ID derived key. The function expects the
// encrypted secret and the encoded key as base64 encoded strings. It panics if
// any errors occur during the decryption process, such as decoding failures,
// cipher setup issues, or decryption errors.
//
// Parameters:
//   - encrypted_secret: The base64 encoded encrypted data to be decrypted.
//   - encoded_key: The base64 encoded key used for decryption.
//
// Returns:
//   - The decrypted plaintext as a string.
func MustDecrypt(encrypted_secret string, key []byte) string {

	// Decode the encrypted secret
	secret_decoded, err := base64.StdEncoding.DecodeString(encrypted_secret)
	if err != nil {
		panic(err)
	}

	// Convert bytes into a AES cipher
	block, err := aes.NewCipher(key)
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
