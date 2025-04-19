package database

import "github.com/cloudlink-omega/storage/pkg/types"

// StoreRecoveryCodes stores a list of recovery codes for a given user in the database. It encrypts each code
// before storing it. If the user already has recovery codes stored, this function will delete them first before
// writing the new ones. If an error occurs while encrypting or writing the codes to the database, it will be returned.
func (d *Database) StoreRecoveryCodes(user string, codes []string) error {
	var entries []*types.RecoveryCode
	for _, code := range codes {

		// Encrypt each recovery code
		encrypted, err := d.Encrypt(user, code)
		if err != nil {
			return err
		}

		// Create a new entry
		entries = append(entries, &types.RecoveryCode{
			UserID: user,
			Code:   encrypted,
		})
	}

	// Optional: delete existing codes for the user first
	if err := d.DB.Where("user_id = ?", user).Delete(&types.RecoveryCode{}).Error; err != nil {
		return err
	}

	return d.DB.Create(&entries).Error
}

// GetRecoveryCodes retrieves all recovery codes for a given user from the database.
// Each code is decrypted before being returned to the caller.
// If the user does not have any recovery codes, an empty slice is returned.
// If an error occurs while retrieving or decrypting the codes, the error is returned.
func (d *Database) GetRecoveryCodes(user string) ([]string, error) {
	var entries []*types.RecoveryCode
	if err := d.DB.Where("user_id = ?", user).Find(&entries).Error; err != nil {
		return nil, err
	}

	// Decrypt each recovery code
	for i, entry := range entries {
		decrypted, err := d.Decrypt(user, entry.Code)
		if err != nil {
			return nil, err
		}
		entries[i].Code = decrypted
	}

	var codes []string
	for _, entry := range entries {
		codes = append(codes, entry.Code)
	}

	return codes, nil
}
