package database

import "github.com/cloudlink-omega/storage/pkg/types"

func (d *Database) StoreRecoveryCodes(user string, codes []string) error {
	var entries []*types.RecoveryCode
	for _, code := range codes {
		entries = append(entries, &types.RecoveryCode{
			UserID: user,
			Code:   code,
		})
	}

	// Optional: delete existing codes for the user first
	if err := d.DB.Where("user_id = ?", user).Delete(&types.RecoveryCode{}).Error; err != nil {
		return err
	}

	return d.DB.Create(&entries).Error
}
