package database

import (
	"errors"

	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

func (d *Database) AddVerificationCode(user string, code string) error {
	vc := &types.Verification{
		UserID: user,
		Code:   code,
	}
	return d.DB.Create(&vc).Error
}

func (d *Database) VerifyCode(user string, code string) (bool, error) {
	var vc types.Verification
	err := d.DB.
		Where("user_id = ? AND code = ?", user, code).
		First(&vc).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (d *Database) DeleteVerificationCode(user string, code string) error {
	return d.DB.
		Where("user_id = ? AND code = ?", user, code).
		Delete(&types.Verification{}).Error
}
