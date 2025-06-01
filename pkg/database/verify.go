package database

import (
	"errors"
	"time"

	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

func (d *Database) AddVerificationCode(user string, code string, expires time.Time) error {
	vc := &types.Verification{
		UserID:    user,
		Code:      code,
		ExpiresAt: expires,
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

	if vc.ExpiresAt.Before(time.Now()) {
		d.DB.Where("user_id = ? AND code = ?", user, code).Delete(&types.Verification{})
		return false, nil
	}

	return true, nil
}

func (d *Database) GetVerificationCode(user string) (string, error) {
	var vc *types.Verification
	res := d.DB.
		Where("user_id = ?", user).
		First(&vc)

	if res.Error == gorm.ErrRecordNotFound {
		return "", nil
	}

	if res.Error != nil {
		return "", res.Error
	}

	// Renew the expiration time
	vc.ExpiresAt = time.Now().Add(time.Minute * 15)
	d.DB.Save(&vc)

	return vc.Code, nil
}

func (d *Database) DeleteVerificationCodes(user string) error {
	return d.DB.
		Where("user_id = ?", user).
		Delete(&types.Verification{}).Error
}
