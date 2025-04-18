package database

import (
	"fmt"

	"github.com/cloudlink-omega/storage/pkg/bitfield"
	"github.com/cloudlink-omega/storage/pkg/types"
	"gorm.io/gorm"
)

func (d *Database) GetUsers() []*types.User {
	var users []*types.User
	d.DB.Find(&users)
	return users
}

func (d *Database) GetUser(id string) *types.User {
	var user types.User
	if err := d.DB.First(&user, "id = ?", id).Error; err != nil {
		return nil
	}
	return &user
}

func (d *Database) UpdateUserState(id string, state bitfield.Bitfield8) error {
	return d.DB.Model(&types.User{}).Where("id = ?", id).Update("state", uint8(state)).Error
}

func (d *Database) UpdateUserPassword(id string, password string) error {
	return d.DB.Model(&types.User{}).Where("id = ?", id).Update("password", password).Error
}

func (d *Database) DoesNameExist(name string) (bool, error) {
	var count int64
	err := d.DB.Model(&types.User{}).Where("username = ?", name).Count(&count).Error
	return count > 0, err
}

func (d *Database) GetUserFromProvider(id string, provider string) (*types.User, error) {
	var user types.User
	var err error

	switch provider {
	case "google":
		err = d.DB.Joins("JOIN user_googles ON users.id = user_googles.user_id").
			Where("user_googles.google_id = ?", id).
			First(&user).Error
	case "discord":
		err = d.DB.Joins("JOIN user_discords ON users.id = user_discords.user_id").
			Where("user_discords.discord_id = ?", id).
			First(&user).Error
	case "github":
		err = d.DB.Joins("JOIN user_git_hubs ON users.id = user_git_hubs.user_id").
			Where("user_git_hubs.git_hub_id = ?", id).
			First(&user).Error
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

func (d *Database) CreateUser(user *types.User) error {
	return d.DB.Create(user).Error
}

func (d *Database) LinkUserToProvider(user string, provider_user string, provider string) error {
	switch provider {
	case "google":
		return d.DB.Create(&types.UserGoogle{UserID: user, GoogleID: provider_user}).Error
	case "discord":
		return d.DB.Create(&types.UserDiscord{UserID: user, DiscordID: provider_user}).Error
	case "github":
		return d.DB.Create(&types.UserGitHub{UserID: user, GitHubID: provider_user}).Error
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (d *Database) GetUserByEmail(email string) (*types.User, error) {
	var user types.User
	if err := d.DB.First(&user, "email = ?", email).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (d *Database) GetSimilarUserByUsername(username string) (*types.User, error) {
	var user types.User
	if err := d.DB.First(&user, "username LIKE ?", username).Error; err != nil {
		if err.Error() == "record not found" {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
