package types

import (
	"fmt"

	"github.com/cloudlink-omega/accounts/pkg/bitfield"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

type MailConfig struct {
	Enabled  bool
	Port     int
	Server   string
	Username string
	Password string
}

type EmailArgs struct {
	Subject  string // Subject of email
	To       string // Email address of recipient (to user)
	Nickname string // Nickname of sender (i.e. this server)
}

type Pages struct {
	RouterPath     string
	ServerURL      string
	APIURL         string
	ServerName     string
	PrimaryWebsite string
	Routes         func(fiber.Router)
	ErrorHandler   func(c *fiber.Ctx, err error) error
	Auth           *Auth
}

type Auth struct {
	ServerURL  string
	SessionKey string
}

type APIv0 struct {
	RouterPath   string
	EnforceHTTPS bool
	APIDomain    string
	Routes       func(fiber.Router)
	Auth         *Auth
}

// Claims are custom claims extending default ones
type Claims struct {
	Email            string `json:"email,omitempty"`
	Username         string `json:"username,omitempty"`
	ULID             string `json:"ulid,omitempty"`
	IdentityProvider string `json:"identity_provider,omitempty"`
	jwt.RegisteredClaims
}

type State struct {
	Redirect string `json:"redirect,omitempty"`
	jwt.RegisteredClaims
}

type Provider struct {
	AccountEndpoint string
	UsernameKey     string
	EmailKey        string
	OAuthConfig     *oauth2.Config
}

type Database struct {
	DB *gorm.DB
}

type User struct {
	ID       string             `gorm:"primaryKey;type:char(26);unique;not null"`
	Username string             `gorm:"type:varchar(30)"`
	Password string             `gorm:"type:varchar(255)"`
	Email    string             `gorm:"type:varchar(255)"`
	State    bitfield.Bitfield8 `gorm:"not null;default:0"`

	Google   *UserGoogle     `gorm:"foreignKey:UserID"`
	Discord  *UserDiscord    `gorm:"foreignKey:UserID"`
	GitHub   *UserGitHub     `gorm:"foreignKey:UserID"`
	TOTP     *UserTOTP       `gorm:"foreignKey:UserID"`
	Verify   *Verification   `gorm:"foreignKey:UserID"`
	Recovery []*RecoveryCode `gorm:"foreignKey:UserID"`
}

type UserGoogle struct {
	UserID string `gorm:"primaryKey;type:char(26);unique;not null"`
	ID     string `gorm:"type:varchar(255);unique;not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;"`
}

type UserDiscord struct {
	UserID string `gorm:"primaryKey;type:char(26);unique;not null"`
	ID     string `gorm:"type:varchar(255);unique;not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;"`
}

type UserGitHub struct {
	UserID string `gorm:"primaryKey;type:char(26);unique;not null"`
	ID     string `gorm:"type:varchar(255);unique;not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;"`
}

type UserTOTP struct {
	UserID string `gorm:"primaryKey;type:char(26);unique;not null"`
	Secret string `gorm:"type:varchar(255);not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;"`
}

type Verification struct {
	UserID string `gorm:"primaryKey;type:char(26);unique;not null"`
	Code   string `gorm:"type:char(6);not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;"`
}

type RecoveryCode struct {
	UserID string `gorm:"type:char(26);not null"`
	Code   string `gorm:"type:varchar(50);not null"`

	User User `gorm:"constraint:OnDelete:CASCADE;foreignKey:UserID"`
}

func (u *User) String() string {
	return fmt.Sprintf("[ID: %s, Username: %s, Password: %s, Email: %s, State: %d]", u.ID, u.Username, u.Password, u.Email, u.State)
}
