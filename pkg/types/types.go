package types

import (
	"database/sql"
	"fmt"

	"github.com/cloudlink-omega/accounts/pkg/bitfield"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/huandu/go-sqlbuilder"
	"golang.org/x/oauth2"
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
	DB     *sql.DB
	Flavor sqlbuilder.Flavor
}

type User struct {
	ID       string // ulid
	Username string
	Password string // scrypt
	Email    string
	State    bitfield.Bitfield8 // bitfield
}

func (u *User) String() string {
	return fmt.Sprintf("[ID: %s, Username: %s, Password: %s, Email: %s, State: %d]", u.ID, u.Username, u.Password, u.Email, u.State)
}
