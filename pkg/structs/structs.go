package structs

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
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
	ClaimType        uint8  `json:"claim_type"`
	SessionID        string `json:"session_id,omitempty"`
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
