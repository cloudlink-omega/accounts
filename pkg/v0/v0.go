package v0

import (
	"github.com/cloudlink-omega/accounts/pkg/authorization"
	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/cloudlink-omega/accounts/pkg/types"
	"github.com/gofiber/fiber/v2"
)

type APIv0 struct {
	MailConfig     *types.MailConfig
	ServerNickname string
	RouterPath     string
	EnforceHTTPS   bool
	APIDomain      string
	Routes         func(fiber.Router)
	Auth           *authorization.Auth
	DB             *database.Database
}

func New(router_path string, enforce_https bool, api_domain string, server_url string, session_key string, db *database.Database, mail_config *types.MailConfig, nickname string) *APIv0 {

	// Create new instance
	v := &APIv0{
		EnforceHTTPS:   enforce_https,
		APIDomain:      api_domain,
		Auth:           authorization.New(server_url, session_key, db),
		DB:             db,
		MailConfig:     mail_config,
		ServerNickname: nickname,
	}

	// Configure default handler for OAuth endpoints
	v.Routes = func(router fiber.Router) {
		router.Post("/login", v.LoginEndpoint)
		router.Post("/register", v.RegisterEndpoint)
		router.Get("/logout", v.LogoutEndpoint)
		router.Get("/verify", v.VerifyEndpoint)
		router.Get("/validate", v.ValidateEndpoint)
		router.Get("/check", v.UsernameChecker)
		router.Get("/begin-totp-enrollment", v.EnrollTotpEndpoint)
		router.Get("/verify-totp-enrollment", v.VerifyTotpEndpoint)
	}

	// Return created instance
	return v
}
