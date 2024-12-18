package v0

import (
	"github.com/cloudlink-omega/accounts/pkg/authorization"
	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/gofiber/fiber/v2"
)

type APIv0 struct {
	RouterPath   string
	EnforceHTTPS bool
	APIDomain    string
	Routes       func(fiber.Router)
	Auth         *authorization.Auth
	DB           *database.Database
}

func New(router_path string, enforce_https bool, api_domain string, server_url string, session_key string, db *database.Database) *APIv0 {

	// Create new instance
	v := &APIv0{
		EnforceHTTPS: enforce_https,
		APIDomain:    api_domain,
		Auth:         authorization.New(server_url, session_key, db),
		DB:           db,
	}

	// Configure default handler for OAuth endpoints
	v.Routes = func(router fiber.Router) {
		router.Post("/login", v.LoginEndpoint)
		router.Post("/register", v.RegisterEndpoint)
		router.Get("/logout", v.LogoutEndpoint)
		router.Get("/validate", v.ValidateEndpoint)
		router.Get("/check", v.UsernameChecker)
	}

	// Return created instance
	return v
}
