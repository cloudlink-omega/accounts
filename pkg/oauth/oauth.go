package oauth

import (
	"git.mikedev101.cc/MikeDEV/accounts/pkg/authorization"
	"git.mikedev101.cc/MikeDEV/accounts/pkg/database"
	"git.mikedev101.cc/MikeDEV/accounts/pkg/types"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuth struct {
	RouterPath   string
	APIDomain    string
	EnforceHTTPS bool
	Providers    map[string]*types.Provider
	ServerURL    string
	Routes       func(fiber.Router)
	Auth         *authorization.Auth
	DB           *database.Database
}

func New(router_path string, server_url string, enforce_https bool, api_domain string, session_key string, db *database.Database) *OAuth {

	// Create new instance
	s := &OAuth{
		RouterPath:   router_path,
		Providers:    make(map[string]*types.Provider),
		ServerURL:    server_url,
		EnforceHTTPS: enforce_https,
		APIDomain:    api_domain,
		Auth:         authorization.New(server_url, session_key, db),
		DB:           db,
	}

	// Configure default handler for OAuth endpoints
	s.Routes = func(router fiber.Router) {
		router.Get("/:provider", s.begin_oauth_flow)
		router.Get("/:provider/callback", s.callback_oauth_flow)
	}

	// Return created instance
	return s
}

func (s *OAuth) Discord(client_id string, client_secret string) {
	s.create_oauth_provider(
		"discord",
		client_id,
		client_secret,
		[]string{"identify", "email"},
		"https://discord.com/api/users/@me",
		"username",
		"email",
		oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	)
}

func (s *OAuth) Google(client_id string, client_secret string) {
	s.create_oauth_provider(
		"google",
		client_id,
		client_secret,
		[]string{"profile", "email"},
		"https://www.googleapis.com/oauth2/v1/userinfo",
		"name",
		"email",
		google.Endpoint,
	)
}

func (s *OAuth) GitHub(client_id string, client_secret string) {
	s.create_oauth_provider(
		"github",
		client_id,
		client_secret,
		[]string{"read:user", "user:email"},
		"https://api.github.com/user",
		"name",
		"email",
		oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	)
}

func (s *OAuth) create_oauth_provider(provider string, client_id string, client_secret string, scopes []string, userapi string, usernamekey string, emailkey string, endpoint oauth2.Endpoint) {
	s.Providers[provider] = &types.Provider{
		AccountEndpoint: userapi,
		UsernameKey:     usernamekey,
		EmailKey:        emailkey,
		OAuthConfig: &oauth2.Config{
			ClientID:     client_id,
			ClientSecret: client_secret,
			Scopes:       scopes,
			Endpoint:     endpoint,
		},
	}
}
