package v0

import (
	"time"

	"github.com/cloudlink-omega/accounts/pkg/authorization"
	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/oklog/ulid/v2"
)

type API struct {
	MailConfig              *structs.MailConfig
	ServerNickname          string
	RouterPath              string
	EnforceHTTPS            bool
	APIDomain               string
	Routes                  func(fiber.Router)
	Auth                    *authorization.Auth
	DB                      *database.Database
	BypassEmailRegistration bool
}

type Credentials struct {
	Token      string `json:"token,omitempty" form:"token,omitempty"`
	Code       string `json:"code,omitempty" form:"code,omitempty"`
	Username   string `json:"username,omitempty" form:"username,omitempty"`
	Email      string `json:"email,omitempty" form:"email,omitempty"`
	Password   string `json:"password,omitempty" form:"password,omitempty"`
	TOTP       string `json:"totp,omitempty" form:"totp,omitempty"`
	BackupCode string `json:"backup_code,omitempty" form:"backup_code,omitempty"`
}

func New(router_path string, enforce_https bool, api_domain string, server_url string, server_secret string, db *database.Database, mail_config *structs.MailConfig, nickname string, bypass_email bool) *API {

	// Create new instance
	v := &API{
		EnforceHTTPS:            enforce_https,
		APIDomain:               api_domain,
		Auth:                    authorization.New(server_url, server_secret, db),
		DB:                      db,
		MailConfig:              mail_config,
		ServerNickname:          nickname,
		BypassEmailRegistration: bypass_email,
	}

	// Configure default handler for endpoints
	v.Routes = func(router fiber.Router) {

		// Configure rate limits. Default to 10 request per 30 seconds with a sliding window.
		router.Use(limiter.New(limiter.Config{
			Max:               10,
			Expiration:        30 * time.Second,
			LimiterMiddleware: limiter.SlidingWindow{},
			LimitReached: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusTooManyRequests).SendString("You're going too damn fast! Please slow down your requests.")
			},
		}))

		// General
		router.Post("/login", v.LoginEndpoint)
		router.Post("/logout", v.LogoutEndpoint)
		router.Post("/register", v.RegisterEndpoint)

		// Verification
		router.Post("/resend-verify", v.ResendVerificationEmail)
		router.Post("/verify", v.VerifyVerificationEmail)
	}

	// Return created instance
	return v
}

func (v *API) CreateSessionToken(c *fiber.Ctx, user *types.User, session_expiry time.Time) (string, error) {
	sessionID := ulid.Make().String()

	// Store the session ID in the database
	err := v.DB.CreateSession(user, sessionID, string(c.Request().Header.Peek("Origin")), string(c.Request().Header.Peek("User-Agent")), c.IP(), session_expiry)
	if err != nil {
		return "", err
	}

	token := v.Auth.Create(&structs.Claims{
		ClaimType:        0,
		SessionID:        sessionID,
		Email:            user.Email,
		Username:         user.Username,
		ULID:             user.ID,
		IdentityProvider: "local",
	}, session_expiry)

	// set session token
	return token, nil
}
