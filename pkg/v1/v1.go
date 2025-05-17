package v1

import (
	"time"

	"github.com/cloudlink-omega/accounts/pkg/authorization"
	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/goccy/go-json"
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

type ValidationData struct {
	VerifiedEmail bool `json:"verified_email"`
	*structs.Claims
}

type Credentials struct {
	Username   string `json:"username" form:"username"`
	Email      string `json:"email" form:"email"`
	Password   string `json:"password" form:"password"`
	TOTP       string `json:"totp" form:"totp"`
	BackupCode string `json:"backup_code" form:"backup_code"`
}

type Result struct {
	Token   string `json:"token,omitempty"`
	Data    any    `json:"data,omitempty"`
	Result  string `json:"result"`
	EventID string `json:"error_id,omitempty"`
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
				return APIResult(c, fiber.StatusTooManyRequests, "You're going too damn fast! Please slow down your requests.", nil)
			},
		}))

		// General
		router.Post("/login", v.LoginEndpoint)
		router.Get("/logout", v.LogoutEndpoint)
		router.Post("/register", v.RegisterEndpoint)
		router.Post("/reset-password", v.ResetPasswordEndpoint)

		// Verification
		router.Post("/resend-verify", v.ResendVerificationEmail)
		router.Get("/verify", v.VerifyVerificationEmail)

		// Utilities
		router.Get("/validate", v.ValidateEndpoint)
		router.Post("/check", v.UsernameChecker)

		// TOTP setup
		router.Get("/begin-totp-enrollment", v.EnrollTotpEndpoint)
		router.Get("/verify-totp-enrollment", v.VerifyTotpEndpoint)

		// Recover account
		router.Post("/send-recovery", v.SendRecoveryEmail)
		router.Post("/confirm-recovery", v.ConfirmRecoveryEmail)
	}

	// Return created instance
	return v
}

func APIResult(c *fiber.Ctx, status int, result string, data any, event_id ...string) error {
	c.Set("Content-Type", "application/json")
	c.SendStatus(status)

	if len(event_id) > 0 && event_id[0] != "" {
		message, _ := json.Marshal(&Result{Result: result, Data: data, EventID: event_id[0]})
		return c.SendString(string(message))
	}

	message, _ := json.Marshal(&Result{Result: result, Data: data})
	return c.SendString(string(message))
}

func (v *API) CreateSession(c *fiber.Ctx, user *types.User, session_expiry time.Time) error {
	sessionID := ulid.Make()

	// Store the session ID in the database
	err := v.DB.CreateSession(user, sessionID.String(), string(c.Request().Header.Peek("Origin")), string(c.Request().Header.Peek("User-Agent")), c.IP(), session_expiry)
	if err != nil {
		return err
	}
	v.SetCookie(user, sessionID.String(), session_expiry, c)
	return nil
}
