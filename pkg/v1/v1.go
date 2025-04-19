package v1

import (
	"time"

	"github.com/cloudlink-omega/accounts/pkg/authorization"
	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

type API struct {
	MailConfig     *structs.MailConfig
	ServerNickname string
	RouterPath     string
	EnforceHTTPS   bool
	APIDomain      string
	Routes         func(fiber.Router)
	Auth           *authorization.Auth
	DB             *database.Database
}

type ValidationData struct {
	VerifiedEmail bool `json:"verified_email"`
	*structs.Claims
}

type Credentials struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTP       string `json:"totp"`
	BackupCode string `json:"backup_code"`
}

type Result struct {
	Token  string `json:"token,omitempty"`
	Data   any    `json:"data,omitempty"`
	Result string `json:"result"`
}

func New(router_path string, enforce_https bool, api_domain string, server_url string, session_key string, db *database.Database, mail_config *structs.MailConfig, nickname string) *API {

	// Create new instance
	v := &API{
		EnforceHTTPS:   enforce_https,
		APIDomain:      api_domain,
		Auth:           authorization.New(server_url, session_key, db),
		DB:             db,
		MailConfig:     mail_config,
		ServerNickname: nickname,
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
		router.Get("/check", v.UsernameChecker)

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

func APIResult(c *fiber.Ctx, status int, result string, data any) error {
	c.Set("Content-Type", "application/json")
	c.SendStatus(status)
	message, _ := json.Marshal(&Result{Result: result, Data: data})
	return c.SendString(string(message))
}
