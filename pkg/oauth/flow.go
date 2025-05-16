package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2/log"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/bitfield"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid/v2"
	"golang.org/x/oauth2"
)

func (s *OAuth) begin_oauth_flow(c *fiber.Ctx) error {
	identity_provider := c.Params("provider")

	provider, ok := s.Providers[identity_provider]
	if !ok {
		panic(fmt.Sprintf("provider %s not found or implemented", identity_provider))
	}

	// Generate RedirectURL for the provider config
	path := s.ServerURL
	for _, n := range []string{s.RouterPath, "oauth", identity_provider, "callback"} {
		path += n + "/"
	}

	provider.OAuthConfig.RedirectURL = path

	// Read redirect URL from request query parameters
	redirect := sanitizer.Sanitized(c, c.Query("redirect"))

	// Check if the user is already logged in. If so, redirect to the secure page
	if s.Auth.ValidFromNormal(c) {
		params := url.Values{}
		params.Add("redirect", redirect)
		return c.Redirect(fmt.Sprintf("%s?%s", s.ServerURL, params.Encode()), http.StatusSeeOther)
	}

	// Create state JWT that will expire in half an hour
	expiration := time.Now().Add(30 * time.Minute)
	state := s.Auth.Create(&structs.State{Redirect: redirect}, expiration)

	// Redirect to the OAuth provider
	return c.Redirect(provider.OAuthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
	), fiber.StatusTemporaryRedirect)
}

func (s *OAuth) callback_oauth_flow(c *fiber.Ctx) error {
	identity_provider := c.Params("provider")

	provider, ok := s.Providers[identity_provider]
	if !ok {
		panic(fmt.Sprintf("provider %s not found or implemented", identity_provider))
	}

	// Read oauth code and state
	code := c.Query("code")
	state := c.Query("state")

	// Check if authorization code is present
	if code == "" {
		return c.Status(fiber.StatusBadRequest).SendString("code required")
	}

	// Read state JWT
	state_data, state_err := s.Auth.GetState(state)
	if state_err != nil {
		return state_err
	}

	// Begin token exchange
	otoken, err := provider.OAuthConfig.Exchange(c.Context(), code)
	if err != nil {
		panic(err)
	}

	// Read user info from token
	client := provider.OAuthConfig.Client(c.Context(), otoken)
	resp, err := client.Get(provider.AccountEndpoint)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	var api_user map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&api_user); err != nil {
		panic(err)
	}

	// Consult with the database
	var provider_id string
	switch api_user["id"].(type) {
	case string:
		provider_id = api_user["id"].(string)
	default:
		provider_id = fmt.Sprintf("%v", api_user["id"])
	}

	// Try to find an existing user based on the provider
	log.Debug("Trying to find user based on provider ", identity_provider)
	user, err := s.DB.GetUserFromProvider(provider_id, identity_provider)
	if err != nil {
		panic(err)
	}

	// Try to find an existing user based on the email address
	if user == nil {
		log.Debug("Didn't find an existing user, trying to find by email")
		user, err = s.DB.GetUserByEmail(api_user[provider.EmailKey].(string))
		if err != nil {
			panic(err)
		}

		if user != nil {
			log.Debug("Found a match, going to link user to provider")
			if err := s.DB.LinkUserToProvider(user.ID, provider_id, identity_provider); err != nil {
				panic(fmt.Errorf("failed to link user: %w", err))
			}
		}
	}

	// Create a new user if neither of the above worked
	if user == nil {
		log.Debug("Creating user")
		user_id := ulid.Make()
		var state bitfield.Bitfield8
		state.Set(constants.USER_IS_EMAIL_REGISTERED)
		state.Set(constants.USER_IS_ACTIVE)
		state.Set(constants.USER_IS_OAUTH_ONLY)

		// Create a 256-bit random secret key that's encrypted with the server's secret key.
		userSecret, err := s.DB.CreateUserSecret()
		if err != nil {
			panic(fmt.Errorf("failed to create user secret: %w", err))
		}

		user = &types.User{
			ID:       user_id.String(),
			Username: api_user[provider.UsernameKey].(string),
			Email:    api_user[provider.EmailKey].(string),
			State:    state,
			Secret:   userSecret,
		}

		if err := s.DB.CreateUser(user); err != nil {
			panic(fmt.Errorf("failed to create user: %w", err))
		}

		if err := s.DB.LinkUserToProvider(user_id.String(), provider_id, identity_provider); err != nil {
			panic(fmt.Errorf("failed to link user: %w", err))
		}

		log.Debug("User created")

	} else {
		log.Debug("Found user")
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	if err := s.CreateSession(c, user, identity_provider, time.Now().Add(24*time.Hour)); err != nil {
		panic(err)
	}

	// Handle redirect
	if state_data.Redirect != "" {

		// Return to the the root page with the redirect parameter so the user is aware of the successful login
		return c.Redirect(fmt.Sprintf("%s%s?redirect=%s", s.ServerURL, s.RouterPath, state_data.Redirect), fiber.StatusSeeOther)
	}

	// Redirect to root
	return c.Redirect(fmt.Sprintf("%s%s", s.ServerURL, s.RouterPath), fiber.StatusSeeOther)
}
