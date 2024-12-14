package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"git.mikedev101.cc/MikeDEV/accounts/pkg/sanitizer"
	"git.mikedev101.cc/MikeDEV/accounts/pkg/types"
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
	if s.Auth.Valid(c) {
		params := url.Values{}
		params.Add("redirect", redirect)
		return c.Redirect(fmt.Sprintf("%s?%s", s.RouterPath, params.Encode()), http.StatusSeeOther)
	}

	// Create state JWT that will expire in half an hour
	expiration := time.Now().Add(30 * time.Minute)
	state := s.Auth.Create(&types.State{Redirect: redirect}, expiration)

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
	var api_user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&api_user); err != nil {
		panic(err)
	}

	// Consult with the database
	user, err := s.DB.GetUserFromProvider(api_user["id"].(string), identity_provider)
	if err != nil {

		userid := ulid.Make()
		user = &types.User{
			ID:       userid.String(),
			Username: api_user[provider.UsernameKey].(string),
			Email:    api_user[provider.EmailKey].(string),
			State:    0,
		}

		if err := s.DB.CreateUser(user); err != nil {
			panic(fmt.Errorf("failed to create user: %w", err))
		}

		if err := s.DB.LinkUserToProvider(api_user["id"].(string), userid.String(), identity_provider); err != nil {
			panic(fmt.Errorf("failed to link user: %w", err))
		}
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	expiration := time.Now().Add(24 * time.Hour)
	token := s.Auth.Create(&types.Claims{
		Email:            user.Email,
		Username:         user.Username,
		ULID:             ulid.MustParse(user.ID),
		IdentityProvider: identity_provider,
	}, expiration)

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Value:    token,
		Expires:  expiration,
		HTTPOnly: true, // Set to true so JavaScript can't access the cookie
		Secure:   s.EnforceHTTPS,
		Path:     "/",
	})

	// Handle redirect
	if state_data.Redirect != "" {

		// Return to the the root page with the redirect parameter so the user is aware of the successful login
		return c.Redirect(fmt.Sprintf("%s%s?redirect=%s", s.ServerURL, s.RouterPath, state_data.Redirect), fiber.StatusSeeOther)
	}

	// Redirect to root
	return c.Redirect(fmt.Sprintf("%s%s", s.ServerURL, s.RouterPath), fiber.StatusSeeOther)
}
