package v0

import (
	"time"

	"git.mikedev101.cc/MikeDEV/accounts/pkg/types"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid/v2"
)

func (v *APIv0) LoginEndpoint(c *fiber.Ctx) error {
	// TODO: Do something with the form data

	// Consult with the database
	/*user, err := v.DB.GetUserFromProvider(api_user["id"].(string), identity_provider)
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

	*/

	if c.FormValue("totp") == "" {
		c.Status(fiber.ErrBadRequest.Code)
		return c.SendString("totp required")
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	expiration := time.Now().Add(24 * time.Hour)
	token := v.Auth.Create(&types.Claims{
		Email:            c.FormValue("email"),
		Username:         c.FormValue("email"),
		ULID:             ulid.Make(),
		IdentityProvider: "local",
	}, expiration)

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Value:    token,
		Expires:  expiration,
		HTTPOnly: true, // Set to true so JavaScript can't access the cookie
		Secure:   v.EnforceHTTPS,
		SameSite: fiber.CookieSameSiteLaxMode,
		Domain:   v.APIDomain,
	})

	// Return "OK"
	return c.SendString("OK")
}

func (v *APIv0) RegisterEndpoint(c *fiber.Ctx) error {

	/*c.FormValue("email")
	c.FormValue("password")*/

	// Create a new JWT for this user. Session expires in 24 hours.
	expiration := time.Now().Add(24 * time.Hour)
	token := v.Auth.Create(&types.Claims{
		Email:            c.FormValue("email"),
		Username:         c.FormValue("email"),
		ULID:             ulid.Make(),
		IdentityProvider: "local",
	}, expiration)

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Value:    token,
		Expires:  expiration,
		HTTPOnly: true, // Set to true so JavaScript can't access the cookie
		Secure:   v.EnforceHTTPS,
		SameSite: fiber.CookieSameSiteLaxMode,
		Domain:   v.APIDomain,
	})

	// Return "OK"
	return c.SendString("OK")
}

func (v *APIv0) LogoutEndpoint(c *fiber.Ctx) error {

	// Check if the user is already logged out. If so, tell them
	if !v.Auth.Valid(c) {
		return c.SendString("already logged out")
	}

	// Destroy the session by setting the cookie to expire
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Expires:  time.Now(),
		HTTPOnly: true,
		Secure:   v.EnforceHTTPS,
		SameSite: fiber.CookieSameSiteLaxMode,
		Domain:   v.APIDomain,
	})

	// Done
	return c.SendString("OK")
}

type errormessage struct {
	Error string `json:"error"`
}

func (v *APIv0) ValidateEndpoint(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	user := v.Auth.GetClaims(c)
	if user == nil {
		c.SendStatus(fiber.StatusUnauthorized)
		message, _ := json.Marshal(&errormessage{
			Error: "not logged in",
		})
		return c.SendString(string(message))
	}
	result, err := json.Marshal(user)
	if err != nil {
		c.SendStatus(fiber.StatusInternalServerError)
		message, _ := json.Marshal(&errormessage{
			Error: err.Error(),
		})
		return c.SendString(string(message))
	}
	c.Set("Content-Type", "application/json")
	return c.SendString(string(result))
}
