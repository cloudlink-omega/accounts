package v0

import (
	"fmt"
	"time"

	"math/rand"

	"github.com/pquerna/otp/totp"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/types"

	scrypt "github.com/elithrar/simple-scrypt"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid/v2"
)

func (v *APIv0) LoginEndpoint(c *fiber.Ctx) error {

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.Valid(c) {
		c.Status(fiber.StatusBadRequest)
		return c.SendString("already logged in")
	}

	// Require email field
	if c.FormValue("email") == "" {
		c.Status(fiber.StatusBadRequest)
		return c.SendString("missing email field")
	}

	// Require password field
	if c.FormValue("password") == "" {
		c.Status(fiber.StatusBadRequest)
		return c.SendString("missing password field")
	}

	// Check if the account exists.
	user, err := v.DB.GetUserByEmail(c.FormValue("email"))
	if err != nil {
		panic(err)
	}
	if user == nil {
		c.Status(fiber.StatusUnauthorized)
		return c.SendString("account not found")
	}

	// Read account flags to see if the user only has OAuth
	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		c.Status(fiber.StatusBadRequest)
		return c.SendString("use oauth to log in")
	}

	// Verify password
	if scrypt.CompareHashAndPassword([]byte(user.Password), []byte(c.FormValue("password"))) != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.SendString("invalid password")
	}

	// Read account flags to see if the user needs TOTP
	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {

		// Require TOTP
		if c.FormValue("totp") == "" || len(c.FormValue("totp")) != 6 {
			c.Status(fiber.StatusBadRequest)
			return c.SendString("totp required")
		}

		// Get secret
		secret, err := v.DB.GetTotpSecret(user.ID)
		if err != nil {
			panic(err)
		}

		// Verify the TOTP
		if !totp.Validate(c.FormValue("totp"), secret) {
			c.Status(fiber.StatusUnauthorized)
			return c.SendString("invalid code")
		}
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	expiration := time.Now().Add(24 * time.Hour)
	token := v.Auth.Create(&types.Claims{
		Email:            user.Email,
		Username:         user.Username,
		ULID:             user.ID,
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

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.Valid(c) {
		c.Status(fiber.ErrBadRequest.Code)
		return c.SendString("already logged in")
	}

	// Check if the email provided already exists.
	if user, err := v.DB.GetUserByEmail(c.FormValue("email")); err == nil && user != nil {
		c.Status(fiber.ErrConflict.Code)
		return c.SendString("email already in use")
	}

	// Hash the password using scrypt
	hash, err := scrypt.GenerateFromPassword([]byte(c.FormValue("password")), scrypt.DefaultParams)
	if err != nil {
		panic(err)
	}

	userid := ulid.Make()
	user := &types.User{
		ID:       userid.String(),
		Username: c.FormValue("username"),
		Email:    c.FormValue("email"),
		Password: string(hash),
	}

	if err := v.DB.CreateUser(user); err != nil {
		panic(err)
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	expiration := time.Now().Add(24 * time.Hour)
	token := v.Auth.Create(&types.Claims{
		Email:            user.Email,
		Username:         user.Username,
		ULID:             user.ID,
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

	// Generate a random 6-digit verification code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Store the verification code in the database
	if err := v.DB.AddVerificationCode(user.ID, code); err != nil {
		panic(err)
	}

	// Send the verification code to the user's email
	email.SendPlainEmail(v.MailConfig, &types.EmailArgs{
		Subject:  "Verify your account",
		To:       user.Email,
		Nickname: v.ServerNickname,
	}, fmt.Sprintf(`Hello %s, You are receiving this email because you recently created a CloudLink Omega account on server %s.

		To verify your account, please enter the following code on the verification page: %s.

		If you did not create this account, you can safely ignore this email.

		Regards,
		 - %s.`, user.Username, v.ServerNickname, code, v.ServerNickname))

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

func (v *APIv0) VerifyEndpoint(c *fiber.Ctx) error {

	// Get authorization
	claims := v.Auth.GetClaims(c)
	if claims == nil {
		c.SendStatus(fiber.StatusUnauthorized)
		return c.SendString("not logged in")
	}

	// Read the user ID from the request
	if c.Query("code") == "" {
		c.SendStatus(fiber.StatusBadRequest)
		return c.SendString("code required")
	}

	// Ask the database if the verification code is valid
	var verified bool
	var err error

	verified, err = v.DB.VerifyCode(claims.ULID, c.Query("code"))
	if err != nil {
		panic(err)
	}

	if !verified {
		c.SendStatus(fiber.StatusBadRequest)
		return c.SendString("invalid verification code")
	}

	// Remove the verification code from the database
	if err := v.DB.DeleteVerificationCode(claims.ULID, c.Query("code")); err != nil {
		panic(err)
	}

	// Set the user's state to "verified" and "active"
	user := v.DB.GetUser(claims.ULID)
	user.State.Set(constants.USER_IS_EMAIL_REGISTERED)
	user.State.Set(constants.USER_IS_ACTIVE)

	if err := v.DB.UpdateUserState(claims.ULID, user.State); err != nil {
		panic(err)
	}

	return c.SendString("OK")
}
