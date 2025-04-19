package v1

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid/v2"
)

func (v *API) RegisterEndpoint(c *fiber.Ctx) error {

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.ValidFromNormal(c) {
		return APIResult(c, fiber.StatusBadRequest, "Already logged in!", nil)
	}

	// Try to read the contents, accept JSON or form data
	var creds Credentials
	creds.Email = c.FormValue("email")
	creds.Password = c.FormValue("password")
	creds.Username = c.FormValue("username")

	// Check if the email provided already exists.
	if user, err := v.DB.GetUserByEmail(creds.Email); err == nil && user != nil {
		return APIResult(c, fiber.StatusBadRequest, "Email already in use!", nil)

	} else if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Check if the username provided already exists.
	if exists, err := v.DB.DoesNameExist(creds.Username); err == nil && exists {
		return APIResult(c, fiber.StatusBadRequest, "Username already in use!", nil)

	} else if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Hash the password using scrypt
	hash, err := scrypt.GenerateFromPassword([]byte(creds.Password), scrypt.DefaultParams)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	userid := ulid.Make()
	user := &types.User{
		ID:       userid.String(),
		Username: creds.Username,
		Email:    creds.Email,
		Password: string(hash),
	}

	if err := v.DB.CreateUser(user); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	v.SetCookie(user, time.Now().Add(24*time.Hour), c)

	// If email is enabled, send a verification email. Otherwise, automatically assign the user as verified.
	if v.MailConfig.Enabled {

		// Generate a random 6-digit verification code
		code := fmt.Sprintf("%06d", rand.Intn(1000000))

		// Store the verification code in the database, which will expire in 15 minutes.
		if err := v.DB.AddVerificationCode(user.ID, code, time.Now().Add(15*time.Minute)); err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

		// Send the verification code to the user's email
		email.SendPlainEmail(v.MailConfig, &structs.EmailArgs{
			Subject:  "Verify your account",
			To:       user.Email,
			Nickname: v.ServerNickname,
		}, fmt.Sprintf(
			`Hello %s, You are receiving this email because you recently created a CloudLink Omega account on server %s.

			To verify your account, please use the following verification code: %s.

			This code will expire in 15 minutes.

			If you did not create this account, you can safely ignore this email.

			Regards,
			- %s.`, user.Username, v.ServerNickname, code, v.ServerNickname),
		)

		return APIResult(c, fiber.StatusOK, "OK", nil)
	}

	// Set the user's state to "verified" and "active"
	user.State.Set(constants.USER_IS_EMAIL_REGISTERED)
	user.State.Set(constants.USER_IS_ACTIVE)
	if err := v.DB.UpdateUserState(user.ID, user.State); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	return APIResult(c, fiber.StatusOK, "OK; Email verification disabled", nil)
}
