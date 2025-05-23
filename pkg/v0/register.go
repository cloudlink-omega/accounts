package v0

import (
	"fmt"
	math_rand "math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/oklog/ulid/v2"
)

func (v *API) RegisterEndpoint(c *fiber.Ctx) error {

	// Try to read the contents, accept JSON or form data
	var creds Credentials
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.ValidFromToken(creds.Token) {
		return c.Status(fiber.StatusBadRequest).SendString("Already logged in!")
	}

	// Check if the email provided already exists.
	if user, err := v.DB.GetUserByEmail(creds.Email); err == nil && user != nil {
		return c.Status(fiber.StatusConflict).SendString("Email already in use!")

	} else if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Check if the username provided already exists.
	if exists, err := v.DB.DoesNameExist(creds.Username); err == nil && exists {
		return c.Status(fiber.StatusConflict).SendString("Username already in use!")

	} else if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Hash the password using scrypt
	hash, err := scrypt.GenerateFromPassword([]byte(creds.Password), scrypt.DefaultParams)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "hash_gen_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Create a 256-bit random secret key that's encrypted with the server's secret key.
	userSecret, err := v.DB.CreateUserSecret()
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "secret_gen_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	userid := ulid.Make().String()
	user := &types.User{
		ID:       userid,
		Username: creds.Username,
		Email:    creds.Email,
		Password: string(hash),
		Secret:   userSecret,
	}

	if err := v.DB.CreateUser(user); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "create_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_created",
		Details:    "Registered using local identity",
		Successful: true,
	})

	// If email is enabled, send a verification email. Otherwise, automatically assign the user as verified. Bypass for localhost if enabled.
	if v.BypassEmailRegistration {
		log.Warn("Bypassing email verification!")

		// Log the event
		common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_bypassed_test",
			Details:    "",
			Successful: true,
		})

	} else if v.MailConfig.Enabled {

		// Generate a random 6-digit verification code
		code := fmt.Sprintf("%06d", math_rand.Intn(1000000))

		// Store the verification code in the database, which will expire in 15 minutes.
		if err := v.DB.AddVerificationCode(user.ID, code, time.Now().Add(15*time.Minute)); err != nil {

			// Log the event
			event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
				UserID:     user.ID,
				EventID:    "user_verify_set_failure",
				Details:    err.Error(),
				Successful: false,
			})

			return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
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

		// Log the event
		common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_sent",
			Details:    "",
			Successful: true,
		})

		return c.Status(fiber.StatusCreated).SendString("OK")
	}

	// Set the user's state to "verified" and "active"
	user.State.Set(constants.USER_IS_EMAIL_REGISTERED)
	user.State.Set(constants.USER_IS_ACTIVE)
	if err := v.DB.UpdateUserState(user.ID, user.State); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_verify_bypassed_disabled",
		Details:    "",
		Successful: true,
	})

	return c.Status(fiber.StatusCreated).SendString("OK; Email verification disabled")
}
