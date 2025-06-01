package v1

import (
	"fmt"
	math_rand "math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ResendVerificationEmail(c *fiber.Ctx) error {

	// Attempt to get claims based on token or cookie
	claims := v.Auth.GetNormalClaims(c)

	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user flags indicate they are already verified
	user, err := v.DB.GetUser(claims.ULID)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	registered := user.State.Read(constants.USER_IS_EMAIL_REGISTERED)
	if registered {
		return APIResult(c, fiber.StatusUnauthorized, "Email already verified!", nil)
	}

	// Remove verification codes from the database
	if err := v.DB.DeleteVerificationCodes(claims.ULID); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Generate a random 6-digit verification code
	code := fmt.Sprintf("%06d", math_rand.Intn(1000000))

	// Store a new verification code in the database, which will expire in 15 minutes.
	if err := v.DB.AddVerificationCode(user.ID, code, time.Now().Add(15*time.Minute)); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Send the verification code to the user's email
	email.SendPlainEmail(v.MailConfig, &structs.EmailArgs{
		Subject:  "Verify your account",
		To:       claims.Email,
		Nickname: v.ServerNickname,
	}, fmt.Sprintf(`Hello %s, You are receiving this email because you recently requested a verification code for your CloudLink Omega account on server %s.

	To verify your account, please use the following verification code: %s.

	If you did not create this account, you can safely ignore this email.

	Regards,
	 - %s.`, claims.Username, v.ServerNickname, code, v.ServerNickname))

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_verify_sent",
		Details:    "",
		Successful: true,
	})

	return APIResult(c, fiber.StatusOK, "OK", nil)
}

func (v *API) VerifyVerificationEmail(c *fiber.Ctx) error {
	claims := v.Auth.GetNormalClaims(c)
	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user flags indicate they are already verified
	user, _ := v.DB.GetUser(claims.ULID)
	registered := user.State.Read(constants.USER_IS_EMAIL_REGISTERED)
	if registered {
		return APIResult(c, fiber.StatusBadRequest, "Email already verified!", nil)
	}

	// Read the user ID from the request
	if c.Query("code") == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing verification code.", nil)
	}

	// Ask the database if the verification code is valid
	var verified bool
	var err error

	verified, err = v.DB.VerifyCode(claims.ULID, c.Query("code"))
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	if !verified {
		return APIResult(c, fiber.StatusBadRequest, "Invalid verification code!", nil)
	}

	// Remove verification codes from the database
	if err := v.DB.DeleteVerificationCodes(claims.ULID); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Set the user's state to "verified" and "active"
	user.State.Set(constants.USER_IS_EMAIL_REGISTERED)
	user.State.Set(constants.USER_IS_ACTIVE)

	if err := v.DB.UpdateUserState(claims.ULID, user.State); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_verify_success",
		Details:    "",
		Successful: true,
	})

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
