package v0

import (
	"fmt"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ResendVerificationEmail(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/plain")

	var creds Credentials
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	if creds.Token == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing token.")
	}

	claims := v.Auth.GetClaimsFromToken(creds.Token)
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Not logged in!")
	}

	// Check if the user flags indicate they are already verified
	user, _ := v.DB.GetUser(claims.ULID)
	registered := user.State.Read(constants.USER_IS_EMAIL_REGISTERED)
	if registered {
		return c.Status(fiber.StatusUnauthorized).SendString("Email already verified!")
	}

	// Get the verification code in the database
	code, err := v.DB.GetVerificationCode(claims.ID)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Send the verification code to the user's email
	email.SendPlainEmail(v.MailConfig, &structs.EmailArgs{
		Subject:  "Verify your account",
		To:       claims.Email,
		Nickname: v.ServerNickname,
	}, fmt.Sprintf(`Hello %s, You are receiving this email because you recently requested another verification code for your CloudLink Omega account on server %s.

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

	return c.Status(fiber.StatusOK).SendString("OK")
}

func (v *API) VerifyVerificationEmail(c *fiber.Ctx) error {

	var creds Credentials
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	if creds.Token == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing token.")
	}

	claims := v.Auth.GetClaimsFromToken(creds.Token)
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Not logged in!")
	}

	// Check if the user flags indicate they are already verified
	user, _ := v.DB.GetUser(claims.ULID)
	registered := user.State.Read(constants.USER_IS_EMAIL_REGISTERED)
	if registered {
		return c.Status(fiber.StatusBadRequest).SendString("Email already verified!")
	}

	// Read the user ID from the request
	if creds.Code == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing verification code.")
	}

	// Ask the database if the verification code is valid
	var verified bool
	var err error

	verified, err = v.DB.VerifyCode(claims.ULID, creds.Code)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	if !verified {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid verification code!")
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

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
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

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_verify_success",
		Details:    "",
		Successful: true,
	})

	return c.Status(fiber.StatusOK).SendString("OK")
}
