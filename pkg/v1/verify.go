package v1

import (
	"fmt"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ResendVerificationEmail(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/plain")

	// Attempt to get claims based on token or cookie
	claims := v.Auth.GetNormalClaims(c)

	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user flags indicate they are already verified
	user := v.DB.GetUser(claims.ULID)
	registered := user.State.Read(constants.USER_IS_EMAIL_REGISTERED)
	if registered {
		return APIResult(c, fiber.StatusUnauthorized, "Email already verified!", nil)
	}

	// Read the user ID from the request
	if c.Query("code") == "" {
		return APIResult(c, fiber.StatusUnauthorized, "Missing verification code.", nil)
	}

	// Get the verification code in the database
	code, err := v.DB.GetVerificationCode(claims.ID)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
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

	return APIResult(c, fiber.StatusOK, "OK", nil)
}

func (v *API) VerifyVerificationEmail(c *fiber.Ctx) error {
	claims := v.Auth.GetNormalClaims(c)
	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user flags indicate they are already verified
	user := v.DB.GetUser(claims.ULID)
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
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	if !verified {
		return APIResult(c, fiber.StatusBadRequest, "Invalid verification code!", nil)
	}

	// Remove verification codes from the database
	if err := v.DB.DeleteVerificationCodes(claims.ULID); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Set the user's state to "verified" and "active"
	user.State.Set(constants.USER_IS_EMAIL_REGISTERED)
	user.State.Set(constants.USER_IS_ACTIVE)

	if err := v.DB.UpdateUserState(claims.ULID, user.State); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
