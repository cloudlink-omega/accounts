package v1

import (
	"log"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ResetPasswordEndpoint(c *fiber.Ctx) error {

	var claims *structs.Claims
	var user *types.User

	// Attempt to get claims based on token or cookie
	if v.Auth.ValidFromNormal(c) {
		claims = v.Auth.GetNormalClaims(c)
	} else if v.Auth.ValidFromRecovery(c) {
		claims = v.Auth.GetRecoveryClaims(c)
	} else {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user is using an OAuth provider
	user = v.DB.GetUser(claims.ULID)
	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		return APIResult(c, fiber.StatusBadRequest, "You are using an OAuth provider for your account. Please use the OAuth provider to reset your password.", nil)
	}

	if c.FormValue("password", "") == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing password.", nil)
	}

	if len(c.FormValue("password", "")) < 8 {
		return APIResult(c, fiber.StatusBadRequest, "Password too short.", nil)
	}

	// Hash the new password using scrypt
	hash, err := scrypt.GenerateFromPassword([]byte(c.FormValue("password")), scrypt.DefaultParams)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {
		log.Println("TOTP enabled for user, re-encrypting backup codes and TOTP secrets...")

		// Load the user's backup codes and TOTP secrets
		secret := v.DB.GetTotpSecret(user.ID)
		codes, err := v.DB.GetRecoveryCodes(user.ID)
		if err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

		// Update password
		err = v.DB.UpdateUserPassword(user.ID, string(hash))
		if err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

		// Re-encrypt the backup codes and TOTP secrets
		v.DB.StoreTotpSecret(user.ID, secret)
		err = v.DB.StoreRecoveryCodes(user.ID, codes)
		if err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

	} else {

		// Just update the password
		err = v.DB.UpdateUserPassword(user.ID, string(hash))
		if err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}
	}

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
