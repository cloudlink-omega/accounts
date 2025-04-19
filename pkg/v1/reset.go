package v1

import (
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
)

type ResetArgs struct {
	Password string `json:"password" form:"password"`
}

func (v *API) ResetPasswordEndpoint(c *fiber.Ctx) error {

	var claims *structs.Claims
	var user *types.User
	var args ResetArgs
	var switch_to_normal bool
	if err := c.BodyParser(&args); err != nil {
		return APIResult(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Attempt to get claims based on token or cookie
	if v.Auth.ValidFromNormal(c) {
		switch_to_normal = false
		claims = v.Auth.GetNormalClaims(c)
	} else if v.Auth.ValidFromRecovery(c) {
		switch_to_normal = true
		claims = v.Auth.GetRecoveryClaims(c)
	} else {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Check if the user is using an OAuth provider
	user = v.DB.GetUser(claims.ULID)
	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		return APIResult(c, fiber.StatusBadRequest, "You are using an OAuth provider for your account. Please use the OAuth provider to reset your password.", nil)
	}

	if args.Password == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing password.", nil)
	}

	if len(args.Password) < 8 {
		return APIResult(c, fiber.StatusBadRequest, "Password too short.", nil)
	}

	// Hash the new password using scrypt
	hash, err := scrypt.GenerateFromPassword([]byte(args.Password), scrypt.DefaultParams)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Update the user's password
	err = v.DB.UpdateUserPassword(user.ID, string(hash))
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Switch to normal session if coming from a recovery session
	if switch_to_normal {
		v.ClearRecoveryCookie(c)
		if err := v.CreateSession(c, user, time.Now().Add(24*time.Hour)); err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}
	}

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
