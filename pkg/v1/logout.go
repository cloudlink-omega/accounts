package v1

import (
	"github.com/gofiber/fiber/v2"
)

func (v *API) LogoutEndpoint(c *fiber.Ctx) error {
	if !v.Auth.ValidFromNormal(c) {
		return APIResult(c, fiber.StatusOK, "Already logged out.", nil)
	}

	// Find and delete the session from the database
	err := v.DB.DeleteSession(v.Auth.GetNormalClaims(c).SessionID)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Clear the cookie
	v.ClearCookie(c)

	// Done
	return APIResult(c, fiber.StatusOK, "OK", nil)
}
