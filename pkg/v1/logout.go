package v1

import (
	"github.com/gofiber/fiber/v2"
)

func (v *API) LogoutEndpoint(c *fiber.Ctx) error {

	if !v.Auth.ValidFromNormal(c) {
		return APIResult(c, fiber.StatusOK, "Already logged out.", nil)
	}

	v.ClearCookie(c)

	// Done
	return APIResult(c, fiber.StatusOK, "OK", nil)
}
