package v0

import (
	"github.com/gofiber/fiber/v2"
)

func (v *API) LogoutEndpoint(c *fiber.Ctx) error {
	var creds Credentials
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	if creds.Token == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing token.")
	}

	if !v.Auth.ValidFromToken(creds.Token) {
		return c.Status(fiber.StatusCreated).SendString("Already logged out.")
	}

	// Find and delete the session from the database
	err := v.DB.DeleteSession(v.Auth.GetClaimsFromToken(creds.Token).SessionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Done
	return c.Status(fiber.StatusCreated).SendString("OK")
}
