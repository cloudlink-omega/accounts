package v0

import (
	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ValidateEndpoint(c *fiber.Ctx) error {
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

	// Read user flags
	user, _ := v.DB.GetUser(claims.ULID)
	output := &ValidationData{
		Claims:        claims,
		VerifiedEmail: user.State.Read(constants.USER_IS_EMAIL_REGISTERED),
	}

	// Send the claims
	result, err := json.Marshal(output)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	return c.Status(fiber.StatusOK).SendString(string(result))
}
