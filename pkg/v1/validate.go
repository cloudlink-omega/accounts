package v1

import (
	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
)

func (v *API) ValidateEndpoint(c *fiber.Ctx) error {

	// Attempt to get claims based on token or cookie
	claims := v.Auth.GetNormalClaims(c)

	// Check if the user is logged in
	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Read user flags
	user := v.DB.GetUser(claims.ULID)
	output := &ValidationData{
		Claims:        claims,
		VerifiedEmail: user.State.Read(constants.USER_IS_EMAIL_REGISTERED),
	}

	// Send the claims
	result, err := json.Marshal(output)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	return APIResult(c, fiber.StatusOK, "OK", string(result))
}
