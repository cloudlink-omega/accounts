package v1

import (
	"github.com/gofiber/fiber/v2"
)

func (v *API) UsernameChecker(c *fiber.Ctx) error {

	// Require a username
	if c.Query("username") == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing username parameter.", nil)
	}

	// Require username to be less than 20 characters
	if len(c.Query("username")) > 20 {
		return APIResult(c, fiber.StatusBadRequest, "Username too long.", nil)
	}

	// Ask the database if the username is available
	if exists, err := v.DB.DoesNameExist(c.Query("username")); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	} else if exists {
		return APIResult(c, fiber.StatusConflict, "Username unavailable.", nil)
	}

	return APIResult(c, fiber.StatusOK, "Username available.", nil)
}
