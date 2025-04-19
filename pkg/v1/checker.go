package v1

import (
	"github.com/gofiber/fiber/v2"
)

type CheckArgs struct {
	Username string `json:"username" form:"username"`
}

func (v *API) UsernameChecker(c *fiber.Ctx) error {

	var args CheckArgs
	if err := c.BodyParser(&args); err != nil {
		return APIResult(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Require a username
	if args.Username == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing username parameter.", nil)
	}

	// Require username to be less than 20 characters
	if len(args.Username) > 20 {
		return APIResult(c, fiber.StatusBadRequest, "Username too long.", nil)
	}

	// Ask the database if the username is available
	if exists, err := v.DB.DoesNameExist(args.Username); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	} else if exists {
		return APIResult(c, fiber.StatusConflict, "Username unavailable.", nil)
	}

	return APIResult(c, fiber.StatusOK, "Username available.", nil)
}
