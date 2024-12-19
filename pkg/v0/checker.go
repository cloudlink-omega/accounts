package v0

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

func (v *APIv0) UsernameChecker(c *fiber.Ctx) error {

	log.Print(c.Query("username"))

	// Require a username
	if c.Query("username") == "" {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.SendString("missing username parameter")
	}

	// Require username to be less than 20 characters
	if len(c.Query("username")) > 20 {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.SendString("username too long")
	}

	// Ask the database if the username is available
	if exists, err := v.DB.DoesNameExist(c.Query("username")); err != nil {
		panic(err)
	} else if exists {
		c.SendStatus(fiber.ErrConflict.Code)
		return c.SendString("unavailable")
	}

	return c.SendString("available")
}
