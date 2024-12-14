package v0

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

func (v *APIv0) UsernameChecker(c *fiber.Ctx) error {

	// Read username URL from request query parameters.
	username := c.Query("username")
	log.Print(username)

	// TODO: ask the database if the username is available

	// Just say it's available for now
	return c.SendString("available")
}
